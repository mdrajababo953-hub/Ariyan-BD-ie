package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.NetTraceApp
import com.example.R
import com.example.data.db.CapturedPacketEntity
import com.example.data.db.TrafficRuleEntity
import com.example.decoder.HexUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

data class VpnRuntimeState(
    val isRunning: Boolean = false,
    val sessionId: Long = 0L,
    val targetPackage: String = "",
    val targetAppName: String = "",
    val packetCount: Int = 0,
    val blockedCount: Int = 0,
    val totalBytes: Long = 0L,
    val errorMessage: String? = null
)

class NetTraceVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.example.vpn.START"
        const val ACTION_STOP = "com.example.vpn.STOP"
        const val EXTRA_PACKAGE = "extra_package"
        const val EXTRA_APP_NAME = "extra_app_name"
        const val CHANNEL_ID = "nettrace_vpn_channel"
        const val NOTIF_ID = 4041

        private val _runtimeState = MutableStateFlow(VpnRuntimeState())
        val runtimeState: StateFlow<VpnRuntimeState> = _runtimeState.asStateFlow()

        fun startCapture(context: Context, packageName: String, appName: String) {
            val intent = Intent(context, NetTraceVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_PACKAGE, packageName)
                putExtra(EXTRA_APP_NAME, appName)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stopCapture(context: Context) {
            val intent = Intent(context, NetTraceVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunInterface: ParcelFileDescriptor? = null
    private var captureJob: Job? = null
    private var writerJob: Job? = null
    private var rulesObserverJob: Job? = null
    private var dbWriteJob: Job? = null
    private val tunWriteChannel = Channel<ByteArray>(capacity = 1024)
    private var dbWriteChannel = Channel<suspend () -> Unit>(capacity = 2048)

    @Volatile
    private var cachedEnabledRules: List<TrafficRuleEntity> = emptyList()

    private val dnsHostMap = ConcurrentHashMap<String, String>()
    private val tcpSessions = ConcurrentHashMap<String, TcpFlowSession>()
    private val udpSockets = ConcurrentHashMap<String, UdpFlowSocket>()

    private val packetCounter = AtomicInteger(0)
    private val blockedCounter = AtomicInteger(0)
    private val byteCounter = AtomicLong(0L)
    @Volatile
    private var activeSessionId: Long = 0L
    private var currentTargetPkg: String = ""
    private var currentTargetLabel: String = ""

    private data class TcpFlowSession(
        val key: String,
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val clientIpStr: String,
        val serverIpStr: String,
        val clientPort: Int,
        val serverPort: Int,
        var hostName: String,
        var clientNextSeq: Long,
        var serverSeq: Long,
        val startedAt: Long = System.currentTimeMillis(),
        var socket: Socket? = null,
        var readerJob: Job? = null,
        var firstTxRecorded: Boolean = false,
        var lastMethod: String = "TCP",
        var lastPath: String = "/",
        var lastHeadersJson: String = "{}",
        var lastReqHex: String = "",
        var txBytes: Int = 0,
        var recordedPacketId: Long = 0L,
        var respStatusCode: Int? = null,
        var respHeadersJson: String = "{}",
        var respHexBuilder: StringBuilder = StringBuilder(),
        var rxBytes: Int = 0
    )

    private data class UdpFlowSocket(
        val key: String,
        val socket: DatagramSocket,
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val clientPort: Int,
        val serverPort: Int,
        val readerJob: Job
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpnEngine()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val pkg = intent.getStringExtra(EXTRA_PACKAGE).orEmpty()
                val label = intent.getStringExtra(EXTRA_APP_NAME).orEmpty().ifBlank { pkg }
                if (pkg.isBlank()) {
                    _runtimeState.value = VpnRuntimeState(errorMessage = "No target app selected.")
                    stopSelf()
                    return START_NOT_STICKY
                }
                startForegroundWithNotification(label, 0)
                startVpnEngine(pkg, label)
            }
        }
        return START_STICKY
    }

    private fun startVpnEngine(targetPkg: String, targetLabel: String) {
        stopVpnEngine(keepForeground = true)
        currentTargetPkg = targetPkg
        currentTargetLabel = targetLabel
        packetCounter.set(0)
        blockedCounter.set(0)
        byteCounter.set(0L)

        val builder = Builder()
            .setSession("NetTrace: $targetLabel")
            .addAddress("10.110.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .setMtu(1500)

        try {
            builder.addAllowedApplication(targetPkg)
        } catch (_: PackageManager.NameNotFoundException) {
            _runtimeState.value = VpnRuntimeState(
                isRunning = false,
                targetPackage = targetPkg,
                targetAppName = targetLabel,
                errorMessage = "Target package '$targetPkg' not found on device."
            )
            stopSelf()
            return
        }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            _runtimeState.value = VpnRuntimeState(
                isRunning = false,
                targetPackage = targetPkg,
                targetAppName = targetLabel,
                errorMessage = "Unable to establish VPN interface: ${e.message}"
            )
            stopSelf()
            return
        }

        if (pfd == null) {
            _runtimeState.value = VpnRuntimeState(
                isRunning = false,
                targetPackage = targetPkg,
                targetAppName = targetLabel,
                errorMessage = "VPN permission not granted."
            )
            stopSelf()
            return
        }

        tunInterface = pfd
        val repo = (application as NetTraceApp).captureRepository

        rulesObserverJob = scope.launch {
            repo.observeAllRules().collect { allRules ->
                cachedEnabledRules = allRules.filter { it.isEnabled }
            }
        }

        dbWriteChannel = Channel(capacity = 2048)
        dbWriteJob = scope.launch {
            for (task in dbWriteChannel) {
                runCatching { task() }
            }
        }

        captureJob = scope.launch {
            activeSessionId = repo.startLiveSession(targetLabel, targetPkg)
            _runtimeState.value = VpnRuntimeState(
                isRunning = true,
                sessionId = activeSessionId,
                targetPackage = targetPkg,
                targetAppName = targetLabel
            )

            val input = FileInputStream(pfd.fileDescriptor)
            val output = FileOutputStream(pfd.fileDescriptor)

            writerJob = launch {
                for (pkt in tunWriteChannel) {
                    runCatching { output.write(pkt) }
                }
            }

            val buffer = ByteArray(32767)
            while (isActive) {
                val len = try {
                    input.read(buffer)
                } catch (_: Exception) {
                    break
                }
                if (len <= 0) continue

                val ip = PacketDissector.parseIpv4(buffer, len) ?: continue
                when (ip.protocol) {
                    PacketDissector.PROTO_UDP -> handleUdpPacket(buffer, ip)
                    PacketDissector.PROTO_TCP -> handleTcpPacket(buffer, ip)
                }
            }
        }
    }

    private fun handleUdpPacket(raw: ByteArray, ip: Ipv4Header) {
        val udp = PacketDissector.parseUdp(raw, ip) ?: return
        val host = dnsHostMap[ip.dstIpStr] ?: ip.dstIpStr
        val protoLabel = if (udp.dstPort == 53) "DNS" else "UDP"
        val dnsQuery = if (udp.dstPort == 53) PacketDissector.extractDnsQueryName(udp.payload) else null
        val displayHost = dnsQuery ?: host

        val matchedRule = matchTrafficRule(displayHost, "/", udp.dstPort, protoLabel)
        if (matchedRule?.action == "BLOCK") {
            recordPacket(
                method = protoLabel,
                url = "${protoLabel.lowercase()}://$displayHost:${udp.dstPort}",
                host = displayHost,
                path = if (dnsQuery != null) "/query/$dnsQuery" else "/",
                port = udp.dstPort,
                protocol = protoLabel,
                statusCode = 0,
                reqHeadersJson = JSONObject().put("Flow", "${ip.srcIpStr}:${udp.srcPort} -> ${ip.dstIpStr}:${udp.dstPort}").toString(),
                reqHex = HexUtils.bytesToHex(udp.payload),
                respHex = "",
                durationMs = 0L,
                bytesTx = udp.payload.size,
                bytesRx = 0,
                isBlocked = true,
                blockReason = "Blocked by rule: ${matchedRule.name}",
                ruleId = matchedRule.id
            )
            return
        }

        val flowKey = "${ip.srcIpStr}:${udp.srcPort}->${ip.dstIpStr}:${udp.dstPort}"
        val udpFlow = udpSockets.getOrPut(flowKey) {
            val sock = DatagramSocket()
            protect(sock)
            val job = scope.launch {
                val recvBuf = ByteArray(4096)
                val recvPkt = DatagramPacket(recvBuf, recvBuf.size)
                while (isActive && !sock.isClosed) {
                    try {
                        sock.receive(recvPkt)
                        val data = recvBuf.copyOfRange(0, recvPkt.length)
                        if (udp.dstPort == 53) {
                            PacketDissector.extractDnsAnswers(data)?.let { (qName, ips) ->
                                ips.forEach { resolvedIp -> dnsHostMap[resolvedIp] = qName }
                            }
                        }
                        val replyIp = PacketBuilder.buildIpv4UdpPacket(
                            srcIp = ip.dstIp,
                            dstIp = ip.srcIp,
                            srcPort = udp.dstPort,
                            dstPort = udp.srcPort,
                            payload = data
                        )
                        tunWriteChannel.trySend(replyIp)
                        byteCounter.addAndGet(data.size.toLong())
                    } catch (_: Exception) {
                        break
                    }
                }
            }
            UdpFlowSocket(flowKey, sock, ip.srcIp, ip.dstIp, udp.srcPort, udp.dstPort, job)
        }

        runCatching {
            val destAddr = InetAddress.getByAddress(ip.dstIp)
            udpFlow.socket.send(DatagramPacket(udp.payload, udp.payload.size, destAddr, udp.dstPort))
        }

        recordPacket(
            method = protoLabel,
            url = if (dnsQuery != null) "dns://$displayHost" else "udp://$displayHost:${udp.dstPort}",
            host = displayHost,
            path = if (dnsQuery != null) "/$dnsQuery" else "/",
            port = udp.dstPort,
            protocol = protoLabel,
            statusCode = null,
            reqHeadersJson = JSONObject().put("Dst-IP", ip.dstIpStr).put("Src-Port", udp.srcPort).toString(),
            reqHex = HexUtils.bytesToHex(udp.payload),
            respHex = "",
            durationMs = 1L,
            bytesTx = udp.payload.size,
            bytesRx = 0,
            isBlocked = false,
            blockReason = null,
            ruleId = if (matchedRule?.action == "HIGHLIGHT") matchedRule.id else null
        )
    }

    private fun handleTcpPacket(raw: ByteArray, ip: Ipv4Header) {
        val tcp = PacketDissector.parseTcp(raw, ip) ?: return
        val flowKey = "${ip.srcIpStr}:${tcp.srcPort}->${ip.dstIpStr}:${tcp.dstPort}"

        if (tcp.isSyn && !tcp.isAck) {
            val resolvedHost = dnsHostMap[ip.dstIpStr] ?: ip.dstIpStr
            val proto = when (tcp.dstPort) {
                443 -> "HTTPS"
                80 -> "HTTP"
                else -> "TCP"
            }
            val matchedRule = matchTrafficRule(resolvedHost, "/", tcp.dstPort, proto)
            if (matchedRule?.action == "BLOCK") {
                val rst = PacketBuilder.buildIpv4TcpPacket(
                    srcIp = ip.dstIp,
                    dstIp = ip.srcIp,
                    srcPort = tcp.dstPort,
                    dstPort = tcp.srcPort,
                    seqNum = 0L,
                    ackNum = tcp.seqNum + 1L,
                    flags = TcpSegment.FLAG_RST or TcpSegment.FLAG_ACK
                )
                tunWriteChannel.trySend(rst)
                recordPacket(
                    method = "SYN",
                    url = "${proto.lowercase()}://$resolvedHost:${tcp.dstPort}",
                    host = resolvedHost,
                    path = "/",
                    port = tcp.dstPort,
                    protocol = proto,
                    statusCode = 0,
                    reqHeadersJson = JSONObject().put("Destination", "${ip.dstIpStr}:${tcp.dstPort}").toString(),
                    reqHex = "",
                    respHex = "",
                    durationMs = 0L,
                    bytesTx = 0,
                    bytesRx = 0,
                    isBlocked = true,
                    blockReason = "Blocked by rule: ${matchedRule.name}",
                    ruleId = matchedRule.id
                )
                return
            }

            tcpSessions.remove(flowKey)?.let { closeTcpSession(it) }
            val initialServerSeq = (System.nanoTime() and 0x7FFFFFFFL)
            val session = TcpFlowSession(
                key = flowKey,
                clientIp = ip.srcIp,
                serverIp = ip.dstIp,
                clientIpStr = ip.srcIpStr,
                serverIpStr = ip.dstIpStr,
                clientPort = tcp.srcPort,
                serverPort = tcp.dstPort,
                hostName = resolvedHost,
                clientNextSeq = tcp.seqNum + 1L,
                serverSeq = initialServerSeq
            )
            tcpSessions[flowKey] = session

            scope.launch {
                try {
                    val sock = Socket()
                    protect(sock)
                    sock.connect(InetSocketAddress(InetAddress.getByAddress(ip.dstIp), tcp.dstPort), 8000)
                    session.socket = sock

                    val synAck = PacketBuilder.buildIpv4TcpPacket(
                        srcIp = session.serverIp,
                        dstIp = session.clientIp,
                        srcPort = session.serverPort,
                        dstPort = session.clientPort,
                        seqNum = session.serverSeq,
                        ackNum = session.clientNextSeq,
                        flags = TcpSegment.FLAG_SYN or TcpSegment.FLAG_ACK
                    )
                    session.serverSeq += 1L
                    tunWriteChannel.trySend(synAck)

                    session.readerJob = launch {
                        val inBuf = ByteArray(4096)
                        val input = sock.getInputStream()
                        while (isActive && !sock.isClosed) {
                            val n = try {
                                input.read(inBuf)
                            } catch (_: Exception) {
                                -1
                            }
                            if (n <= 0) break
                            val chunk = inBuf.copyOfRange(0, n)
                            var offset = 0
                            while (offset < chunk.size) {
                                val sliceLen = minOf(1360, chunk.size - offset)
                                val slice = chunk.copyOfRange(offset, offset + sliceLen)
                                val psh = PacketBuilder.buildIpv4TcpPacket(
                                    srcIp = session.serverIp,
                                    dstIp = session.clientIp,
                                    srcPort = session.serverPort,
                                    dstPort = session.clientPort,
                                    seqNum = session.serverSeq,
                                    ackNum = session.clientNextSeq,
                                    flags = TcpSegment.FLAG_PSH or TcpSegment.FLAG_ACK,
                                    payload = slice
                                )
                                session.serverSeq += sliceLen
                                tunWriteChannel.trySend(psh)
                                offset += sliceLen
                            }

                            val httpResp = PacketDissector.tryParseHttpResponse(chunk)
                            val bodyChunk = httpResp?.body ?: chunk
                            if (httpResp != null) {
                                session.respStatusCode = httpResp.statusCode
                                session.respHeadersJson = httpResp.headersJson
                            }
                            session.rxBytes += chunk.size
                            session.respHexBuilder.append(HexUtils.bytesToHex(bodyChunk))

                            val totalBytes = byteCounter.addAndGet(chunk.size.toLong())
                            _runtimeState.value = _runtimeState.value.copy(totalBytes = totalBytes)

                            val capturedSessionId = activeSessionId
                            if (capturedSessionId != 0L) {
                                val respStatus = session.respStatusCode
                                val respHeaders = session.respHeadersJson
                                val respHex = session.respHexBuilder.toString()
                                val totalRx = session.rxBytes
                                val addedRx = chunk.size
                                val duration = System.currentTimeMillis() - session.startedAt
                                val protoGuess = if (httpResp != null) "HTTP" else if (session.serverPort == 443) "HTTPS" else "TCP"
                                val reqMethod = session.lastMethod
                                val reqHost = session.hostName
                                val reqPath = session.lastPath
                                val reqPort = session.serverPort
                                val reqHeaders = session.lastHeadersJson
                                val reqHex = session.lastReqHex
                                val reqTx = session.txBytes

                                enqueueDbWrite {
                                    val repo = (application as NetTraceApp).captureRepository
                                    if (session.recordedPacketId != 0L) {
                                        repo.updateCapturedPacketResponse(
                                            sessionId = capturedSessionId,
                                            packetId = session.recordedPacketId,
                                            statusCode = respStatus,
                                            responseHeadersJson = respHeaders,
                                            responseBodyHex = respHex,
                                            totalBytesRx = totalRx,
                                            addedBytesRx = addedRx,
                                            durationMs = duration
                                        )
                                    } else {
                                        session.recordedPacketId = repo.recordCapturedPacket(
                                            CapturedPacketEntity(
                                                sessionId = capturedSessionId,
                                                timestamp = System.currentTimeMillis(),
                                                method = reqMethod,
                                                url = "${protoGuess.lowercase()}://$reqHost$reqPath",
                                                host = reqHost,
                                                path = reqPath,
                                                port = reqPort,
                                                protocol = protoGuess,
                                                statusCode = respStatus,
                                                requestHeadersJson = reqHeaders,
                                                requestBodyHex = reqHex,
                                                responseHeadersJson = respHeaders,
                                                responseBodyHex = respHex,
                                                durationMs = duration,
                                                bytesTx = reqTx,
                                                bytesRx = totalRx,
                                                isBlocked = false,
                                                blockReason = null
                                            )
                                        )
                                    }
                                }
                            }
                        }
                        val fin = PacketBuilder.buildIpv4TcpPacket(
                            srcIp = session.serverIp,
                            dstIp = session.clientIp,
                            srcPort = session.serverPort,
                            dstPort = session.clientPort,
                            seqNum = session.serverSeq,
                            ackNum = session.clientNextSeq,
                            flags = TcpSegment.FLAG_FIN or TcpSegment.FLAG_ACK
                        )
                        tunWriteChannel.trySend(fin)
                    }
                } catch (_: Exception) {
                    val rst = PacketBuilder.buildIpv4TcpPacket(
                        srcIp = ip.dstIp,
                        dstIp = ip.srcIp,
                        srcPort = tcp.dstPort,
                        dstPort = tcp.srcPort,
                        seqNum = 0L,
                        ackNum = tcp.seqNum + 1L,
                        flags = TcpSegment.FLAG_RST or TcpSegment.FLAG_ACK
                    )
                    tunWriteChannel.trySend(rst)
                    tcpSessions.remove(flowKey)
                }
            }
            return
        }

        val session = tcpSessions[flowKey] ?: return

        if (tcp.isRst || tcp.isFin) {
            if (tcp.isFin) {
                session.clientNextSeq = tcp.seqNum + 1L
                val finAck = PacketBuilder.buildIpv4TcpPacket(
                    srcIp = session.serverIp,
                    dstIp = session.clientIp,
                    srcPort = session.serverPort,
                    dstPort = session.clientPort,
                    seqNum = session.serverSeq,
                    ackNum = session.clientNextSeq,
                    flags = TcpSegment.FLAG_ACK
                )
                tunWriteChannel.trySend(finAck)
            }
            tcpSessions.remove(flowKey)
            closeTcpSession(session)
            return
        }

        if (tcp.payload.isNotEmpty()) {
            session.clientNextSeq = tcp.seqNum + tcp.payload.size.toLong()
            val ackPkt = PacketBuilder.buildIpv4TcpPacket(
                srcIp = session.serverIp,
                dstIp = session.clientIp,
                srcPort = session.serverPort,
                dstPort = session.clientPort,
                seqNum = session.serverSeq,
                ackNum = session.clientNextSeq,
                flags = TcpSegment.FLAG_ACK
            )
            tunWriteChannel.trySend(ackPkt)

            // Inspect TLS SNI or HTTP request
            PacketDissector.extractTlsSni(tcp.payload)?.let { sni ->
                session.hostName = sni
                dnsHostMap[session.serverIpStr] = sni
                session.lastMethod = "TLS"
                session.lastPath = "/ClientHello"
                session.lastHeadersJson = JSONObject().put("SNI", sni).put("Dst-IP", session.serverIpStr).toString()
            }

            val httpReq = PacketDissector.tryParseHttpRequest(tcp.payload)
            if (httpReq != null) {
                httpReq.host?.let { session.hostName = it.substringBefore(":") }
                session.lastMethod = httpReq.method
                session.lastPath = httpReq.path
                session.lastHeadersJson = httpReq.headersJson
                session.lastReqHex = HexUtils.bytesToHex(httpReq.body)
            } else if (session.lastMethod != "TLS") {
                session.lastMethod = if (session.serverPort == 443) "TLS" else "TCP"
                session.lastReqHex = HexUtils.bytesToHex(tcp.payload)
            }
            session.txBytes += tcp.payload.size

            // Re-evaluate rules now that SNI or HTTP path may be known
            val proto = if (httpReq != null) "HTTP" else if (session.serverPort == 443) "HTTPS" else "TCP"
            val postRule = matchTrafficRule(session.hostName, session.lastPath, session.serverPort, proto)
            if (postRule?.action == "BLOCK") {
                val rst = PacketBuilder.buildIpv4TcpPacket(
                    srcIp = session.serverIp,
                    dstIp = session.clientIp,
                    srcPort = session.serverPort,
                    dstPort = session.clientPort,
                    seqNum = session.serverSeq,
                    ackNum = session.clientNextSeq,
                    flags = TcpSegment.FLAG_RST or TcpSegment.FLAG_ACK
                )
                tunWriteChannel.trySend(rst)
                recordPacket(
                    method = session.lastMethod,
                    url = "${proto.lowercase()}://${session.hostName}${session.lastPath}",
                    host = session.hostName,
                    path = session.lastPath,
                    port = session.serverPort,
                    protocol = proto,
                    statusCode = 0,
                    reqHeadersJson = session.lastHeadersJson,
                    reqHex = session.lastReqHex,
                    respHex = "",
                    durationMs = System.currentTimeMillis() - session.startedAt,
                    bytesTx = tcp.payload.size,
                    bytesRx = 0,
                    isBlocked = true,
                    blockReason = "Blocked by rule: ${postRule.name}",
                    ruleId = postRule.id
                )
                tcpSessions.remove(flowKey)
                closeTcpSession(session)
                return
            }

            // Forward payload to protected upstream socket
            runCatching {
                session.socket?.getOutputStream()?.apply {
                    write(tcp.payload)
                    flush()
                }
            }

            if (!session.firstTxRecorded) {
                session.firstTxRecorded = true
                recordPacket(
                    method = session.lastMethod,
                    url = "${proto.lowercase()}://${session.hostName}${session.lastPath}",
                    host = session.hostName,
                    path = session.lastPath,
                    port = session.serverPort,
                    protocol = proto,
                    statusCode = null,
                    reqHeadersJson = session.lastHeadersJson,
                    reqHex = if (httpReq != null) HexUtils.bytesToHex(httpReq.body) else HexUtils.bytesToHex(tcp.payload),
                    respHex = "",
                    durationMs = 0L,
                    bytesTx = tcp.payload.size,
                    bytesRx = 0,
                    isBlocked = false,
                    blockReason = null,
                    ruleId = if (postRule?.action == "HIGHLIGHT") postRule.id else null,
                    onInserted = { id -> session.recordedPacketId = id }
                )
            }
        }
    }

    private fun matchTrafficRule(
        host: String,
        path: String,
        port: Int,
        protocol: String
    ): TrafficRuleEntity? {
        val rules = cachedEnabledRules
        if (rules.isEmpty()) return null
        return rules.firstOrNull { rule ->
            val targetOk = rule.targetPackage == "*" || rule.targetPackage == currentTargetPkg
            if (!targetOk) return@firstOrNull false
            when (rule.matchType.uppercase()) {
                "HOST" -> host.contains(rule.pattern, ignoreCase = true)
                "PATH" -> path.contains(rule.pattern, ignoreCase = true)
                "PORT" -> port.toString() == rule.pattern.trim()
                "PROTOCOL" -> protocol.equals(rule.pattern.trim(), ignoreCase = true)
                else -> host.contains(rule.pattern, ignoreCase = true) || path.contains(rule.pattern, ignoreCase = true)
            }
        }
    }

    private fun enqueueDbWrite(block: suspend () -> Unit) {
        dbWriteChannel.trySend(block)
    }

    private fun recordPacket(
        method: String,
        url: String,
        host: String,
        path: String,
        port: Int,
        protocol: String,
        statusCode: Int?,
        reqHeadersJson: String,
        reqHex: String,
        respHeadersJson: String = "{}",
        respHex: String,
        durationMs: Long,
        bytesTx: Int,
        bytesRx: Int,
        isBlocked: Boolean,
        blockReason: String?,
        ruleId: Long?,
        onInserted: ((Long) -> Unit)? = null
    ) {
        val capturedSessionId = activeSessionId
        if (capturedSessionId == 0L) return

        val count = packetCounter.incrementAndGet()
        val blocked = if (isBlocked) blockedCounter.incrementAndGet() else blockedCounter.get()
        val total = byteCounter.addAndGet((bytesTx + bytesRx).toLong())
        _runtimeState.value = _runtimeState.value.copy(
            packetCount = count,
            blockedCount = blocked,
            totalBytes = total
        )
        if (count % 10 == 0 || isBlocked) {
            updateNotification(currentTargetLabel, count)
        }

        val entity = CapturedPacketEntity(
            sessionId = capturedSessionId,
            timestamp = System.currentTimeMillis(),
            method = method,
            url = url,
            host = host,
            path = path,
            port = port,
            protocol = protocol,
            statusCode = statusCode,
            requestHeadersJson = reqHeadersJson,
            requestBodyHex = reqHex,
            responseHeadersJson = respHeadersJson,
            responseBodyHex = respHex,
            durationMs = durationMs,
            bytesTx = bytesTx,
            bytesRx = bytesRx,
            isBlocked = isBlocked,
            blockReason = blockReason
        )
        enqueueDbWrite {
            val repo = (application as NetTraceApp).captureRepository
            if (ruleId != null) {
                repo.incrementRuleHit(ruleId)
            }
            val insertedId = repo.recordCapturedPacket(entity)
            onInserted?.invoke(insertedId)
        }
    }

    private fun closeTcpSession(session: TcpFlowSession) {
        session.readerJob?.cancel()
        runCatching { session.socket?.close() }
    }

    private fun stopVpnEngine(keepForeground: Boolean = false) {
        captureJob?.cancel()
        captureJob = null
        writerJob?.cancel()
        writerJob = null
        rulesObserverJob?.cancel()
        rulesObserverJob = null
        dbWriteJob?.cancel()
        dbWriteJob = null
        dbWriteChannel.close()
        tcpSessions.values.forEach { closeTcpSession(it) }
        tcpSessions.clear()
        udpSockets.values.forEach {
            it.readerJob.cancel()
            runCatching { it.socket.close() }
        }
        udpSockets.clear()
        runCatching { tunInterface?.close() }
        tunInterface = null

        val finishedId = activeSessionId
        activeSessionId = 0L
        if (finishedId != 0L) {
            val repo = (application as NetTraceApp).captureRepository
            scope.launch { repo.finishSession(finishedId) }
        }
        _runtimeState.value = VpnRuntimeState(isRunning = false)
        if (!keepForeground) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    private fun startForegroundWithNotification(appLabel: String, packets: Int) {
        ensureNotificationChannel()
        val notification = buildNotification(appLabel, packets)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    private fun updateNotification(appLabel: String, packets: Int) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(NOTIF_ID, buildNotification(appLabel, packets))
    }

    private fun buildNotification(appLabel: String, packets: Int): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, NetTraceVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(getString(R.string.vpn_notif_title, appLabel))
            .setContentText(getString(R.string.vpn_notif_text, appLabel, packets))
            .setContentIntent(openIntent)
            .addAction(0, getString(R.string.action_stop_capture), stopIntent)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.vpn_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.vpn_channel_desc)
            }
            nm.createNotificationChannel(channel)
        }
    }

    override fun onRevoke() {
        stopVpnEngine()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpnEngine()
        scope.cancel()
        super.onDestroy()
    }
}
