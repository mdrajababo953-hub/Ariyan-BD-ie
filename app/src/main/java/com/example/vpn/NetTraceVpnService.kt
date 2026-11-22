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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Locale
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class VpnRuntimeState(
    val isRunning: Boolean = false,
    val sessionId: Long = 0L,
    val targetPackage: String = "",
    val targetAppName: String = "",
    val packetCount: Int = 0,
    val blockedCount: Int = 0,
    val totalBytes: Long = 0L,
    val mitmActive: Boolean = false,
    val pinningBypassCount: Int = 0,
    val errorMessage: String? = null
)

class NetTraceVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.example.vpn.START"
        const val ACTION_STOP = "com.example.vpn.STOP"
        const val EXTRA_PACKAGE = "extra_package"
        const val EXTRA_APP_NAME = "extra_app_name"
        const val EXTRA_MITM_ENABLED = "extra_mitm_enabled"
        const val CHANNEL_ID = "nettrace_vpn_channel"
        const val NOTIF_ID = 4041

        private const val MAX_OOO_SEGMENTS = 24
        private const val UDP_IDLE_TIMEOUT_MS = 45_000L
        private const val TCP_IDLE_TIMEOUT_MS = 120_000L

        private val _runtimeState = MutableStateFlow(VpnRuntimeState())
        val runtimeState: StateFlow<VpnRuntimeState> = _runtimeState.asStateFlow()

        fun startCapture(
            context: Context,
            packageName: String,
            appName: String,
            mitmEnabled: Boolean = true
        ) {
            val intent = Intent(context, NetTraceVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_PACKAGE, packageName)
                putExtra(EXTRA_APP_NAME, appName)
                putExtra(EXTRA_MITM_ENABLED, mitmEnabled)
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
            runCatching { context.startService(intent) }
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunInterface: ParcelFileDescriptor? = null
    private var bridgeServer: ServerSocket? = null
    private var bridgeAcceptJob: Job? = null
    private var captureJob: Job? = null
    private var writerJob: Job? = null
    private var rulesObserverJob: Job? = null
    private var dbWriteJob: Job? = null
    private var cleanupJob: Job? = null

    private var tunWriteChannel = Channel<ByteArray>(capacity = 2048)
    private var dbWriteChannel = Channel<suspend () -> Unit>(capacity = 4096)

    @Volatile
    private var cachedEnabledRules: List<TrafficRuleEntity> = emptyList()

    @Volatile
    private var mitmEnabled: Boolean = true

    private val dnsHostMap = ConcurrentHashMap<String, String>()
    private val pinningBypassedHosts = ConcurrentHashMap.newKeySet<String>()
    private val tcpSessions = ConcurrentHashMap<String, TcpFlowSession>()
    private val pendingBridgeSessions = ConcurrentHashMap<Int, TcpFlowSession>()
    private val udpSockets = ConcurrentHashMap<String, UdpFlowSocket>()

    private val packetCounter = AtomicInteger(0)
    private val blockedCounter = AtomicInteger(0)
    private val byteCounter = AtomicLong(0L)

    @Volatile
    private var activeSessionId: Long = 0L
    private var currentTargetPkg: String = ""
    private var currentTargetLabel: String = ""

    private class TcpFlowSession(
        val key: String,
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val clientIpStr: String,
        val serverIpStr: String,
        val clientPort: Int,
        val serverPort: Int,
        @Volatile var hostName: String,
        val clientInitialSeq: Long,
        @Volatile var clientNextSeq: Long,
        val initialServerSeq: Long,
        @Volatile var serverSeq: Long,
        val startedAt: Long = System.currentTimeMillis()
    ) {
        val seqLock = Any()
        val closed = AtomicBoolean(false)
        @Volatile var lastActivityAt: Long = startedAt
        @Volatile var synAckSent: Boolean = false
        @Volatile var clientFinReceived: Boolean = false
        @Volatile var localSocket: Socket? = null
        @Volatile var upstreamSocket: Socket? = null
        @Volatile var tunBridgeReaderJob: Job? = null
        @Volatile var txWriterJob: Job? = null
        val txChannel = Channel<ByteArray>(capacity = 512)
        val oooBuffer = TreeMap<Long, ByteArray>()

        // Used when falling back to raw non-HTTP tunnel capture
        val rawLock = Any()
        var rawPacketId: Long = 0L
        var rawTxBytes: Int = 0
        var rawRxBytes: Int = 0
        val rawReqBuf = ByteArrayOutputStream()
        val rawRespBuf = ByteArrayOutputStream()
    }

    private data class UdpFlowSocket(
        val key: String,
        val socket: DatagramSocket,
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val clientPort: Int,
        val serverPort: Int,
        val isDns: Boolean,
        val readerJob: Job,
        @Volatile var lastActivityAt: Long = System.currentTimeMillis(),
        @Volatile var lastPacketId: Long = 0L,
        @Volatile var totalTx: Int = 0,
        @Volatile var totalRx: Int = 0
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
                val enableMitm = intent.getBooleanExtra(EXTRA_MITM_ENABLED, true)
                startForegroundWithNotification(label.ifBlank { "Target App" }, 0)
                if (pkg.isBlank()) {
                    _runtimeState.value = VpnRuntimeState(errorMessage = "No target app selected.")
                    stopVpnEngine()
                    stopSelf()
                    return START_NOT_STICKY
                }
                startVpnEngine(pkg, label, enableMitm)
            }
        }
        return START_STICKY
    }

    private fun startVpnEngine(targetPkg: String, targetLabel: String, enableMitm: Boolean) {
        stopVpnEngine(keepForeground = true)
        currentTargetPkg = targetPkg
        currentTargetLabel = targetLabel
        mitmEnabled = enableMitm
        pinningBypassedHosts.clear()
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
            stopVpnEngine()
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
            stopVpnEngine()
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
            stopVpnEngine()
            stopSelf()
            return
        }

        val serverSock = try {
            ServerSocket(0, 64, InetAddress.getLoopbackAddress())
        } catch (e: Exception) {
            runCatching { pfd.close() }
            _runtimeState.value = VpnRuntimeState(
                isRunning = false,
                targetPackage = targetPkg,
                targetAppName = targetLabel,
                errorMessage = "Unable to start local proxy bridge: ${e.message}"
            )
            stopVpnEngine()
            stopSelf()
            return
        }

        tunInterface = pfd
        bridgeServer = serverSock

        val app = application as NetTraceApp
        val repo = app.captureRepository
        val certMgr = app.mitmCertificateManager

        if (mitmEnabled) {
            scope.launch {
                runCatching { certMgr.ensureCa() }
            }
        }

        rulesObserverJob = scope.launch {
            repo.observeAllRules().collect { allRules ->
                cachedEnabledRules = allRules.filter { it.isEnabled }
            }
        }

        tunWriteChannel = Channel(capacity = 2048)
        dbWriteChannel = Channel(capacity = 4096)

        dbWriteJob = scope.launch {
            for (task in dbWriteChannel) {
                runCatching { task() }
            }
        }

        bridgeAcceptJob = scope.launch {
            while (isActive && !serverSock.isClosed) {
                val accepted = try {
                    serverSock.accept()
                } catch (_: Exception) {
                    break
                }
                launch {
                    handleBridgeConnection(accepted, certMgr)
                }
            }
        }

        cleanupJob = scope.launch {
            while (isActive) {
                delay(15_000L)
                val now = System.currentTimeMillis()
                udpSockets.entries.removeIf { (_, flow) ->
                    val expired = (now - flow.lastActivityAt) > UDP_IDLE_TIMEOUT_MS
                    if (expired) {
                        flow.readerJob.cancel()
                        runCatching { flow.socket.close() }
                    }
                    expired
                }
                tcpSessions.entries.removeIf { (_, sess) ->
                    val expired = sess.closed.get() || ((now - sess.lastActivityAt) > TCP_IDLE_TIMEOUT_MS)
                    if (expired) {
                        closeTcpSession(sess)
                    }
                    expired
                }
            }
        }

        captureJob = scope.launch {
            activeSessionId = repo.startLiveSession(targetLabel, targetPkg)
            _runtimeState.value = VpnRuntimeState(
                isRunning = true,
                sessionId = activeSessionId,
                targetPackage = targetPkg,
                targetAppName = targetLabel,
                mitmActive = mitmEnabled,
                pinningBypassCount = 0
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
        val isDns = udp.dstPort == 53
        val protoLabel = if (isDns) "DNS" else "UDP"
        val dnsQuery = if (isDns) PacketDissector.extractDnsQueryName(udp.payload) else null
        val displayHost = dnsQuery ?: host

        val matchedRule = matchTrafficRule(displayHost, "/", udp.dstPort, protoLabel)
        if (matchedRule?.action == "BLOCK") {
            recordPacket(
                method = protoLabel,
                url = "${protoLabel.lowercase(Locale.US)}://$displayHost:${udp.dstPort}",
                host = displayHost,
                path = if (dnsQuery != null) "/query/$dnsQuery" else "/",
                port = udp.dstPort,
                protocol = protoLabel,
                statusCode = 0,
                reqHeadersJson = JSONObject()
                    .put("Flow", "${ip.srcIpStr}:${udp.srcPort} -> ${ip.dstIpStr}:${udp.dstPort}")
                    .toString(),
                reqHex = cappedHex(udp.payload),
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
        val existingFlow = udpSockets[flowKey]
        val udpFlow = if (existingFlow != null && !existingFlow.socket.isClosed) {
            existingFlow
        } else {
            val sock = DatagramSocket()
            protect(sock)
            lateinit var flowHolder: UdpFlowSocket
            val job = scope.launch {
                val recvBuf = ByteArray(8192)
                val recvPkt = DatagramPacket(recvBuf, recvBuf.size)
                while (isActive && !sock.isClosed) {
                    try {
                        sock.receive(recvPkt)
                        val data = recvBuf.copyOfRange(0, recvPkt.length)
                        flowHolder.lastActivityAt = System.currentTimeMillis()
                        flowHolder.totalRx += data.size
                        var answerHeaders = "{}"
                        if (isDns) {
                            PacketDissector.extractDnsAnswers(data)?.let { (qName, ips) ->
                                ips.forEach { resolvedIp -> dnsHostMap[resolvedIp] = qName }
                                answerHeaders = JSONObject()
                                    .put("Query", qName)
                                    .put("Resolved-IPs", ips.joinToString(", "))
                                    .toString()
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
                        val total = byteCounter.addAndGet(data.size.toLong())
                        _runtimeState.value = _runtimeState.value.copy(totalBytes = total)

                        val sid = activeSessionId
                        if (sid != 0L && flowHolder.lastPacketId != 0L) {
                            val pid = flowHolder.lastPacketId
                            val rxTotal = flowHolder.totalRx
                            val respHex = cappedHex(data)
                            enqueueDbWrite {
                                (application as NetTraceApp).captureRepository.updateCapturedPacketResponse(
                                    sessionId = sid,
                                    packetId = pid,
                                    statusCode = if (isDns) 200 else null,
                                    responseHeadersJson = answerHeaders,
                                    responseBodyHex = respHex,
                                    totalBytesRx = rxTotal,
                                    addedBytesRx = data.size,
                                    durationMs = (System.currentTimeMillis() - flowHolder.lastActivityAt).coerceAtLeast(1L)
                                )
                            }
                        }
                    } catch (_: Exception) {
                        break
                    }
                }
            }
            flowHolder = UdpFlowSocket(
                key = flowKey,
                socket = sock,
                clientIp = ip.srcIp,
                serverIp = ip.dstIp,
                clientPort = udp.srcPort,
                serverPort = udp.dstPort,
                isDns = isDns,
                readerJob = job
            )
            udpSockets[flowKey] = flowHolder
            flowHolder
        }

        udpFlow.lastActivityAt = System.currentTimeMillis()
        udpFlow.totalTx += udp.payload.size

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
            reqHeadersJson = JSONObject()
                .put("Dst-IP", ip.dstIpStr)
                .put("Src-Port", udp.srcPort)
                .toString(),
            reqHex = cappedHex(udp.payload),
            respHex = "",
            durationMs = 1L,
            bytesTx = udp.payload.size,
            bytesRx = 0,
            isBlocked = false,
            blockReason = null,
            ruleId = if (matchedRule?.action == "HIGHLIGHT") matchedRule.id else null,
            onInserted = { id -> udpFlow.lastPacketId = id }
        )
    }

    private fun handleTcpPacket(raw: ByteArray, ip: Ipv4Header) {
        val tcp = PacketDissector.parseTcp(raw, ip) ?: return
        val flowKey = "${ip.srcIpStr}:${tcp.srcPort}->${ip.dstIpStr}:${tcp.dstPort}"

        if (tcp.isSyn && !tcp.isAck) {
            val existing = tcpSessions[flowKey]
            if (existing != null && !existing.closed.get() && existing.clientInitialSeq == tcp.seqNum) {
                if (existing.synAckSent) {
                    val synAck = PacketBuilder.buildIpv4TcpPacket(
                        srcIp = existing.serverIp,
                        dstIp = existing.clientIp,
                        srcPort = existing.serverPort,
                        dstPort = existing.clientPort,
                        seqNum = existing.initialServerSeq,
                        ackNum = existing.clientNextSeq,
                        flags = TcpSegment.FLAG_SYN or TcpSegment.FLAG_ACK
                    )
                    tunWriteChannel.trySend(synAck)
                }
                return
            }

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
                    ackNum = (tcp.seqNum + 1L) and 0xFFFFFFFFL,
                    flags = TcpSegment.FLAG_RST or TcpSegment.FLAG_ACK
                )
                tunWriteChannel.trySend(rst)
                recordPacket(
                    method = "SYN",
                    url = "${proto.lowercase(Locale.US)}://$resolvedHost:${tcp.dstPort}",
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

            if (existing != null) {
                tcpSessions.remove(flowKey)
                closeTcpSession(existing)
            }

            val bridge = bridgeServer ?: return
            val bridgePort = bridge.localPort
            val initialServerSeq = System.nanoTime() and 0x7FFFFFFFL
            val session = TcpFlowSession(
                key = flowKey,
                clientIp = ip.srcIp,
                serverIp = ip.dstIp,
                clientIpStr = ip.srcIpStr,
                serverIpStr = ip.dstIpStr,
                clientPort = tcp.srcPort,
                serverPort = tcp.dstPort,
                hostName = resolvedHost,
                clientInitialSeq = tcp.seqNum,
                clientNextSeq = (tcp.seqNum + 1L) and 0xFFFFFFFFL,
                initialServerSeq = initialServerSeq,
                serverSeq = initialServerSeq
            )
            tcpSessions[flowKey] = session

            scope.launch {
                try {
                    val localSock = Socket()
                    localSock.tcpNoDelay = true
                    localSock.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                    val localPort = localSock.localPort
                    pendingBridgeSessions[localPort] = session
                    localSock.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), bridgePort), 3000)
                    session.localSocket = localSock

                    val localOut = BufferedOutputStream(localSock.getOutputStream(), 8192)
                    session.txWriterJob = launch {
                        try {
                            for (chunk in session.txChannel) {
                                localOut.write(chunk)
                                localOut.flush()
                            }
                            runCatching {
                                localOut.flush()
                                localSock.shutdownOutput()
                            }
                        } catch (_: Exception) {
                            runCatching { localSock.close() }
                        }
                    }

                    session.tunBridgeReaderJob = launch {
                        val inBuf = ByteArray(8192)
                        val input = localSock.getInputStream()
                        try {
                            while (isActive && !localSock.isClosed && !session.closed.get()) {
                                val n = input.read(inBuf)
                                if (n <= 0) break
                                session.lastActivityAt = System.currentTimeMillis()
                                val chunk = inBuf.copyOfRange(0, n)
                                var offset = 0
                                while (offset < chunk.size) {
                                    val sliceLen = minOf(1360, chunk.size - offset)
                                    val slice = chunk.copyOfRange(offset, offset + sliceLen)
                                    val (seqToSend, ackToSend) = synchronized(session.seqLock) {
                                        val s = session.serverSeq
                                        val a = session.clientNextSeq
                                        session.serverSeq = (s + sliceLen.toLong()) and 0xFFFFFFFFL
                                        s to a
                                    }
                                    val psh = PacketBuilder.buildIpv4TcpPacket(
                                        srcIp = session.serverIp,
                                        dstIp = session.clientIp,
                                        srcPort = session.serverPort,
                                        dstPort = session.clientPort,
                                        seqNum = seqToSend,
                                        ackNum = ackToSend,
                                        flags = TcpSegment.FLAG_PSH or TcpSegment.FLAG_ACK,
                                        payload = slice
                                    )
                                    tunWriteChannel.trySend(psh)
                                    offset += sliceLen
                                }
                            }
                        } catch (_: Exception) {
                        } finally {
                            if (!session.closed.get()) {
                                val (finSeq, finAck) = synchronized(session.seqLock) {
                                    val s = session.serverSeq
                                    val a = session.clientNextSeq
                                    session.serverSeq = (s + 1L) and 0xFFFFFFFFL
                                    s to a
                                }
                                val fin = PacketBuilder.buildIpv4TcpPacket(
                                    srcIp = session.serverIp,
                                    dstIp = session.clientIp,
                                    srcPort = session.serverPort,
                                    dstPort = session.clientPort,
                                    seqNum = finSeq,
                                    ackNum = finAck,
                                    flags = TcpSegment.FLAG_FIN or TcpSegment.FLAG_ACK
                                )
                                tunWriteChannel.trySend(fin)
                            }
                            tcpSessions.remove(flowKey, session)
                            closeTcpSession(session)
                        }
                    }

                    val (synAckSeq, synAckAck) = synchronized(session.seqLock) {
                        val s = session.serverSeq
                        val a = session.clientNextSeq
                        session.serverSeq = (s + 1L) and 0xFFFFFFFFL
                        session.synAckSent = true
                        s to a
                    }
                    val synAck = PacketBuilder.buildIpv4TcpPacket(
                        srcIp = session.serverIp,
                        dstIp = session.clientIp,
                        srcPort = session.serverPort,
                        dstPort = session.clientPort,
                        seqNum = synAckSeq,
                        ackNum = synAckAck,
                        flags = TcpSegment.FLAG_SYN or TcpSegment.FLAG_ACK
                    )
                    tunWriteChannel.trySend(synAck)
                } catch (_: Exception) {
                    tcpSessions.remove(flowKey, session)
                    closeTcpSession(session)
                    val rst = PacketBuilder.buildIpv4TcpPacket(
                        srcIp = ip.dstIp,
                        dstIp = ip.srcIp,
                        srcPort = tcp.dstPort,
                        dstPort = tcp.srcPort,
                        seqNum = 0L,
                        ackNum = (tcp.seqNum + 1L) and 0xFFFFFFFFL,
                        flags = TcpSegment.FLAG_RST or TcpSegment.FLAG_ACK
                    )
                    tunWriteChannel.trySend(rst)
                }
            }
            return
        }

        val session = tcpSessions[flowKey] ?: return
        session.lastActivityAt = System.currentTimeMillis()

        if (tcp.isRst) {
            tcpSessions.remove(flowKey, session)
            closeTcpSession(session)
            return
        }

        val readyPayloads = mutableListOf<ByteArray>()
        var ackNeeded = false
        var finAckNeeded = false
        var sendSeq = 0L
        var sendAck = 0L

        synchronized(session.seqLock) {
            if (tcp.payload.isNotEmpty()) {
                ackNeeded = true
                val expected = session.clientNextSeq
                val diff = (tcp.seqNum - expected).toInt()
                when {
                    diff == 0 -> {
                        readyPayloads.add(tcp.payload)
                        session.clientNextSeq = (expected + tcp.payload.size.toLong()) and 0xFFFFFFFFL
                        drainOooLocked(session, readyPayloads)
                    }
                    diff < 0 -> {
                        val overlap = -diff
                        if (overlap < tcp.payload.size) {
                            val tail = tcp.payload.copyOfRange(overlap, tcp.payload.size)
                            readyPayloads.add(tail)
                            session.clientNextSeq = (expected + tail.size.toLong()) and 0xFFFFFFFFL
                            drainOooLocked(session, readyPayloads)
                        }
                    }
                    diff in 1..65536 -> {
                        if (session.oooBuffer.size < MAX_OOO_SEGMENTS && !session.oooBuffer.containsKey(tcp.seqNum)) {
                            session.oooBuffer[tcp.seqNum] = tcp.payload
                        }
                    }
                }
            }

            if (tcp.isFin && !session.clientFinReceived) {
                session.clientFinReceived = true
                session.clientNextSeq = (session.clientNextSeq + 1L) and 0xFFFFFFFFL
                finAckNeeded = true
            }

            sendSeq = session.serverSeq
            sendAck = session.clientNextSeq
        }

        readyPayloads.forEach { bytes ->
            session.txChannel.trySend(bytes)
        }

        if (ackNeeded || finAckNeeded) {
            val ackPkt = PacketBuilder.buildIpv4TcpPacket(
                srcIp = session.serverIp,
                dstIp = session.clientIp,
                srcPort = session.serverPort,
                dstPort = session.clientPort,
                seqNum = sendSeq,
                ackNum = sendAck,
                flags = TcpSegment.FLAG_ACK
            )
            tunWriteChannel.trySend(ackPkt)
        }

        if (finAckNeeded) {
            session.txChannel.close()
        }
    }

    private fun drainOooLocked(session: TcpFlowSession, outList: MutableList<ByteArray>) {
        while (session.oooBuffer.isNotEmpty()) {
            val nextChunk = session.oooBuffer.remove(session.clientNextSeq) ?: break
            outList.add(nextChunk)
            session.clientNextSeq = (session.clientNextSeq + nextChunk.size.toLong()) and 0xFFFFFFFFL
        }
    }

    private suspend fun handleBridgeConnection(
        clientSocket: Socket,
        certMgr: MitmCertificateManager
    ) {
        val session = pendingBridgeSessions.remove(clientSocket.port)
        if (session == null) {
            runCatching { clientSocket.close() }
            return
        }

        try {
            clientSocket.tcpNoDelay = true
            clientSocket.soTimeout = 20_000
            val clientIn = clientSocket.getInputStream()
            val peekBuf = ByteArray(16384)
            val firstLen = clientIn.read(peekBuf)
            if (firstLen <= 0) {
                runCatching { clientSocket.close() }
                return
            }
            val firstBytes = peekBuf.copyOfRange(0, firstLen)

            val sni = PacketDissector.extractTlsSni(firstBytes)
            if (!sni.isNullOrBlank()) {
                session.hostName = sni
                dnsHostMap[session.serverIpStr] = sni
            }

            val isTlsClientHello = firstBytes.size >= 6 &&
                (firstBytes[0].toInt() and 0xFF) == 0x16 &&
                (firstBytes[5].toInt() and 0xFF) == 0x01

            val preHttp = if (!isTlsClientHello) PacketDissector.tryParseHttpRequest(firstBytes) else null
            preHttp?.host?.let { h ->
                val cleanH = h.substringBefore(':')
                if (cleanH.isNotBlank()) session.hostName = cleanH
            }

            val protoGuess = when {
                isTlsClientHello -> "HTTPS"
                preHttp != null -> "HTTP"
                session.serverPort == 443 -> "HTTPS"
                session.serverPort == 80 -> "HTTP"
                else -> "TCP"
            }

            val postRule = matchTrafficRule(
                host = session.hostName,
                path = preHttp?.path ?: "/",
                port = session.serverPort,
                protocol = protoGuess
            )
            if (postRule?.action == "BLOCK") {
                recordPacket(
                    method = preHttp?.method ?: if (isTlsClientHello) "TLS" else "TCP",
                    url = "${protoGuess.lowercase(Locale.US)}://${session.hostName}${preHttp?.path ?: "/"}",
                    host = session.hostName,
                    path = preHttp?.path ?: "/",
                    port = session.serverPort,
                    protocol = protoGuess,
                    statusCode = 0,
                    reqHeadersJson = preHttp?.headersJson
                        ?: JSONObject().put("SNI", session.hostName).put("Dst-IP", session.serverIpStr).toString(),
                    reqHex = cappedHex(preHttp?.body ?: firstBytes),
                    respHex = "",
                    durationMs = System.currentTimeMillis() - session.startedAt,
                    bytesTx = firstBytes.size,
                    bytesRx = 0,
                    isBlocked = true,
                    blockReason = "Blocked by rule: ${postRule.name}",
                    ruleId = postRule.id
                )
                runCatching { clientSocket.close() }
                closeTcpSession(session)
                return
            }

            val hostKey = session.hostName.lowercase(Locale.US)
            val attemptMitm = mitmEnabled && isTlsClientHello && !pinningBypassedHosts.contains(hostKey)

            if (attemptMitm) {
                var plainUpstream: Socket? = null
                var serverSsl: SSLSocket? = null
                var clientTls: TlsStreamChannel? = null
                try {
                    plainUpstream = Socket()
                    plainUpstream.tcpNoDelay = true
                    protect(plainUpstream)
                    plainUpstream.connect(
                        InetSocketAddress(InetAddress.getByAddress(session.serverIp), session.serverPort),
                        8000
                    )
                    session.upstreamSocket = plainUpstream

                    val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                    serverSsl = sslFactory.createSocket(
                        plainUpstream,
                        session.hostName,
                        session.serverPort,
                        true
                    ) as SSLSocket
                    serverSsl.soTimeout = 20_000
                    serverSsl.sslParameters = serverSsl.sslParameters.apply {
                        if (!hostKey.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) {
                            serverNames = listOf(SNIHostName(session.hostName))
                        }
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            applicationProtocols = arrayOf("http/1.1")
                        }
                    }
                    serverSsl.startHandshake()

                    val mitmCtx = certMgr.getSslContextForHost(session.hostName)
                    val serverEngine = mitmCtx.createSSLEngine().apply {
                        useClientMode = false
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            sslParameters = sslParameters.apply {
                                applicationProtocols = arrayOf("http/1.1")
                            }
                        }
                    }
                    clientTls = TlsStreamChannel(
                        engine = serverEngine,
                        rawIn = clientIn,
                        rawOut = clientSocket.getOutputStream(),
                        initialBytes = firstBytes
                    )
                    clientTls.handshake()

                    clientSocket.soTimeout = 0
                    serverSsl.soTimeout = 0

                    HttpStreamProxy.relayStream(
                        scope = scope,
                        clientIn = clientTls.inputStream,
                        clientOut = clientTls.outputStream,
                        serverIn = serverSsl.inputStream,
                        serverOut = serverSsl.outputStream,
                        initialClientBytes = ByteArray(0),
                        isHttps = true,
                        defaultHost = session.hostName,
                        port = session.serverPort,
                        callbacks = createCallbacks(session)
                    )
                } catch (tlsErr: Exception) {
                    // App rejected our leaf cert (User CA not installed/trusted or SSL Certificate Pinning).
                    // Record diagnostic packet and auto-bypass future connections to this host!
                    pinningBypassedHosts.add(hostKey)
                    _runtimeState.value = _runtimeState.value.copy(
                        pinningBypassCount = pinningBypassedHosts.size
                    )
                    recordPacket(
                        method = "TLS_PIN",
                        url = "https://${session.hostName}/ClientHello",
                        host = session.hostName,
                        path = "/ClientHello",
                        port = session.serverPort,
                        protocol = "HTTPS",
                        statusCode = 495,
                        reqHeadersJson = JSONObject()
                            .put("SNI", session.hostName)
                            .put("Dst-IP", session.serverIpStr)
                            .put("MITM-Status", "Auto-bypassed to passthrough")
                            .put("Reason", tlsErr.message ?: tlsErr.javaClass.simpleName)
                            .put("Hint", "Install NetTrace CA cert or target app enforces SSL Pinning")
                            .toString(),
                        reqHex = cappedHex(firstBytes),
                        respHex = "",
                        durationMs = (System.currentTimeMillis() - session.startedAt).coerceAtLeast(1L),
                        bytesTx = firstBytes.size,
                        bytesRx = 0,
                        isBlocked = false,
                        blockReason = null,
                        ruleId = null
                    )
                } finally {
                    runCatching { clientTls?.close() }
                    runCatching { serverSsl?.close() }
                    runCatching { plainUpstream?.close() }
                    runCatching { clientSocket.close() }
                }
                return
            }

            // Plain HTTP, raw TCP, MITM disabled, or pinning-bypassed HTTPS passthrough
            var upstream: Socket? = null
            try {
                upstream = Socket()
                upstream.tcpNoDelay = true
                protect(upstream)
                upstream.connect(
                    InetSocketAddress(InetAddress.getByAddress(session.serverIp), session.serverPort),
                    8000
                )
                session.upstreamSocket = upstream
                clientSocket.soTimeout = 0
                upstream.soTimeout = 0

                HttpStreamProxy.relayStream(
                    scope = scope,
                    clientIn = clientIn,
                    clientOut = clientSocket.getOutputStream(),
                    serverIn = upstream.getInputStream(),
                    serverOut = upstream.getOutputStream(),
                    initialClientBytes = firstBytes,
                    isHttps = isTlsClientHello || session.serverPort == 443,
                    defaultHost = session.hostName,
                    port = session.serverPort,
                    callbacks = createCallbacks(session)
                )
            } finally {
                runCatching { upstream?.close() }
                runCatching { clientSocket.close() }
            }
        } catch (_: Exception) {
            runCatching { clientSocket.close() }
        }
    }

    private fun createCallbacks(session: TcpFlowSession): HttpCaptureCallbacks {
        return object : HttpCaptureCallbacks {
            override fun onHttpRequest(meta: CapturedHttpRequestMeta) {
                val matched = matchTrafficRule(meta.host, meta.path, meta.port, meta.protocol)
                recordPacket(
                    method = meta.method,
                    url = meta.url,
                    host = meta.host,
                    path = meta.path,
                    port = meta.port,
                    protocol = meta.protocol,
                    statusCode = null,
                    reqHeadersJson = meta.requestHeadersJson,
                    reqHex = meta.requestBodyHex,
                    respHex = "",
                    durationMs = 0L,
                    bytesTx = meta.bytesTx,
                    bytesRx = 0,
                    isBlocked = false,
                    blockReason = null,
                    ruleId = if (matched?.action == "HIGHLIGHT") matched.id else null,
                    onInserted = { id -> meta.packetIdHolder.packetId = id }
                )
            }

            override fun onHttpResponse(
                meta: CapturedHttpRequestMeta,
                statusCode: Int?,
                responseHeadersJson: String,
                responseBodyHex: String,
                bytesRx: Int,
                durationMs: Long
            ) {
                val sid = activeSessionId
                if (sid == 0L) return
                enqueueDbWrite {
                    val pid = meta.packetIdHolder.packetId
                    val repo = (application as NetTraceApp).captureRepository
                    if (pid != 0L) {
                        repo.updateCapturedPacketResponse(
                            sessionId = sid,
                            packetId = pid,
                            statusCode = statusCode,
                            responseHeadersJson = responseHeadersJson,
                            responseBodyHex = responseBodyHex,
                            totalBytesRx = bytesRx,
                            addedBytesRx = bytesRx,
                            durationMs = durationMs
                        )
                    } else {
                        val fallbackId = repo.recordCapturedPacket(
                            CapturedPacketEntity(
                                sessionId = sid,
                                timestamp = meta.startedAt,
                                method = meta.method,
                                url = meta.url,
                                host = meta.host,
                                path = meta.path,
                                port = meta.port,
                                protocol = meta.protocol,
                                statusCode = statusCode,
                                requestHeadersJson = meta.requestHeadersJson,
                                requestBodyHex = meta.requestBodyHex,
                                responseHeadersJson = responseHeadersJson,
                                responseBodyHex = responseBodyHex,
                                durationMs = durationMs,
                                bytesTx = meta.bytesTx,
                                bytesRx = bytesRx,
                                isBlocked = false,
                                blockReason = null
                            )
                        )
                        meta.packetIdHolder.packetId = fallbackId
                    }
                }
            }

            override fun onRawTunnelBytes(
                isHttps: Boolean,
                host: String,
                port: Int,
                reqBytes: ByteArray?,
                respBytes: ByteArray?
            ) {
                val sid = activeSessionId
                if (sid == 0L) return
                var insertNow = false
                var snapshotReqHex = ""
                var snapshotRespHex = ""
                var totalTx = 0
                var totalRx = 0
                var addedRx = 0

                synchronized(session.rawLock) {
                    if (reqBytes != null && reqBytes.isNotEmpty()) {
                        session.rawTxBytes += reqBytes.size
                        appendBounded(session.rawReqBuf, reqBytes)
                    }
                    if (respBytes != null && respBytes.isNotEmpty()) {
                        session.rawRxBytes += respBytes.size
                        addedRx = respBytes.size
                        appendBounded(session.rawRespBuf, respBytes)
                    }
                    if (session.rawPacketId == 0L) {
                        insertNow = true
                        session.rawPacketId = -1L
                    }
                    snapshotReqHex = HexUtils.bytesToHex(session.rawReqBuf.toByteArray())
                    snapshotRespHex = HexUtils.bytesToHex(session.rawRespBuf.toByteArray())
                    totalTx = session.rawTxBytes
                    totalRx = session.rawRxBytes
                }

                val proto = if (isHttps) "HTTPS" else "TCP"
                val method = if (isHttps) "TLS" else "TCP"
                val path = if (isHttps) "/Passthrough" else "/"
                val duration = (System.currentTimeMillis() - session.startedAt).coerceAtLeast(1L)

                if (insertNow) {
                    val matched = matchTrafficRule(host, path, port, proto)
                    recordPacket(
                        method = method,
                        url = "${proto.lowercase(Locale.US)}://$host$path",
                        host = host,
                        path = path,
                        port = port,
                        protocol = proto,
                        statusCode = null,
                        reqHeadersJson = JSONObject()
                            .put("Host", host)
                            .put("Dst-IP", session.serverIpStr)
                            .put("Mode", if (isHttps) "TLS Passthrough" else "Raw TCP")
                            .toString(),
                        reqHex = snapshotReqHex,
                        respHex = snapshotRespHex,
                        durationMs = duration,
                        bytesTx = totalTx,
                        bytesRx = totalRx,
                        isBlocked = false,
                        blockReason = null,
                        ruleId = if (matched?.action == "HIGHLIGHT") matched.id else null,
                        onInserted = { id ->
                            synchronized(session.rawLock) {
                                session.rawPacketId = id
                            }
                        }
                    )
                } else {
                    enqueueDbWrite {
                        val pid = synchronized(session.rawLock) { session.rawPacketId }
                        if (pid > 0L) {
                            (application as NetTraceApp).captureRepository.updateCapturedPacketResponse(
                                sessionId = sid,
                                packetId = pid,
                                statusCode = null,
                                responseHeadersJson = JSONObject()
                                    .put("Host", host)
                                    .put("Dst-IP", session.serverIpStr)
                                    .put("Mode", if (isHttps) "TLS Passthrough" else "Raw TCP")
                                    .toString(),
                                responseBodyHex = snapshotRespHex,
                                totalBytesRx = totalRx,
                                addedBytesRx = addedRx,
                                durationMs = duration
                            )
                        }
                    }
                }
            }

            override fun onBytesTransferred(bytes: Int) {
                val total = byteCounter.addAndGet(bytes.toLong())
                _runtimeState.value = _runtimeState.value.copy(totalBytes = total)
            }
        }
    }

    private fun appendBounded(out: ByteArrayOutputStream, data: ByteArray) {
        val room = HttpStreamProxy.MAX_CAPTURE_BYTES - out.size()
        if (room > 0) {
            out.write(data, 0, minOf(data.size, room))
        }
    }

    private fun cappedHex(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val sliced = if (bytes.size > HttpStreamProxy.MAX_CAPTURE_BYTES) {
            bytes.copyOf(HttpStreamProxy.MAX_CAPTURE_BYTES)
        } else {
            bytes
        }
        return HexUtils.bytesToHex(sliced)
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
            when (rule.matchType.uppercase(Locale.US)) {
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
        if (!session.closed.compareAndSet(false, true)) return
        session.txChannel.close()
        session.tunBridgeReaderJob?.cancel()
        session.txWriterJob?.cancel()
        runCatching { session.localSocket?.close() }
        runCatching { session.upstreamSocket?.close() }
    }

    private fun stopVpnEngine(keepForeground: Boolean = false) {
        captureJob?.cancel()
        captureJob = null
        bridgeAcceptJob?.cancel()
        bridgeAcceptJob = null
        cleanupJob?.cancel()
        cleanupJob = null
        writerJob?.cancel()
        writerJob = null
        rulesObserverJob?.cancel()
        rulesObserverJob = null
        dbWriteJob?.cancel()
        dbWriteJob = null

        runCatching { tunWriteChannel.close() }
        runCatching { dbWriteChannel.close() }
        runCatching { bridgeServer?.close() }
        bridgeServer = null

        pendingBridgeSessions.clear()
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
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        }
    }

    private fun startForegroundWithNotification(appLabel: String, packets: Int) {
        ensureNotificationChannel()
        val notification = buildNotification(appLabel, packets)
        runCatching {
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
    }

    private fun updateNotification(appLabel: String, packets: Int) {
        runCatching {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            nm.notify(NOTIF_ID, buildNotification(appLabel, packets))
        }
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
            .setSmallIcon(R.drawable.ic_vpn_notification)
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
