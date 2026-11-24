package com.example.proxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.NetTraceApp
import com.example.R
import com.example.data.db.CapturedPacketEntity
import com.example.decoder.PayloadAnalyzer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.net.URI
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

data class LocalProxyRuntimeState(
    val isRunning: Boolean = false,
    val port: Int = 8080,
    val forwardUrl: String = "https://client.ind.freefiremobile.com",
    val sessionId: Long = 0L,
    val capturedCount: Int = 0,
    val skippedNonDecodableCount: Int = 0,
    val totalBytes: Long = 0L,
    val errorMessage: String? = null
)

class LocalForwardProxyService : Service() {

    companion object {
        const val ACTION_START = "com.example.proxy.START"
        const val ACTION_STOP = "com.example.proxy.STOP"
        const val EXTRA_PORT = "extra_port"
        const val EXTRA_FORWARD_URL = "extra_forward_url"
        const val EXTRA_ONLY_DECODABLE = "extra_only_decodable"
        const val CHANNEL_ID = "nettrace_proxy_channel"
        const val NOTIF_ID = 4042

        private val _runtimeState = MutableStateFlow(LocalProxyRuntimeState())
        val runtimeState: StateFlow<LocalProxyRuntimeState> = _runtimeState.asStateFlow()

        fun startProxy(
            context: Context,
            port: Int,
            forwardUrl: String,
            onlyDecodable: Boolean
        ) {
            val intent = Intent(context, LocalForwardProxyService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_PORT, port)
                putExtra(EXTRA_FORWARD_URL, forwardUrl)
                putExtra(EXTRA_ONLY_DECODABLE, onlyDecodable)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stopProxy(context: Context) {
            val intent = Intent(context, LocalForwardProxyService::class.java).apply {
                action = ACTION_STOP
            }
            runCatching { context.startService(intent) }
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var engine: LocalForwardProxyEngine? = null
    private var dbWriteChannel = Channel<suspend () -> Unit>(capacity = 2048)
    private var dbWriteJob: Job? = null

    private val capturedCounter = AtomicInteger(0)
    private val skippedCounter = AtomicInteger(0)
    private val byteCounter = AtomicLong(0L)

    @Volatile
    private var activeSessionId: Long = 0L

    @Volatile
    private var currentPort: Int = 8080

    @Volatile
    private var currentForwardUrl: String = "https://client.ind.freefiremobile.com"

    @Volatile
    private var onlyDecodableFilter: Boolean = true

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProxyEngine(keepForeground = false)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val port = intent.getIntExtra(EXTRA_PORT, 8080).coerceIn(1024, 65535)
                val rawUrl = intent.getStringExtra(EXTRA_FORWARD_URL).orEmpty()
                val normalizedUrl = LocalForwardProxyEngine.sanitizeBaseUrl(rawUrl)
                val onlyDecodable = intent.getBooleanExtra(EXTRA_ONLY_DECODABLE, true)

                startForegroundWithNotification(port, normalizedUrl, 0)
                startProxyEngine(port, normalizedUrl, onlyDecodable)
            }
        }
        return START_STICKY
    }

    private fun startProxyEngine(port: Int, forwardUrl: String, onlyDecodable: Boolean) {
        stopProxyEngine(keepForeground = true)
        currentPort = port
        currentForwardUrl = forwardUrl
        onlyDecodableFilter = onlyDecodable
        capturedCounter.set(0)
        skippedCounter.set(0)
        byteCounter.set(0L)

        dbWriteChannel = Channel(capacity = 2048)
        dbWriteJob = scope.launch {
            for (task in dbWriteChannel) {
                runCatching { task() }
            }
        }

        val targetHost = runCatching { URI.create(forwardUrl).host }.getOrNull().orEmpty()
            .ifBlank { forwardUrl }

        val repo = (application as NetTraceApp).captureRepository

        scope.launch {
            val sessionId = repo.startLiveSession(
                targetAppName = "Proxy :$port → $targetHost",
                targetPackageName = "proxy:$port"
            )
            activeSessionId = sessionId

            try {
                val newEngine = LocalForwardProxyEngine(
                    port = port,
                    forwardBaseUrl = forwardUrl
                ) { tx ->
                    val sid = activeSessionId
                    if (sid == 0L) return@LocalForwardProxyEngine

                    val shouldSave = !onlyDecodableFilter ||
                        PayloadAnalyzer.hasDecodablePayload(tx.requestBodyHex, tx.responseBodyHex)

                    if (!shouldSave) {
                        val skipped = skippedCounter.incrementAndGet()
                        _runtimeState.value = _runtimeState.value.copy(
                            skippedNonDecodableCount = skipped
                        )
                        return@LocalForwardProxyEngine
                    }

                    val count = capturedCounter.incrementAndGet()
                    val total = byteCounter.addAndGet((tx.bytesTx + tx.bytesRx).toLong())
                    _runtimeState.value = _runtimeState.value.copy(
                        capturedCount = count,
                        totalBytes = total
                    )
                    if (count % 5 == 1) {
                        updateNotification(currentPort, currentForwardUrl, count)
                    }

                    val entity = CapturedPacketEntity(
                        sessionId = sid,
                        timestamp = tx.timestamp,
                        method = tx.method,
                        url = tx.url,
                        host = tx.host,
                        path = tx.path,
                        port = tx.port,
                        protocol = tx.protocol,
                        statusCode = tx.statusCode,
                        requestHeadersJson = tx.requestHeadersJson,
                        requestBodyHex = tx.requestBodyHex,
                        responseHeadersJson = tx.responseHeadersJson,
                        responseBodyHex = tx.responseBodyHex,
                        durationMs = tx.durationMs,
                        bytesTx = tx.bytesTx,
                        bytesRx = tx.bytesRx,
                        isBlocked = false,
                        blockReason = null
                    )
                    dbWriteChannel.trySend { repo.recordCapturedPacket(entity) }
                }

                val bound = newEngine.start(scope)
                engine = newEngine
                currentPort = bound
                _runtimeState.value = LocalProxyRuntimeState(
                    isRunning = true,
                    port = bound,
                    forwardUrl = forwardUrl,
                    sessionId = sessionId,
                    capturedCount = 0,
                    skippedNonDecodableCount = 0,
                    totalBytes = 0L,
                    errorMessage = null
                )
                updateNotification(bound, forwardUrl, 0)
            } catch (e: Exception) {
                repo.finishSession(sessionId)
                activeSessionId = 0L
                _runtimeState.value = LocalProxyRuntimeState(
                    isRunning = false,
                    port = port,
                    forwardUrl = forwardUrl,
                    errorMessage = "Unable to bind proxy on port $port: ${e.message}"
                )
                stopProxyEngine(keepForeground = false)
                stopSelf()
            }
        }
    }

    private fun stopProxyEngine(keepForeground: Boolean) {
        engine?.stop()
        engine = null
        dbWriteJob?.cancel()
        dbWriteJob = null
        runCatching { dbWriteChannel.close() }

        val finishedId = activeSessionId
        activeSessionId = 0L
        if (finishedId != 0L) {
            val repo = (application as NetTraceApp).captureRepository
            scope.launch { repo.finishSession(finishedId) }
        }
        _runtimeState.value = _runtimeState.value.copy(
            isRunning = false,
            sessionId = 0L
        )
        if (!keepForeground) {
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        }
    }

    private fun startForegroundWithNotification(port: Int, forwardUrl: String, count: Int) {
        ensureNotificationChannel()
        val notification = buildNotification(port, forwardUrl, count)
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

    private fun updateNotification(port: Int, forwardUrl: String, count: Int) {
        runCatching {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            nm.notify(NOTIF_ID, buildNotification(port, forwardUrl, count))
        }
    }

    private fun buildNotification(port: Int, forwardUrl: String, count: Int): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = PendingIntent.getService(
            this,
            2,
            Intent(this, LocalForwardProxyService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle("Proxy Running (127.0.0.1:$port)")
            .setContentText("Forward: $forwardUrl • $count captured")
            .setContentIntent(openIntent)
            .addAction(0, "Stop Proxy", stopIntent)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            val channel = NotificationChannel(
                CHANNEL_ID,
                "NetTrace Local Forward Proxy",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Runs the local HTTP reverse proxy on port 8080"
            }
            nm.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        stopProxyEngine(keepForeground = false)
        scope.cancel()
        super.onDestroy()
    }
}
