package security.kron.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import android.os.Bundle
import io.flutter.embedding.android.FlutterFragmentActivity

/**
 * KRON SIEM main Android activity.
 *
 * Uses [FlutterFragmentActivity] (not [FlutterActivity]) so that the biometric
 * [androidx.biometric.BiometricPrompt] can use the Fragment API on all API
 * levels >= 21, which the [local_auth] plugin requires.
 *
 * Notification channels are created here on first launch so that Firebase
 * Messaging can route P1 alerts to the high-importance channel before any
 * Dart code runs.
 */
class MainActivity : FlutterFragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val manager = getSystemService(NotificationManager::class.java) ?: return

        // P1 / P2 critical alerts — HIGH importance, sound + vibration.
        val p1Channel = NotificationChannel(
            CHANNEL_P1_ALERTS,
            "Critical Alerts (P1/P2)",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Immediate notifications for P1 and P2 SIEM alerts"
            enableVibration(true)
            enableLights(true)
        }

        // P3–P5 informational alerts — DEFAULT importance.
        val infoChannel = NotificationChannel(
            CHANNEL_INFO_ALERTS,
            "Informational Alerts (P3–P5)",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "Non-urgent SIEM alert notifications"
        }

        // SOAR approval requests — HIGH importance so the analyst sees them.
        val soarChannel = NotificationChannel(
            CHANNEL_SOAR,
            "SOAR Approval Requests",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Playbook approval requests requiring analyst action"
            enableVibration(true)
        }

        manager.createNotificationChannels(listOf(p1Channel, infoChannel, soarChannel))
    }

    companion object {
        const val CHANNEL_P1_ALERTS = "kron_p1_alerts"
        const val CHANNEL_INFO_ALERTS = "kron_info_alerts"
        const val CHANNEL_SOAR = "kron_soar"
    }
}
