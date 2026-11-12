package com.duolink.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Backspace
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.duolink.app.lock.PinDerivation

/**
 * The lock screen: PIN entry plus an optional strong-biometric shortcut.
 *
 * Design decisions:
 *  - The PIN is entered on a numeric keypad rather than a plain text field, so the digits are never
 *    handed to the IME (which, on a hostile keyboard, is a keystroke logger with network access).
 *  - The entered digits are shown as filled dots, never as characters.
 *  - The biometric button is only rendered when the platform actually offers BIOMETRIC_STRONG, so a
 *    user is never offered an option that will fail.
 *  - When the user is in a cooling-off period the keypad is disabled and a countdown is shown, instead
 *    of accepting an attempt that will not be evaluated.
 */
@Composable
fun AppLockScreen(
    mode: LockScreenMode,
    errorMessage: String?,
    lockoutRemainingSeconds: Long,
    biometricAvailable: Boolean,
    onPinSubmitted: (String) -> Unit,
    onBiometricRequested: () -> Unit,
    onRecoveryRequested: (() -> Unit)? = null
) {
    var pin by remember { mutableStateOf("") }
    val lockedOut = lockoutRemainingSeconds > 0
    val title = when (mode) {
        LockScreenMode.UNLOCK -> "قفل دوولینک"
        LockScreenMode.CREATE -> "یک رمز عددی انتخاب کنید"
        LockScreenMode.CONFIRM -> "رمز را دوباره وارد کنید"
    }
    val subtitle = when (mode) {
        LockScreenMode.UNLOCK -> "برای باز کردن برنامه رمز خود را وارد کنید."
        LockScreenMode.CREATE ->
            "این رمز از پیام‌های شما محافظت می‌کند. آن را جایی امن نگه دارید؛ بازیابی آن ممکن نیست."
        LockScreenMode.CONFIRM -> "برای اطمینان، همان رمز را دوباره وارد کنید."
    }
    val canConfirm = pin.length >= PinDerivation.MIN_PIN_LENGTH && !lockedOut

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(ObsidianBackground)
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(48.dp))
        Icon(
            Icons.Filled.Lock,
            contentDescription = null,
            modifier = Modifier.size(40.dp),
            tint = GoldPrimary
        )
        Spacer(Modifier.height(16.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
            color = TextIvory,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = TextMuted,
            textAlign = TextAlign.Center
        )

        Spacer(Modifier.height(28.dp))

        // Dots
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            repeat(PinDerivation.MAX_PIN_LENGTH.coerceAtMost(6).coerceAtLeast(4)) { index ->
                val filled = index < pin.length
                Box(
                    modifier = Modifier
                        .size(if (index < 6) 14.dp else 10.dp)
                        .clip(CircleShape)
                        .background(if (filled) GoldPrimary else SurfaceElevated)
                )
            }
        }

        if (errorMessage != null) {
            Spacer(Modifier.height(14.dp))
            Text(
                text = errorMessage,
                style = MaterialTheme.typography.bodySmall,
                color = ErrorCrimson,
                textAlign = TextAlign.Center
            )
        }
        if (lockedOut) {
            Spacer(Modifier.height(14.dp))
            Text(
                text = "برای تلاش دوباره ${lockoutRemainingSeconds} ثانیه صبر کنید.",
                style = MaterialTheme.typography.bodySmall,
                color = WarningAmber,
                textAlign = TextAlign.Center
            )
        }

        Spacer(Modifier.height(24.dp))

        NumberPad(
            enabled = !lockedOut,
            onDigit = { digit ->
                if (pin.length < PinDerivation.MAX_PIN_LENGTH) pin += digit
            },
            onBackspace = { if (pin.isNotEmpty()) pin = pin.dropLast(1) }
        )

        Spacer(Modifier.height(16.dp))

        Button(
            onClick = {
                onPinSubmitted(pin)
                pin = ""
            },
            enabled = canConfirm,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = GoldPrimary,
                contentColor = ObsidianBackground
            )
        ) {
            Text(
                text = if (mode == LockScreenMode.UNLOCK) "باز کردن" else "ادامه",
                fontWeight = FontWeight.SemiBold
            )
        }

        if (mode == LockScreenMode.UNLOCK && biometricAvailable) {
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onBiometricRequested) {
                Icon(
                    Icons.Filled.Fingerprint,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                    tint = GoldSoft
                )
                Spacer(Modifier.width(8.dp))
                Text("ورود با بیومتریک", color = GoldSoft, fontSize = 13.sp)
            }
        }

        if (mode == LockScreenMode.UNLOCK && onRecoveryRequested != null) {
            TextButton(onClick = onRecoveryRequested) {
                Text(
                    text = "رمز را فراموش کرده‌ام",
                    color = TextMuted,
                    fontSize = 12.sp
                )
            }
        }

        Spacer(Modifier.weight(1f))
        Text(
            text = if (mode == LockScreenMode.UNLOCK) "" else
                "هیچ‌کس، حتی توسعه‌دهندهٔ این برنامه، نمی‌تواند این رمز را بازیابی کند.",
            style = MaterialTheme.typography.labelSmall,
            color = TextMuted.copy(alpha = 0.7f),
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(16.dp))
    }
}

enum class LockScreenMode { UNLOCK, CREATE, CONFIRM }

@Composable
private fun NumberPad(
    enabled: Boolean,
    onDigit: (String) -> Unit,
    onBackspace: () -> Unit
) {
    val rows = listOf(
        listOf("1", "2", "3"),
        listOf("4", "5", "6"),
        listOf("7", "8", "9"),
        listOf("", "0", "⌫")
    )
    Column(
        verticalArrangement = Arrangement.spacedBy(10.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        rows.forEach { row ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                row.forEach { key ->
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(58.dp)
                            .clip(RoundedCornerShape(14.dp))
                            .background(if (key.isEmpty()) ObsidianBackground else SurfaceCharcoal),
                        contentAlignment = Alignment.Center
                    ) {
                        when (key) {
                            "" -> Unit
                            "⌫" -> IconChip(Icons.Filled.Backspace, enabled, onBackspace)
                            else -> androidx.compose.material3.TextButton(
                                onClick = { onDigit(key) },
                                enabled = enabled,
                                modifier = Modifier.fillMaxSize()
                            ) {
                                Text(
                                    text = key,
                                    style = MaterialTheme.typography.headlineSmall,
                                    color = if (enabled) TextIvory else TextMuted,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun IconChip(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    enabled: Boolean,
    onClick: () -> Unit
) {
    androidx.compose.material3.TextButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxSize()
    ) {
        Icon(
            icon,
            contentDescription = "پاک کردن",
            tint = if (enabled) TextIvory else TextMuted
        )
    }
}
