package com.duolink.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val ObsidianBackground = Color(0xFF111318)
val SurfaceCharcoal = Color(0xFF20242C)
val SurfaceElevated = Color(0xFF282D37)
val GoldPrimary = Color(0xFFD6B36A)
val GoldSoft = Color(0xFFE7CFA0)
val GoldMuted = Color(0xFF8F7540)
val TextIvory = Color(0xFFF3EFE6)
val TextMuted = Color(0xFF9AA3B2)
val SuccessEmerald = Color(0xFF4CAF7D)
val WarningAmber = Color(0xFFE5A93C)
val ErrorCrimson = Color(0xFFE05A5A)

object DuoLinkColors {
    val Ink = ObsidianBackground
    val Gold = GoldPrimary
    val GoldDim = GoldMuted
    val Panel = SurfaceCharcoal
    val PanelElevated = SurfaceElevated
    val Divider = Color(0xFF343A45)
    val Muted = TextMuted
    val Success = SuccessEmerald
    val SuccessBg = Color(0xFF192E24)
    val Warning = WarningAmber
    val WarningBg = Color(0xFF332814)
    val Danger = ErrorCrimson
    val DangerBg = Color(0xFF361A1D)
}

private val DuoLinkDarkScheme = darkColorScheme(
    primary = GoldPrimary,
    onPrimary = Color.Black,
    secondary = GoldSoft,
    background = ObsidianBackground,
    surface = SurfaceCharcoal,
    onBackground = TextIvory,
    onSurface = TextIvory,
    error = ErrorCrimson
)

@Composable
fun DuoLinkTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DuoLinkDarkScheme,
        content = content
    )
}
