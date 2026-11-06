package com.duolink.app.ui

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import com.duolink.app.R

object DuoLinkColors {
    val Ink = Color(0xFF111318)
    val Gold = Color(0xFFD6B36A)
    val GoldDim = Color(0xFF8F7540)
    val Panel = Color(0xFF20242C)
    val PanelElevated = Color(0xFF282D37)
    val Divider = Color(0xFF343A45)
    val Muted = Color(0xFF9AA3B2)
    val Success = Color(0xFF4CAF7D)
    val SuccessBg = Color(0xFF192E24)
    val Warning = Color(0xFFE5A93C)
    val WarningBg = Color(0xFF332814)
    val Danger = Color(0xFFE05A5A)
    val DangerBg = Color(0xFF361A1D)
}

@Composable
fun DuoLinkTopBar(title: String, onBack: (() -> Unit)? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (onBack != null) {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "بازگشت",
                    tint = Color.White
                )
            }
        } else {
            AsyncImage(
                model = R.drawable.duolink_logo,
                contentDescription = "لوگوی DuoLink",
                modifier = Modifier
                    .size(42.dp)
                    .clip(CircleShape)
            )
        }
        Text(
            text = title,
            modifier = Modifier.weight(1f),
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            color = Color.White
        )
        Spacer(Modifier.width(42.dp))
    }
}
