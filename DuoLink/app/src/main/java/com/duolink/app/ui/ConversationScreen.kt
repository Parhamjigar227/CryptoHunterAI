package com.duolink.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.duolink.app.messaging.ChatMessage
import com.duolink.app.messaging.ConnectionState
import com.duolink.app.messaging.DeliveryState
import com.duolink.app.messaging.MessageType

/**
 * The two-person conversation screen.
 *
 * Layout intent: it should read like a normal private messenger, not like a crypto tool. There is no
 * key id, cipher name or timestamp-of-handshake anywhere on this screen — those live in Settings. The
 * only security-adjacent things shown are the ones a user genuinely needs to act on:
 *
 *  - a small lock + plain status line at the top (connected / reconnecting / offline),
 *  - a per-message state (sending, sent, delivered, read, failed) without jargon,
 *  - and, when something genuinely went wrong, an explicit Persian sentence rather than a silent gap.
 *
 * Attachments are shown as a tap target with their state. Saving to the Gallery is a deliberate
 * per-item action from the open attachment viewer, never a side effect of receiving one.
 */
@Composable
fun ConversationScreen(
    messages: List<ChatMessage>,
    connectionState: ConnectionState,
    peerDisplayName: String,
    isSending: Boolean,
    onBack: () -> Unit,
    onSendText: (String) -> Unit,
    onPickImage: () -> Unit,
    onPickVideo: () -> Unit,
    onOpenAttachment: (ChatMessage) -> Unit,
    onRetry: (ChatMessage) -> Unit
) {
    var draft by remember { mutableStateOf("") }
    var attachMenuOpen by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    // Keep the newest message in view, like every other messenger.
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.lastIndex)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .statusBarsPadding()
            .navigationBarsPadding()
            .imePadding()
    ) {
        ConversationTopBar(peerDisplayName, connectionState, onBack)

        if (connectionState != ConnectionState.ONLINE) {
            ConnectionBanner(connectionState)
        }

        Box(modifier = Modifier.weight(1f)) {
            if (messages.isEmpty()) {
                EmptyConversationHint()
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(
                        horizontal = 12.dp,
                        vertical = 12.dp
                    ),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(messages, key = { it.messageIdHex }) { message ->
                        MessageBubble(
                            message = message,
                            onOpenAttachment = { onOpenAttachment(message) },
                            onRetry = { onRetry(message) }
                        )
                    }
                }
            }
        }

        if (attachMenuOpen) {
            AttachmentMenu(
                onDismiss = { attachMenuOpen = false },
                onPickImage = { attachMenuOpen = false; onPickImage() },
                onPickVideo = { attachMenuOpen = false; onPickVideo() }
            )
        }

        ComposerRow(
            draft = draft,
            onDraftChange = { draft = it },
            enabled = !isSending && connectionState == ConnectionState.ONLINE,
            onAttach = { attachMenuOpen = !attachMenuOpen },
            onSend = {
                val text = draft.trim()
                if (text.isNotEmpty()) {
                    onSendText(text)
                    draft = ""
                }
            }
        )
    }
}

@Composable
private fun ConversationTopBar(
    peerDisplayName: String,
    connectionState: ConnectionState,
    onBack: () -> Unit
) {
    Surface(
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 2.dp,
        shadowElevation = 1.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "بازگشت")
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = peerDisplayName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Lock,
                        contentDescription = null,
                        modifier = Modifier.size(11.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        text = when (connectionState) {
                            ConnectionState.ONLINE -> "رمزنگاری سرتاسری · متصل"
                            ConnectionState.CONNECTING -> "رمزنگاری سرتاسری · در حال اتصال"
                            ConnectionState.RECONNECTING -> "رمزنگاری سرتاسری · اتصال دوباره"
                            ConnectionState.OFFLINE -> "رمزنگاری سرتاسری · آفلاین"
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun ConnectionBanner(state: ConnectionState) {
    val (text, tint) = when (state) {
        ConnectionState.OFFLINE ->
            "اتصال قطع است. پیام‌ها پس از برقراری اتصال ارسال می‌شوند." to WarningAmber
        ConnectionState.CONNECTING ->
            "در حال اتصال به سرور…" to MaterialTheme.colorScheme.primary
        ConnectionState.RECONNECTING ->
            "اتصال دوباره برقرار می‌شود…" to WarningAmber
        ConnectionState.ONLINE -> "" to MaterialTheme.colorScheme.primary
    }
    if (text.isEmpty()) return
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(tint.copy(alpha = 0.12f))
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Text(text = text, style = MaterialTheme.typography.bodySmall, color = tint)
    }
}

/** Shown when the transcript is genuinely empty — not as a placeholder for loading. */
@Composable
private fun EmptyConversationHint() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            Icons.Filled.Lock,
            contentDescription = null,
            modifier = Modifier.size(40.dp),
            tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = "هنوز پیامی رد و بدل نشده است.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = "اولین پیام خود را بنویسید.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun MessageBubble(
    message: ChatMessage,
    onOpenAttachment: () -> Unit,
    onRetry: () -> Unit
) {
    val outgoing = message.isOutgoing
    val bubbleColor = if (outgoing) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val align = if (outgoing) Alignment.CenterEnd else Alignment.CenterStart

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp),
        contentAlignment = align
    ) {
        Column(
            horizontalAlignment = if (outgoing) Alignment.End else Alignment.Start,
            modifier = Modifier.widthIn(max = 300.dp)
        ) {
            Box(
                modifier = Modifier
                    .clip(
                        RoundedCornerShape(
                            topStart = 16.dp,
                            topEnd = 16.dp,
                            bottomStart = if (outgoing) 16.dp else 4.dp,
                            bottomEnd = if (outgoing) 4.dp else 16.dp
                        )
                    )
                    .background(bubbleColor)
                    .then(
                        if (message.cryptoFailure != null) {
                            Modifier.border(
                                1.dp,
                                MaterialTheme.colorScheme.error,
                                RoundedCornerShape(16.dp)
                            )
                        } else {
                            Modifier
                        }
                    )
                    .padding(horizontal = 12.dp, vertical = 8.dp)
            ) {
                when {
                    // A message that failed authentication is shown as such. Hiding it would make a
                    // tampered message indistinguishable from one that never arrived.
                    message.cryptoFailure != null -> {
                        Text(
                            text = "این پیام قابل اعتماد نبود و خوانده نشد.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }

                    message.payload.type == MessageType.IMAGE ||
                        message.payload.type == MessageType.VIDEO -> {
                        AttachmentBubble(message, onOpenAttachment)
                    }

                    else -> {
                        Text(
                            text = String(message.payload.body, Charsets.UTF_8),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }

            MessageFooter(message, onRetry)
        }
    }
}

@Composable
private fun AttachmentBubble(message: ChatMessage, onOpenAttachment: () -> Unit) {
    val isVideo = message.payload.type == MessageType.VIDEO
    Column(
        modifier = Modifier
            .width(220.dp)
            .clickable(enabled = message.payload.mediaDigestSha256 != null) { onOpenAttachment() }
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = if (isVideo) Icons.Filled.Videocam else Icons.Filled.Image,
                contentDescription = null,
                modifier = Modifier.size(28.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.width(8.dp))
            Column {
                Text(
                    text = if (isVideo) "ویدیو" else "تصویر",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = formatBytes(message.payload.mediaSizeBytes) +
                        if (isVideo && message.payload.mediaDurationMs > 0) {
                            " · ${formatDuration(message.payload.mediaDurationMs)}"
                        } else {
                            ""
                        },
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        if (message.payload.body.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            Text(
                text = String(message.payload.body, Charsets.UTF_8),
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

@Composable
private fun MessageFooter(message: ChatMessage, onRetry: () -> Unit) {
    if (!message.isOutgoing) return
    when (message.deliveryState) {
        DeliveryState.FAILED -> {
            TextButton(onClick = onRetry, contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 4.dp)) {
                Text(
                    text = "ارسال نشد — تلاش دوباره",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
        DeliveryState.PENDING -> {
            Text(
                text = "در حال ارسال…",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
            )
        }
        DeliveryState.SENT -> StatusLabel("ارسال شد", MaterialTheme.colorScheme.onSurfaceVariant)
        DeliveryState.DELIVERED -> StatusLabel("تحویل شد", MaterialTheme.colorScheme.onSurfaceVariant)
        DeliveryState.READ -> StatusLabel("خوانده شد", MaterialTheme.colorScheme.primary)
    }
}

@Composable
private fun StatusLabel(text: String, color: Color) {
    Text(text = text, style = MaterialTheme.typography.labelSmall, color = color, fontSize = 10.sp)
}

@Composable
private fun AttachmentMenu(
    onDismiss: () -> Unit,
    onPickImage: () -> Unit,
    onPickVideo: () -> Unit
) {
    Surface(
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 3.dp,
        shadowElevation = 4.dp,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                AttachmentOption("تصویر", Icons.Filled.PhotoLibrary, onPickImage)
                AttachmentOption("ویدیو", Icons.Filled.Videocam, onPickVideo)
            }
            TextButton(onClick = onDismiss, modifier = Modifier.align(Alignment.End)) {
                Text("بستن", style = MaterialTheme.typography.labelMedium)
            }
        }
    }
}

@Composable
private fun AttachmentOption(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(16.dp)
    ) {
        Icon(icon, contentDescription = label, modifier = Modifier.size(28.dp))
        Spacer(Modifier.height(6.dp))
        Text(label, style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun ComposerRow(
    draft: String,
    onDraftChange: (String) -> Unit,
    enabled: Boolean,
    onAttach: () -> Unit,
    onSend: () -> Unit
) {
    Surface(color = MaterialTheme.colorScheme.surface, tonalElevation = 2.dp) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.Bottom
        ) {
            IconButton(onClick = onAttach, enabled = enabled) {
                Icon(Icons.Filled.AttachFile, contentDescription = "پیوست")
            }
            OutlinedTextField(
                value = draft,
                onValueChange = onDraftChange,
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = 48.dp, max = 140.dp),
                placeholder = { Text("پیام…", style = MaterialTheme.typography.bodyMedium) },
                enabled = enabled,
                maxLines = 6,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                shape = RoundedCornerShape(24.dp)
            )
            IconButton(
                onClick = onSend,
                enabled = enabled && draft.isNotBlank()
            ) {
                if (draft.isNotBlank()) {
                    Icon(
                        Icons.AutoMirrored.Filled.Send,
                        contentDescription = "ارسال",
                        tint = MaterialTheme.colorScheme.primary
                    )
                } else {
                    CircularProgressIndicator(modifier = Modifier.size(0.dp)) // keeps layout stable
                }
            }
        }
    }
}

/** Human-readable byte size in Persian numerals-friendly wording. */
internal fun formatBytes(bytes: Long): String = when {
    bytes <= 0 -> "—"
    bytes < 1024 -> "$bytes بایت"
    bytes < 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f کیلوبایت", bytes / 1024.0)
    else -> String.format(java.util.Locale.US, "%.1f مگابایت", bytes / (1024.0 * 1024.0))
}

internal fun formatDuration(ms: Long): String {
    val totalSeconds = (ms / 1000).coerceAtLeast(0)
    val minutes = totalSeconds / 60
    val seconds = totalSeconds % 60
    return String.format(java.util.Locale.US, "%d:%02d", minutes, seconds)
}
