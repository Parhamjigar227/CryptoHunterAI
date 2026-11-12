package com.duolink.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp

/**
 * Lets the user point the app at a signaling server.
 *
 * This screen exists because version 0.4.0 shipped with `https://relay.duolink.invalid` compiled in
 * and no way to change it. `.invalid` is reserved by RFC 2606 and never resolves, so the remote-code
 * flow could not work in the field no matter what the user did. A build can still supply a default
 * (`-Pduolink.signalingEndpoint=...`), and that default is shown here so the user can see what the
 * app will talk to rather than having to trust it.
 *
 * Validation lives in `ServerEndpointStore` + `SignalingEndpointPolicy`, not in this composable, so
 * the rules are testable on the JVM and cannot be bypassed by another caller.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServerSettingsScreen(
    state: DuoLinkViewModel.ServerSettingsUiState,
    onBack: () -> Unit,
    onSave: (String) -> Unit,
    onClear: () -> Unit,
    onRefresh: () -> Unit,
    onTest: () -> Unit
) {
    // Ask the ViewModel for a fresh snapshot whenever the screen is shown, so a value saved in a
    // previous visit (or a build-time default) is reflected without the caller wiring an init call.
    LaunchedEffect(Unit) { onRefresh() }

    var draft by remember(state.currentUrl) { mutableStateOf(state.currentUrl.orEmpty()) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("سرور ارتباط") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "بازگشت")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Icon(Icons.Filled.Cloud, contentDescription = null)
                    Text(
                        "برای «اتصال با کد»، هر دو گوشی باید به یک سرور واسط دسترسی داشته باشند. " +
                            "سرور پیام‌ها را فقط به‌صورت رمزنگاری‌شده عبور می‌دهد و کلید خصوصی شما هرگز " +
                            "از گوشی خارج نمی‌شود.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }

            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                label = { Text("آدرس سرور") },
                placeholder = { Text("https://relay.example.com") },
                singleLine = true,
                isError = state.lastError != null,
                supportingText = {
                    Text(
                        state.lastError
                            ?: "فقط آدرس پایه بدون مسیر. مثال: https://relay.example.com"
                    )
                },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth()
            )

            Button(
                onClick = { onSave(draft.trim()) },
                enabled = draft.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("ذخیره و استفاده") }

            // Saving only proves the URL parses. This button makes a real request, which is what tells
            // the user whether the two phones can actually reach a server that speaks this protocol.
            OutlinedButton(
                onClick = onTest,
                enabled = !state.isTesting && state.currentUrl != null,
                modifier = Modifier.fillMaxWidth()
            ) { Text(if (state.isTesting) "در حال آزمایش…" else "آزمایش اتصال به سرور") }

            state.testResult?.let { result ->
                Text(
                    text = result,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (result.startsWith("اتصال موفق")) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.error
                    }
                )
            }

            if (!state.isFromBuild && state.currentUrl != null) {
                OutlinedButton(onClick = onClear, modifier = Modifier.fillMaxWidth()) {
                    Text("حذف مقدار ذخیره‌شده و بازگشت به پیش‌فرض")
                }
            }

            Spacer(Modifier.height(4.dp))
            Text(
                when {
                    state.currentUrl == null -> "وضعیت: تعیین نشده"
                    state.isFromBuild -> "وضعیت: مقدار پیش‌فرض نسخهٔ برنامه (${state.currentUrl})"
                    else -> "وضعیت: مقدار ذخیره‌شده توسط شما (${state.currentUrl})"
                },
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                "در نسخهٔ نهایی، فقط آدرس https پذیرفته می‌شود. آدرس http تنها برای سرور محلی " +
                    "(127.0.0.1) و فقط در نسخهٔ آزمایشی مجاز است.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
