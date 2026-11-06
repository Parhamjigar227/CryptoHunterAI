# DuoLink — Cryptographic Architecture & Verified Dependency Specification

**Document Version:** 1.1 (Milestone 2 Security & Persistence Hardening Revision)  
**Target Application:** `com.duolink.app` (`DuoLink v0.2.0`)  
**Supported Android Platform:** `minSdk = 26` (Android 8.0 Oreo) through `targetSdk = 35` / `compileSdk = 35` (Android 15)  
**Build Wrapper:** Official Gradle `8.9` Wrapper (`gradle-wrapper.jar` SHA-256 `498495120a03b9a6ab5d155f5de3c8f0d986a449153702fb80fc80e134484f17`; `gradle-8.9-bin.zip` `distributionSha256Sum=d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab`)

---

## 1. Verified Dependency Report (Official Documentation Audit)

Every dependency declared in `DuoLink/app/build.gradle.kts` was audited against its official upstream repository and Android Developers release notes for coordinates, version compatibility (`minSdk = 26`, `compileSdk = 35`, AGP `8.7.3`, Kotlin `2.0.21`), maintenance status, and SPDX license.

### 1.1 Active Dependencies Declared in Milestone 2 (`app/build.gradle.kts`)

| Functional Role | Exact Maven Coordinates | Version | License | Upstream Maintenance Status | Android / API Compatibility & Rationale |
|---|---|---|---|---|---|
| **OS Keystore & JCA Primitives** | Platform `java.security.KeyStore` (`"AndroidKeyStore"`) & standard `java.security` / `javax.crypto` JCA | Android OS / JDK Built-in | Apache-2.0 / GPLv2+CE | Official Android OS framework (`developer.android.com/training/articles/keystore`) | Supported across **API 26–35+**. Provides `AndroidKeyStore` `EC` (`secp256r1`) signing keys (`PURPOSE_SIGN \| PURPOSE_VERIFY`), `AndroidKeyStore` 256-bit `AES/GCM/NoPadding` wrapping keys (`PURPOSE_ENCRYPT \| PURPOSE_DECRYPT`), and API 31+ `PURPOSE_AGREE_KEY` ECDH where supported by device KeyMint HAL. |
| **Offline QR Matrix Encoding & Decoding** | `com.google.zxing:core` | `3.5.4` | Apache-2.0 | Actively maintained (`github.com/zxing/zxing`, tag `zxing-3.5.4`, Java 1.8 target bytecode, **zero** runtime transitive dependencies). | Pure JVM bytecode, **API 26–35+** compatible, 16 KB page-size safe (no JNI `.so`), 100% offline QR generation and luminance decoding with **no Google Play Services, ML Kit, or Firebase**. |
| **Camera Frame Acquisition for QR Scanning** | `androidx.camera:camera-core`<br>`androidx.camera:camera-camera2`<br>`androidx.camera:camera-lifecycle`<br>`androidx.camera:camera-view` | `1.4.2` | Apache-2.0 | Official Android Jetpack CameraX (`developer.android.com/jetpack/androidx/releases/camera`). | Verified compatible with **`minSdk = 26`**, **`compileSdk = 35`**, and **AGP `8.7.3`**. |
| **UI, Core & State Lifecycle** | `androidx.compose:compose-bom`<br>`androidx.core:core-ktx`<br>`androidx.activity:activity-compose`<br>`androidx.navigation:navigation-compose`<br>`androidx.lifecycle:lifecycle-viewmodel-compose`<br>`androidx.lifecycle:lifecycle-runtime-compose`<br>`io.coil-kt:coil-compose` | `2024.12.01`<br>`1.15.0`<br>`1.10.0`<br>`2.8.5`<br>`2.8.7`<br>`2.8.7`<br>`2.7.0` | Apache-2.0 | Official Jetpack & Coil (`coil-kt/coil`). | Verified compatible with **AGP `8.7.3`**, **Kotlin `2.0.21`**, **`minSdk = 26`**, **`compileSdk = 35`**. (`lifecycle-*-compose:2.11+` requires AGP 9.1 / `compileSdk = 37` and is intentionally avoided.) |
| **JVM Unit & Regression Tests** | `junit:junit`<br>`org.jetbrains.kotlin:kotlin-test` | `4.13.2`<br>`2.0.21` | EPL-1.0<br>Apache-2.0 | Standard JUnit 4 (`testImplementation` only — excluded from APK). | Runs 26 deterministic cryptographic, pairing, MITM, replay, crash-recovery, and fail-closed corruption regression tests on JVM. |
| **Android Instrumentation Integration Tests** | `androidx.test:core-ktx`<br>`androidx.test:runner`<br>`androidx.test.ext:junit-ktx` | `1.6.1`<br>`1.6.2`<br>`1.2.1` | Apache-2.0 | Official AndroidX Test (`developer.android.com/jetpack/androidx/releases/test`; `androidTestImplementation` only). | Runs `AndroidIntegrationTest` under `AndroidJUnitRunner` on real Android devices/emulators (`API 26+`) to test `AndroidKeyStore`, CameraX/ZXing stride handling, restart persistence, and corruption recovery. |

### 1.2 Libraries Explicitly Evaluated and Rejected (or Deferred to Milestones 3–7)

| Library Evaluated | Decision | Technical & Security Rationale |
|---|---|---|
| `androidx.security:security-crypto` (`EncryptedSharedPreferences`) | **Rejected** | Officially **deprecated by Google** at `1.1.0-alpha07`, unmaintained, and pins outdated transitive Tink `1.8.0`. Replaced by direct `AndroidKeyStore` `AES-256-GCM` sealing with explicit Associated Data (`AAD`) and crash-safe `fsync` + `ATOMIC_MOVE` file persistence. |
| Platform JCA `Ed25519` / `X25519` (`NamedParameterSpec.ED25519` / `X25519`) | **Rejected for `minSdk = 26`** | Per official Android API reference (`java.security.spec.NamedParameterSpec` & `java.security.Signature`), `Ed25519` and `X25519` were **added in API level 33 (Android 13)** and fail on Android 8.0–12 (`API 26–32`). Android Keystore below API 33 also lacks Curve25519 support. |
| `com.google.crypto.tink:tink-android` (`1.24.0`) | **Audited & Deferred to Milestones 3–4** | Apache-2.0 (`github.com/tink-crypto/tink-java`), API 23+ compatible for `Aead` / `StreamingAead` (encrypted media & message storage in Milestones 3–4). **Not** declared in Milestone 2 `build.gradle.kts` so unused dependencies are not shipped prematurely, and **never** assumed to provide raw two-party `ECDH`/`X25519` (`HybridEncrypt` is one-way HPKE and `subtle.X25519` is internal). |
| `org.signal:libsignal-client` | **Not selected** | Licensed under **`AGPL-3.0`** (copyleft network/distribution obligations) and ships native Rust JNI binaries. |
| `com.goterl:lazysodium-android` | **Not selected** | MPL-2.0 wrapper carrying prebuilt native JNI `.so` maintenance and 16 KB page-alignment risk. |
| Google ML Kit Barcode Scanning (`com.google.mlkit:barcode-scanning`) | **Rejected** | Pulls proprietary Google Play Services / dynamic model downloads, violating strict offline privacy and zero-telemetry requirements. |
| `net.zetetic:sqlcipher-android`, WebRTC Android SDK, `com.squareup.okhttp3:okhttp`, `androidx.biometric:biometric`, `androidx.media3:media3-exoplayer` | **Deferred to Milestones 3–7** | Withheld from `app/build.gradle.kts` during Milestone 2 to preserve strict sequential milestone isolation. |

---

## 2. Cryptographic Architecture & Provider Selection

### 2.1 Primitives & Actual JCA Provider Resolution

DuoLink uses standard NIST and IETF cryptographic primitives without custom algorithms:

- **Digital Signatures:** `SHA256withECDSA` over NIST **`P-256` (`secp256r1`)**, with strict validation of 91-byte uncompressed ASN.1 DER X.509 `SubjectPublicKeyInfo` (`0x04 || X || Y`).
- **Elliptic-Curve Diffie-Hellman Key Agreement:** **`ECDH` over `P-256` (`secp256r1`)** rejecting invalid SPKI headers and degenerate all-zero shared secrets.
- **Key Derivation Function:** **RFC 5869 `HKDF-SHA256`** (`Extract` + `Expand` over `HmacSHA256`) verified against all three official RFC 5869 test vectors.
- **Authenticated Local Envelope Encryption:** **`AES-256-GCM`** (`AES/GCM/NoPadding`) with randomized 96-bit IV, 128-bit authentication tag, and context-binding Associated Data (`AAD`).
- **Safety Number Hash:** **5,200-round iterated `SHA-512`** over canonically sorted `(deviceId, IK_sig_spki)` blocks producing 12 groups of 5 digits (**60 digits total**).

**Accurate JCA Provider Selection Disclosure:**
- `EcP256Crypto`, `HkdfSha256`, `SafetyFingerprint`, and `JcaAesGcmSealer` call standard provider-agnostic JCA factory methods (`KeyPairGenerator.getInstance("EC")`, `Signature.getInstance("SHA256withECDSA")`, `KeyAgreement.getInstance("ECDH")`, `Mac.getInstance("HmacSHA256")`, `MessageDigest.getInstance(...)`) **without hardcoding `"AndroidOpenSSL"` or `"BoringSSL"`**.
- An explicit provider name (`"AndroidKeyStore"`) is passed **only** inside `AndroidKeystoreSealer` and `AndroidKeystoreVault` when generating/loading Keystore keys and when invoking API 31+ Keystore `KeyAgreement.getInstance("ECDH", "AndroidKeyStore")`.
- Consequently:
  - On **Android Runtime**, software JCA operations resolve via Android's default provider priority list (typically Conscrypt / `AndroidOpenSSL`, backed by BoringSSL on AOSP-compliant builds), whereas `Signature.initSign(keystorePrivateKey)` routes via JCA delayed provider selection to the platform `AndroidKeyStore` provider.
  - On **OpenJDK 17 JVM unit tests**, the exact same JCA calls resolve to OpenJDK's **`SunEC` and `SunJCE`** providers (not BoringSSL).

### 2.2 Per-Key Protection Hierarchy & Separate Runtime Reporting (`minSdk = 26` to `35+`)

DuoLink **never** makes blanket claims that all keys are hardware-backed. Even for keys generated inside `"AndroidKeyStore"`, hardware backing (`TEE` or `StrongBox`) depends on the physical device's Keymaster/KeyMint implementation; emulators or budget devices without secure hardware implement `"AndroidKeyStore"` in an OS daemon (`isInsideSecureHardware == false`). Furthermore, Android 8.0–11 (`API 26–30`) does **not** support `KeyProperties.PURPOSE_AGREE_KEY` in `AndroidKeyStore` at all.

Therefore, `DeviceKeyVault.getKeyProtectionReport()` inspects and reports all three keys **separately** using `KeyProtectionTier`:

1. **Identity Signing Key (`IK_sig`, `EC P-256`, `SHA256withECDSA`)**
   - **Alias:** `duolink_ik_sig_p256_v1` in `AndroidKeyStore` (`PURPOSE_SIGN | PURPOSE_VERIFY`, StrongBox attempted on API 28+ when `FEATURE_STRONGBOX_KEYSTORE` is advertised, with automatic fallback to standard `AndroidKeyStore`).
   - **Exportability & Hardware Inspection:** Non-exportable from `AndroidKeyStore` (`privateKey.encoded == null`). Actual runtime tier (`STRONGBOX_HARDWARE`, `TEE_HARDWARE`, or `ANDROID_KEYSTORE_OS_SOFTWARE`) is queried dynamically via `KeyFactory.getKeySpec(privateKey, KeyInfo::class.java)`.
   - **`deviceId` Binding:**
     $$\text{deviceId} = \text{SHA-256}(\text{"DuoLink-DeviceId-v1"} \parallel \text{SPKI}(\text{IK}_{\text{sig,pub}}))[0..15] \quad (16\text{ bytes})$$

2. **Master Storage Wrapping Key (`MSK`, `AES-256-GCM`)**
   - **Alias:** `duolink_msk_aes256_v1` in `AndroidKeyStore` (`PURPOSE_ENCRYPT | PURPOSE_DECRYPT`, `setRandomizedEncryptionRequired(true)`).
   - **Exportability & Hardware Inspection:** Non-exportable from `AndroidKeyStore` (`secretKey.encoded == null`). Actual runtime tier (`STRONGBOX_HARDWARE`, `TEE_HARDWARE`, or `ANDROID_KEYSTORE_OS_SOFTWARE`) is queried dynamically via `SecretKeyFactory.getKeySpec(secretKey, KeyInfo::class.java)`.
   - **Role:** Authenticates and encrypts `pinned_peer_v1`, `archived_peer_v1`, `replay_ledger_v1`, `vault_init_v2`, `spk_entries_v2`, and software-wrapped `SPK_dh` blobs (`duolink_sealed_spk_v2_<id>`).

3. **Signed Pre-Key for ECDH Key Agreement (`SPK_dh`, `EC P-256`, `ECDH`)**
   - **Strict Key-Purpose Separation:** `IK_sig` is used solely for `SHA256withECDSA` signatures; `SPK_dh` is used solely for `ECDH` key agreement and is signed by `IK_sig` over `"DuoLink-SPK-v1" || deviceId || spkId || createdAt || len(spki) || spki`.
   - **API 31+ (Android 12+) Path:** Attempts generation inside `AndroidKeyStore` (`duolink_spk_dh_v1_<id>`, `PURPOSE_AGREE_KEY`). If accepted by the device KeyMint HAL, ECDH runs inside `AndroidKeyStore` and `KeyInfo` is inspected to report `STRONGBOX_HARDWARE`, `TEE_HARDWARE`, or `ANDROID_KEYSTORE_OS_SOFTWARE`.
   - **API 26–30 (Android 8.0–11) & API 31+ HAL Fallback Path (`SOFTWARE_WRAPPED_AT_REST`):**
     - Generated in software (`KeyPairGenerator.getInstance("EC")`) in app JVM heap memory.
     - PKCS#8 private key bytes are sealed at rest under `MSK` (`AES-256-GCM`, `AAD = "duolink:spk_priv:v2|<deviceIdHex>|<spkId>"`) and immediately zeroized (`Arrays.fill(..., 0)`).
     - During `agreeWithSignedPreKey()`, the PKCS#8 bytes are decrypted **transiently in JVM heap RAM**, used for `KeyAgreement.getInstance("ECDH")`, and zeroized in a `finally` block.
     - **Explicit Security Disclosure:** Software-wrapped `SPK_dh` keys on API 26–30 are **neither hardware-backed nor non-exportable from process memory** (`isHardwareBacked = false`, `isKeystoreNonExportable = false`), and both `KeyProtectionReport` and the Persian UI state this explicitly.

---

## 3. Mutual Two-Device QR Pairing & Verification Protocol (`duolink://pair/v1?p=...`)

### 3.1 Handshake Steps & Root Key Derivation

1. **Step 1 — Initiator `OFFER` QR (Device A):**
   - Refuses to start if security storage is corrupted (`TRUST_STORAGE_CORRUPTED`) or if a peer is already pinned (`THIRD_DEVICE_BLOCKED`).
   - Generates 16-byte random `sessionId` and 32-byte random `offerNonce` (`TTL = 300s`, max clock skew `90s`).
   - Signs canonical length-prefixed transcript `"DUOLINK-QR-OFFER-V1"` with `IK_sig_A` and renders offline QR URI `duolink://pair/v1?p=<base64url>`.

2. **Step 2 — Responder `OFFER` Validation & `ACCEPT` QR (Device B):**
   - Verifies canonical Base64URL, binary structure (zero trailing bytes), uncompressed P-256 SPKIs, `deviceId` derivation, `SPK_dh` signature, `OFFER` signature, timestamp freshness, non-self-pairing, persistent replay ledger, and `archived_peer_v1` integrity.
   - Generates 32-byte random `acceptNonce`, binds `targetInitiatorDeviceId = deviceId_A` and `boundOfferDigest = SHA-256(offerTranscript)` into signed transcript `"DUOLINK-QR-ACCEPT-V1"`, durably commits the `OFFER` token to `replay_ledger_v1` (`fsync` + `ATOMIC_MOVE`), and stages `PendingPairingConfirmation` without pinning yet.

3. **Step 3 — Initiator `ACCEPT` Validation & Mutual 60-Digit Safety Number Verification:**
   - Device A scans `ACCEPT`, verifies `sessionId`, `targetInitiatorDeviceId == deviceId_A`, `boundOfferDigest == SHA-256(activeOfferTranscript)`, signatures, freshness, replay ledger, and `archived_peer_v1` integrity.
   - Both devices derive the identical 256-bit `K_pair_root`:
     $$\text{salt} = \text{SHA-256}(\text{"DuoLink-PairSalt-v1"} \parallel \text{sessionId} \parallel \text{offerNonce} \parallel \text{acceptNonce})$$
     $$\text{info} = \text{"DuoLink-PairRoot-v1"} \parallel \text{id}_A \parallel \text{id}_B \parallel \text{LP}(\text{IK}_A) \parallel \text{LP}(\text{IK}_B) \parallel \text{offerDigest} \parallel \text{acceptDigest}$$
     $$K_{\text{pair\_root}} = \text{HKDF-SHA256}(\text{ECDH}(\text{SPK}_{\text{local}}, \text{SPK}_{\text{peer}}), \text{salt}, \text{info}, 32)$$

### 3.2 Complete 60-Digit Safety Number vs. Public Handshake Diagnostic ID

- **60-Digit Safety Number (`SafetyFingerprint.computeSafetyNumber`):**
  - 12 groups of 5 decimal digits derived from 5,200 rounds of `SHA-512` over sorted `(deviceId, IK_sig_spki)` blocks.
  - **Mandatory Security Requirement:** Both users **MUST** compare **all 60 digits** through an **independent trusted out-of-band channel** (in person or direct voice call with Nasrin) before confirming pairing. `PairingCoordinator.confirmSafetyFingerprint(fullSafetyNumberComparedViaTrustedChannel = ...)` rejects confirmation unless this requirement is explicitly affirmed (and if `previousPeerChanged == true`, `acknowledgeKeyChange == true` is also required).
- **12-Hex Public Handshake Diagnostic ID (`SafetyFingerprint.computePublicHandshakeTranscriptId`):**
  - Formatted `XXXX-XXXX-XXXX`, computed strictly from **public** QR fields (`sessionId`, `offerDigest`, `offerNonce`, `acceptNonce`).
  - **Explicit Non-Secret Role:** It is **NOT** a secret authentication token and provides **zero** protection against an active MITM who relays/substitutes QR codes. In UI and code it is strictly separated from the 60-digit Safety Number and labeled solely as a diagnostic aid for spotting stale/mismatched QR scans.

---

## 4. Crash-Safe Persistence & Fail-Closed Corruption Recovery

### 4.1 Atomic File Writes (`DirectoryFileByteStore`)

- Every write serializes into a sibling `<name>.bin.tmp` inside `Context.filesDir`, flushes stream buffers, invokes **`FileDescriptor.sync()` (`fsync`)** to flush file data blocks to physical storage before directory update, and atomically replaces `<name>.bin` via **`Files.move(..., REPLACE_EXISTING, ATOMIC_MOVE)`** (never truncating `<name>.bin` in-place).
- On startup/read, any uncommitted `<name>.bin.tmp` left behind by a crash prior to `ATOMIC_MOVE` is cleaned up without disturbing a committed `<name>.bin`.
- Zero-byte truncated files or unreadable entries return `RawStoreRead.CorruptedIo` — **never** `RawStoreRead.Missing`.

### 4.2 Fail-Closed Security Store Rules (Zero Silent Trust Resets)

| Persisted Record | Normal States | Corruption / Deletion Behavior |
|---|---|---|
| `pinned_peer_v1.bin` | `None` / `Valid(PairedPeerRecord)` | `Corrupted` — re-verifies AEAD tag (`AAD = duolink:trust:pinned_peer:v1`), `deviceId == computeDeviceId(IK)`, and `SPK_dh` signature on every load. Blocks all pairing/unpairing on failure. |
| `archived_peer_v1.bin` | `None` / `Valid(ArchivedPeerIdentity)` | `Corrupted` — **never** returns `null`/`None` on decryption or schema failure. Blocks pairing, re-pairing, and unpairing fail-closed so an attacker or disk fault cannot suppress `previousPeerChanged` key-change warnings. During normal unpair, `archived_peer_v1` is synced & atomically committed **before** `pinned_peer_v1` is deleted. |
| `replay_ledger_v1.bin` | `Uninitialized` / `Valid(List<ByteArray>)` | `Corrupted` — **never** resets to `emptyList()` on AEAD/schema failure. Furthermore, if `pinned_peer_v1` or `archived_peer_v1` is `Valid` while `replay_ledger_v1` is missing (`Uninitialized`), `inspectHealth()` flags `Corrupted(REPLAY_LEDGER)` to defeat file-deletion replay attacks. |
| `vault_init_v2.bin`, `spk_entries_v2.bin`, `sealed_spk_v2_<id>.bin` | `Healthy` (monotonic `highestIssuedSpkId`, `deviceId`-bound AAD, `IK_sig` verified on load) | `VaultHealth.Corrupted` / throws `KeyVaultStorageCorruptedException` — **never** falls back to `emptyList()` or resets `spkId` to `1`. Detects bit-flips, deleted `spk_entries_v2.bin` after initialization, missing Keystore aliases, or corrupted software SPK blobs. |

### 4.3 Explicit Destructive Recovery Procedure

When any component enters `Corrupted`, `PairingCoordinator.currentStateSnapshot()` returns `PairingStateSnapshot.TrustStorageCorrupted(component, technicalReason)`, blocking `startInitiatorOffer()`, `processScannedQr()`, `confirmSafetyFingerprint()`, and `unpairForSecureRePairing()`. Recovery is possible **only** via `PairingCoordinator.recoverFromCorruptedStorage(confirmDestructiveRecovery = true)`, which requires explicit user confirmation in the UI, purges corrupted local files, rotates `IK_sig` + `SPK_dh` to a brand-new `deviceId`, re-initializes a fresh sealed `replay_ledger_v1`, and requires a fresh out-of-band 60-digit Safety Number verification with the peer.

---

## 5. Automated Test Coverage & Unresolved Sandbox Limitations

1. **JVM Unit & Regression Suite (`PairingAndCryptoTest.kt` — Executed & Passing):**
   - **26 JUnit 4 tests** compiled with `kotlinc 2.0.21 -Werror` and executed on `OpenJDK Temurin 17.0.9+9` (`26 passed, 0 failed`), covering RFC 5869 vectors, AES-256-GCM tamper/AAD rejection, ECDH symmetry & monotonic SPK rotation, 60-digit Safety Number symmetry & MITM divergence, mutual QR pairing, tampered/expired/skewed/replayed/wrong-target/self/3rd-device rejections, key-change acknowledgement, fail-closed `archived_peer_v1` / `pinned_peer_v1` / `replay_ledger_v1` / `spk_entries_v2` corruption & file-deletion detection, `DirectoryFileByteStore` `.tmp` crash recovery & 0-byte truncation detection, separate key-protection reporting, mandatory 60-digit confirmation gating, and simulated process-restart persistence.
2. **Android Instrumentation Suite (`AndroidIntegrationTest.kt` — Authored & Statically Verified, Not Executed):**
   - **6 AndroidJUnit4 instrumentation tests** under `DuoLink/app/src/androidTest/java/com/duolink/app/AndroidIntegrationTest.kt` covering real `AndroidKeyStore` AES-GCM & ECDSA keygen/non-exportability, API 31+ Keystore ECDH, API 26–30 software-wrapped SPK fallback & honest protection reporting, CameraX padded Y-plane (`rowStride`/`pixelStride`) + ZXing mutual QR round-trip, `filesDir` restart persistence, and fail-closed corruption recovery.
   - Statically compiled with `kotlinc 2.0.21 -Werror` against Android API 35 signature stubs (`0 errors, 0 warnings`).
   - **Unresolved Environment Limitation:** Because this Linux container has no Android SDK, Android emulator, physical Android device, or network access to `dl.google.com` / `repo.maven.apache.org` / `services.gradle.org`, neither `./gradlew assembleDebug` (APK build) nor `./gradlew connectedDebugAndroidTest` has been executed here. They must be run on a machine with Android SDK 35 and an Android 8.0+ (`API 26+`) device/emulator.
3. **Physical & OS Security Boundaries:**
   - `FLAG_SECURE` blocks OS screenshots/Recents thumbnails on non-compromised Android builds, but cannot prevent an external physical camera photographing the display or root/kernel compromise.
   - Biometric/PIN App Lock and Milestones 3–8 networking, media, and WebRTC features remain scheduled for subsequent milestones after Milestone 2 approval.
