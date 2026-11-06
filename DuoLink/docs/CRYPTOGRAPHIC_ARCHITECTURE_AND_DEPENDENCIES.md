# DuoLink — Cryptographic Architecture & Verified Dependency Specification

**Document Version:** 1.0 (Milestone 2 Baseline)  
**Target Application:** `com.duolink.app` (`DuoLink v0.2.0`)  
**Supported Android Platform:** `minSdk = 26` (Android 8.0 Oreo) through `targetSdk = 35` / `compileSdk = 35` (Android 15)

---

## 1. Verified Dependency Report (Official Documentation Audit)

Every dependency below was audited against its official upstream repository, Maven Central POM metadata, Android API level compatibility tables, maintenance activity, and SPDX software license prior to Milestone 2 implementation.

### 1.1 Active Dependencies in Milestone 2 (`app/build.gradle.kts`)

| Functional Role | Exact Maven Coordinates | Version | License | Upstream Maintenance Status | Android / API Compatibility & Rationale |
|---|---|---|---|---|---|
| **Hardware Key Protection** | Platform `java.security.KeyStore` (`"AndroidKeyStore"`) | Android OS Built-in | Apache-2.0 | Official Android OS framework (`developer.android.com/training/articles/keystore`) | Supported across **API 26–35+**. Provides hardware-isolated (TEE / StrongBox where present) non-exportable `EC` (`secp256r1`) signing keys (`PURPOSE_SIGN`) and non-exportable 256-bit `AES/GCM/NoPadding` master wrapping keys (`PURPOSE_ENCRYPT \| PURPOSE_DECRYPT`). |
| **AEAD & Streaming Encryption Primitives** | `com.google.crypto.tink:tink-android` | `1.24.0` | Apache-2.0 | Actively maintained by Google Tink team (`github.com/tink-crypto/tink-java`, `v1.24.0` released 2026-10-16; note: legacy monorepo `tink-crypto/tink` was archived in 2024 in favor of `tink-java`). | Supports **API 23+** (`minSdk = 26` compatible). Used strictly for officially supported public primitives (`Aead` `AES256_GCM`, `StreamingAead` `AES256_GCM_HKDF_4KB`, `AndroidKeysetManager`). **Important audit finding:** Tink does *not* expose raw ECDH / `X25519` key agreement as a public primitive (`HybridEncrypt` is one-way unauthenticated HPKE, and `com.google.crypto.tink.subtle.X25519` is internal/unsupported). Therefore, Tink is **not** assumed or used for two-party Diffie-Hellman key agreement. |
| **Offline QR Matrix Encoding & Decoding** | `com.google.zxing:core` | `3.5.4` | Apache-2.0 | Actively maintained (`github.com/zxing/zxing`, `zxing-3.5.4`, Java 1.8 target bytecode, **zero** runtime transitive dependencies). | Pure JVM bytecode, **API 26–35+** compatible, 16 KB page-size safe (no JNI `.so`), 100% offline QR generation and luminance decoding with **no Google Play Services, ML Kit, or Firebase**. |
| **Camera Frame Acquisition for QR Scanning** | `androidx.camera:camera-core`<br>`androidx.camera:camera-camera2`<br>`androidx.camera:camera-lifecycle`<br>`androidx.camera:camera-view` | `1.4.2` | Apache-2.0 | Official Android Jetpack CameraX (`developer.android.com/jetpack/androidx/releases/camera`). | Verified compatible with **`minSdk = 26`**, **`compileSdk = 35`**, and **AGP `8.7.3`**. (CameraX `1.5+`/`1.6+` raises `compileSdk` requirements; `1.4.2` is the stable release aligned with AGP `8.7.3` and Compose BOM `2024.12.01`.) |
| **UI & State Lifecycle** | `androidx.compose:compose-bom`<br>`androidx.activity:activity-compose`<br>`androidx.navigation:navigation-compose`<br>`androidx.lifecycle:lifecycle-viewmodel-compose`<br>`androidx.lifecycle:lifecycle-runtime-compose`<br>`io.coil-kt:coil-compose` | `2024.12.01`<br>`1.10.0`<br>`2.8.5`<br>`2.8.7`<br>`2.8.7`<br>`2.7.0` | Apache-2.0 | Official Jetpack Compose & Coil (`coil-kt/coil`). | Verified compatible with **AGP `8.7.3`**, **Kotlin `2.0.21`**, **`minSdk = 26`**, **`compileSdk = 35`**. (`lifecycle-*-compose:2.11+` requires AGP 9.1 / compileSdk 37 and is intentionally avoided.) |
| **Automated Unit Tests** | `junit:junit`<br>`org.jetbrains.kotlin:kotlin-test-junit` | `4.13.2`<br>`2.0.21` | EPL-1.0<br>Apache-2.0 | Standard JVM / Android unit test runner (`testImplementation` only — excluded from APK). | Executes deterministic cryptographic, tamper, replay, MITM, wrong-peer, third-device, and key-change tests. |

### 1.2 Libraries Explicitly Evaluated and Rejected (or Deferred to Milestones 3–7)

| Library Evaluated | Decision | Technical & Security Rationale |
|---|---|---|
| `androidx.security:security-crypto` (`EncryptedSharedPreferences`) | **Rejected** | Officially **deprecated by Google in April 2025** at `1.1.0-alpha07`, unmaintained, and pins an outdated transitive Tink `1.8.0`. Replaced by direct `AndroidKeyStore` `AES-256-GCM` sealing with explicit Associated Data (`AAD`). |
| Platform JCA `Ed25519` / `X25519` (`NamedParameterSpec.ED25519` / `X25519`) | **Rejected for `minSdk = 26`** | Per official Android API reference (`java.security.spec.NamedParameterSpec` & `java.security.Signature`), `Ed25519` and `X25519` were **added in API level 33 (Android 13)** and throw `NoSuchAlgorithmException` on Android 8.0–12 (`API 26–32`). Furthermore, Android Keystore below API 33 does not support Curve25519 keys. |
| `org.signal:libsignal-client` (`0.106.2`) | **Not selected** | Licensed under **`AGPL-3.0`** (copyleft network/distribution obligations) and ships native Rust JNI binaries. |
| `com.goterl:lazysodium-android` (`5.2.0`) | **Not selected** | MPL-2.0 wrapper lagging upstream `libsodium 1.0.22` and carrying prebuilt native JNI `.so` page-alignment maintenance risk on Android 15+. |
| Google ML Kit Barcode Scanning (`com.google.mlkit:barcode-scanning`) | **Rejected** | Pulls proprietary Google Play Services / dynamic model downloads, violating strict offline privacy and zero-telemetry requirements. |
| `net.zetetic:sqlcipher-android`, `io.getstream:stream-webrtc-android`, `com.squareup.okhttp3:okhttp`, `androidx.biometric:biometric`, `androidx.media3:media3-exoplayer` | **Deferred to Milestones 3–7** | Verified compatible (`Apache-2.0` / `BSD-style`), withheld from `app/build.gradle.kts` during Milestone 2 to obey strict sequential milestone isolation and minimize binary attack surface at each stage. |

---

## 2. Cryptographic Architecture

DuoLink uses **only standard, independently standardized NIST and IETF cryptographic primitives** implemented by Android Keystore, BoringSSL (`AndroidOpenSSL` JCA), and Google Tink:

- **Digital Signatures:** `SHA256withECDSA` over NIST curve **`P-256` (`secp256r1`)** (FIPS 186-4 / SEC 1), public keys encoded as canonical ASN.1 DER X.509 `SubjectPublicKeyInfo` (91 bytes).
- **Elliptic-Curve Diffie-Hellman Key Agreement:** **`ECDH` over `P-256` (`secp256r1`)** (NIST SP 800-56A).
- **Key Derivation Function:** **RFC 5869 `HKDF-SHA256`** (`Extract` + `Expand` over `HmacSHA256`) with strict protocol-versioned domain separation labels.
- **Authenticated Symmetric Encryption:** **NIST SP 800-38D `AES-256-GCM`** with 96-bit cryptographically random IV per encryption, 128-bit authentication tag, and mandatory context-binding Associated Data (`AAD`).
- **Safety Number / Fingerprint Hash:** **5,200-round iterated `SHA-512`** over canonically ordered `(deviceId, IK_sig_pub)` tuples (modeled after Signal's numeric safety number construction).

### 2.1 Key Hierarchy & Storage Protection (`minSdk = 26` to `35+`)

1. **Master Storage Wrapping Key (`MSK`, Symmetric `AES-256-GCM`)**
   - **Alias:** `duolink_master_wrap_v1` inside `AndroidKeyStore`.
   - **Protection:** Hardware-backed TEE (or StrongBox on supported API 28+ devices with automatic fallback to TEE if StrongBox hardware is absent). `setRandomizedEncryptionRequired(true)` ensures the Keystore hardware generates a fresh random 96-bit IV for every seal operation. Non-exportable (`key.encoded == null`).
   - **Purpose:** Seals `PeerTrustStore` (`duolink:trust_store:v1`), the persistent QR replay nonce ledger (`duolink:replay_ledger:v1`), and wrapped local pre-key material on API 26–30.

2. **Long-Term Device Identity Signing Key (`IK_sig`, Asymmetric `EC P-256`)**
   - **Alias:** `duolink_identity_sig_v1` inside `AndroidKeyStore` (`KeyProperties.PURPOSE_SIGN | PURPOSE_VERIFY`, `ECGenParameterSpec("secp256r1")`, `DIGEST_SHA256`).
   - **Protection:** Non-exportable hardware-backed private key across **all Android 8.0+ (`API 26+`)** devices. Private key bytes **never** enter JVM heap memory and **never** leave the device.
   - **Deterministic `deviceId` Binding:**
     $$\text{deviceId} = \text{HexLower}\Big(\text{SHA-256}(\text{"DUOLINK-DEVICE-ID-V1\x00"} \parallel \text{SPKI}(\text{IK}_{\text{sig,pub}}))[0..15]\Big)$$
     This 128-bit (32-hex-char) identifier cryptographically binds every `deviceId` to its `IK_sig` public key, preventing Unknown Key-Share (UKS) and identity substitution attacks.

3. **Signed Pre-Key for Key Agreement (`SPK_dh`, Asymmetric `EC P-256` ECDH)**
   - **Purpose:** Enables authenticated Diffie-Hellman key agreement during pairing (`RootPairingKey`) and Milestone 3 session establishment while keeping signing (`IK_sig`) strictly separated from ECDH (`SPK_dh`) — enforcing cryptographic **key-purpose separation** (never reusing the same EC keypair for both ECDSA signing and ECDH!).
   - **Storage:**
     - On **Android 12+ (`API 31+`)**: Generated directly inside `AndroidKeyStore` with `KeyProperties.PURPOSE_AGREE_KEY` (`non-exportable`).
     - On **Android 8.0–11 (`API 26–30`)**: Generated via `AndroidOpenSSL` JCA `EC` (`secp256r1`), PKCS#8 private key immediately sealed under `AndroidKeyStore` `MSK` (`AES-256-GCM`, `AAD = "duolink:spk_dh:v1|<spkId>"`), plaintext PKCS#8 byte array zeroized in memory immediately after sealing and immediately after each `KeyAgreement.generateSecret()`.
   - **Identity Binding Signature (`spkSig`):** Signed by `IK_sig` (`SHA256withECDSA`) over length-prefixed binary transcript:
     $$\text{Transcript}_{\text{SPK}} = \text{LP}(\text{"DUOLINK-SPK-V1"}) \parallel \text{LP}(\text{deviceId}) \parallel \text{U32BE}(\text{spkId}) \parallel \text{U64BE}(\text{issuedAt}) \parallel \text{U64BE}(\text{expiresAt}) \parallel \text{LP}(\text{SPKI}(\text{SPK}_{\text{dh,pub}}))$$

4. **Root Pairing Key (`RPK`, 256-bit Secret) & Forward Session Derivation**
   - Computed identically by both devices upon completing the mutual QR exchange:
     $$\text{Z}_{\text{dh}} = \text{ECDH}(\text{SPK}_{\text{dh,local,priv}}, \text{SPK}_{\text{dh,peer,pub}})$$
     $$\text{salt} = \text{SHA-256}(\text{LP}(\text{"DUOLINK-PAIR-SALT-V1"}) \parallel \text{LP}(\text{nonce}_{\text{offer}}) \parallel \text{LP}(\text{nonce}_{\text{accept}}))$$
     $$\text{info} = \text{LP}(\text{"DUOLINK-PAIR-ROOT-V1"}) \parallel \text{LP}(\text{sessionId}) \parallel \text{LP}(\text{offerDeviceId}) \parallel \text{LP}(\text{IK}_{\text{offer}}) \parallel \text{LP}(\text{acceptDeviceId}) \parallel \text{LP}(\text{IK}_{\text{accept}})$$
     $$\text{RPK} = \text{HKDF-SHA256}(\text{IKM} = \text{Z}_{\text{dh}}, \text{salt} = \text{salt}, \text{info} = \text{info}, \text{L} = 32)$$
   - Raw `Z_dh` is zeroized immediately after HKDF extraction. `RPK` is sealed on disk via `MSK` (`AES-256-GCM`) and only marked active once the user explicitly confirms the Safety Fingerprint.
   - In Milestone 3, per-session ephemeral ECDH keys (`EK_dh`) signed by `IK_sig` will combine with `RPK` in a ratcheted HKDF chain to provide **forward secrecy** for every conversation session.

---

## 3. Mutual Two-Device QR Pairing Protocol (`DUOLINK-QR-PAIR-V1`)

### 3.1 Protocol Flow

1. **Step 1 — Offer Generation (Device A / Initiator):**
   - Generates 16-byte random `sessionId` and 32-byte random `nonceA` (`SecureRandom`).
   - Sets `iat = nowEpochSec`, `exp = iat + 300` (5-minute TTL; clock-skew grace `±60s`).
   - Signs canonical length-prefixed transcript `"DUOLINK-QR-OFFER-V1"` with `IK_sig_A`.
   - Encodes URI `duolink://pair/v1?<base64url-payload>` as an offline QR bitmap.

2. **Step 2 — Offer Verification & Accept Generation (Device B / Responder):**
   - Rejects immediately if:
     - Already `PAIRED` with a *different* `deviceId` (**`ThirdDeviceBlocked`** — enforces strictly 2 devices).
     - Previously pinned peer `ikSigPub` changed (**`PeerKeyChangedWarning`** — surfaces blocking alert comparing old vs. new Safety Fingerprints).
     - `offer.deviceId == localDeviceId` (**`SelfPairingAttempt`**).
     - `deviceId != SHA256("DUOLINK-DEVICE-ID-V1\x00" || offer.ikSigPub)[0..15]` (**`IdentitySubstitution`**).
     - Expired or future-skewed timestamp (**`ExpiredQrPayload`**).
     - `(sessionId, nonceA)` already recorded in persistent sealed replay ledger (**`ReplayedQrNonce`**).
     - `spkSig` or `offer.sig` fails `SHA256withECDSA` verification or curve-point validation (**`TamperedSignature`**).
   - Generates 32-byte random `nonceB`, computes `offerDigest = SHA-256(offerTranscriptBytes)`, signs `"DUOLINK-QR-ACCEPT-V1"` binding `sessionId`, `peerDeviceId = offer.deviceId`, and `offerDigest`, records `nonceA` in the sealed replay ledger, and displays its Response QR (`ACCEPT`) alongside the computed **60-digit Safety Fingerprint**.

3. **Step 3 — Accept Verification & Mutual Explicit Confirmation (Device A & Device B):**
   - Device A scans Device B's `ACCEPT` QR and verifies:
     - Active pending offer exists with matching `sessionId`.
     - `accept.peerDeviceId == deviceId_A` (**`WrongPeerTarget`** otherwise).
     - `accept.offerDigest == SHA-256(localPendingOfferTranscript)` (**`OfferDigestMismatch`** otherwise — defeats MITM offer-splicing).
     - Valid `deviceId_B` binding, freshness, non-replayed `nonceB`, valid `spkSig_B`, and valid `accept.sig`.
   - **Explicit Dual Confirmation Gate:** Both devices remain in `AWAITING_CONFIRMATION` (never auto-paired by scan alone). Both independently compute the identical **12-group, 60-digit Safety Fingerprint** (5,200-round iterated `SHA-512` over sorted peer identities) and **6-hex-pair Session Verification Code**. Each device transitions to `PAIRED` **only** when the user explicitly confirms on that device.

### 3.2 Nonce Handling, Key Rotation, and Secure Recovery

- **AES-GCM Nonces:** Never reused; generated via hardware `AndroidKeyStore` randomized IV (`12 bytes`) or `SecureRandom` (`12 bytes`) per encryption operation.
- **QR Pairing Nonces:** 256-bit `SecureRandom` per message + 5-minute TTL + persistent AES-GCM-sealed SHA-256 replay ledger (bounded FIFO of 512 entries) surviving app process restarts.
- **Signed Pre-Key (`SPK_dh`) Rotation:** `rotateSignedPreKey()` increments monotonic `spkId`, generates a fresh `P-256` ECDH keypair, signs it with `IK_sig`, seals it under `MSK`, and zeroizes retired key material.
- **Key-Change Warning & Secure Re-Pairing Recovery:** If Nasrin's phone is lost, factory-reset, or reinstalled, her new installation generates a fresh `IK_sig` and new `deviceId`. Attempting to pair with an already-paired phone raises a blocking warning (`ThirdDeviceBlocked` or `PeerKeyChangedWarning`). To re-pair legitimately, the user must open **Security & Device Identity (`امنیت و هویت دستگاه`)**, execute **Secure Pairing Reset (`لغو جفت‌سازی و بازنشانی امن`)**, and complete a fresh two-QR exchange with explicit Safety Fingerprint verification on both phones.

---

## 4. Threat Model & Honest Security Limitations

| Threat | Mitigation Implemented in Milestone 2 | Residual Risk / Boundary |
|---|---|---|
| **Passive or Active QR Tampering** | Canonical length-prefixed `SHA256withECDSA` signatures over both `OFFER` and `ACCEPT` + strict SPKI curve validation. | None for signature forgery under standard P-256 ECDSA assumptions. |
| **Man-in-the-Middle (MITM) During Pairing** | `ACCEPT` binds `SHA-256(offerTranscript)` + `peerDeviceId`; 5,200-round `SHA-512` Safety Fingerprint + Session Code requires explicit confirmation on **both** devices. | If **both** users click "Confirm" without actually comparing the displayed Safety Fingerprint out-of-band (in person or trusted voice check), an active physical/optical dual-QR relay could substitute keys. UI warns users explicitly to compare digits. |
| **Replay of Captured QR Codes** | 5-minute TTL (`iat`/`exp`) + 256-bit nonces + persistent Keystore-sealed replay ledger + session-bound `ACCEPT`. | Clock manipulation within the 5-minute TTL is still blocked once the nonce hits the persistent replay ledger. |
| **Unknown Key-Share / Identity Substitution** | `deviceId` is cryptographically derived from `SHA-256(IK_sig_pub)` and checked before signature verification. | Eliminated. |
| **Unauthorized 3rd Device Joining** | `PeerTrustStore` enforces a single pinned peer slot (`maxPeers = 1`); any 3rd device QR is rejected (`ThirdDeviceBlocked`). | Eliminated unless physical unlocked user deliberately resets pairing. |
| **Extraction of Private Keys / Cloud Backup Leakage** | `IK_sig` and `MSK` reside in `AndroidKeyStore`; `allowBackup="false"`, `fullBackupContent="false"`, and Android 12+ `dataExtractionRules` exclude cloud backup & D2D transfer. | Rooted OS, custom kernel exploit, or physical unlocked device access prior to Milestone 7 Biometric/PIN App Lock can access active app process. |
| **Screenshots / Screen Recording** | `FLAG_SECURE` enabled globally by default on `MainActivity` window. | **Honest limitation:** `FLAG_SECURE` cannot stop a second physical camera photographing the screen, HDMI hardware capture, or privileged hooks on a rooted phone. |
| **Independent Security Audit** | Modular, standard-primitive codebase with deterministic test coverage. | Has **not** undergone an external third-party cryptographic penetration audit; never claimed "unhackable". |
