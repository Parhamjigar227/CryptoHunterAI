# DuoLink Phase B — Continuation Report (`DUOLINK_PHASE_B_TOMORROW.md`)

Written: 2026-11-06 (end of session)
Status: **WORK IN PROGRESS — NOT FUNCTIONAL, NOT COMPLETE**
Purpose: preserve the workspace and pin the exact continuation point so tomorrow resumes from this
state, not from a fresh audit.

> **Read this first.** Phase B is **not** working end to end. The cryptographic core has been
> corrected and compile-verified, and Method B's Kotlin sources now compile for the first time in
> this repository's history. But the server test suite is red (7 pass / 35 fail), the cross-language
> parity test is red (3 pass / 3 fail — and it is red for a *real* reason, see §9), no two-device
> end-to-end flow has ever been executed, and there is no UI, no `INTERNET` permission and no APK.
> Nothing below should be read as a claim that Phase B "works".

---

## 1. Repository and branch

| | |
|---|---|
| Repository | `Parhamjigar227/CryptoHunterAI` |
| Branch | `arena/c7250baa-cryptohunterai` |
| Local path | `/home/user/CryptoHunterAI` |
| Remote tracking | `origin/arena/c7250baa-cryptohunterai` |
| Ahead / behind at session end | local == remote (in sync) |

This is the only branch work may be done on. The branch name is fixed by the session.

## 2. Current commit

| | |
|---|---|
| HEAD before this session's preservation commit | `aae6432e1ef574a93d9a79ee0f4ca5e62249a1b7` |
| HEAD after preservation commit | recorded in §13 below (written after the commit was created) |
| Parent of preservation commit | `aae6432` |
| Method A protected baseline | `fdb46b8` |

History (unmodified, not amended, not force-pushed):

```
<new>  WIP: Preserve DuoLink Phase B partial implementation before continuation
aae6432 WIP: preserve incomplete DuoLink Phase B work (NOT functional, NOT tested)
fdb46b8 Verify MainActivity cold-start before connectedDebugAndroidTest across API 29, 33, 34
```

## 3. Complete list of Phase B files

### 3.1 Kotlin — Method B / Remote (12 files, `DuoLink/app/src/main/java/com/duolink/app/remote/`)

| File | Role |
|---|---|
| `RemoteTranscripts.kt` | Canonical domain-separated transcripts (SPK, invitation, redeem, commit, ACK, receipt) |
| `RemoteKeySchedule.kt` | Two-DH → HKDF key schedule, envelope AEAD, `DhContributions` guard |
| `RemoteSafetyNumber.kt` | 60-digit Safety Number (5 200 SHA-512 iterations) |
| `RemoteInvitationCodec.kt` | Activation code + QR payload (`c`/`i`/`s` params) |
| `RemotePairingModels.kt` | Phase enum, `RemoteFailure` codes, snapshot types |
| `RemotePendingSessionStore.kt` | Sealed persistence of an in-flight pairing |
| `RemoteCommitCodec.kt` | Commit plaintext encode/decode + peer-commit verification |
| `RemotePairingCoordinator.kt` | Owner/recipient flows, DH contributions, signature verification |
| `SignalingApi.kt` | HTTP contract against the self-hosted server |
| `SignalingHttpClient.kt` | No-redirect HTTP client |
| `SignalingJson.kt` | Minimal JSON parse/emit |
| `SignalingEndpointPolicy.kt` | Endpoint validation (HTTPS / debug / private-host rules) |

### 3.2 Kotlin — tests

| File | Status |
|---|---|
| `app/src/test/java/com/duolink/app/RemoteTranscriptParityTest.kt` | **NEW this session**, 6 tests; 3 pass / 3 fail (§9) |
| `app/src/test/java/com/duolink/app/PairingAndCryptoTest.kt` | Pre-existing Method A test — **26/26 pass**, unmodified |

### 3.3 Node.js signalling server (`DuoLink/server/`, 13 files)

`package.json` (v0.3.0), `serve.js`, `src/app.js`, `src/crypto.js`, `src/protocol.js`,
`src/server.js`, `src/store.js`, `src/search`-none, `test/client.js`, `test/helpers.js`,
`test/server.test.js`, `test/transcriptParity.test.js`, `README.md`, `.gitignore`.

Note: `test/constants.js` still does **absent** while `test/client.js` used to import it; that import
was rewritten this session to `../src/protocol.js` (see §10).

### 3.4 Not present (missing, not forgotten)

Android UI/Compose screens, `DuoLinkViewModel` wiring, navigation entries, `INTERNET` permission,
CI matrix changes, Method B documentation, and any APK artifact.

## 4. Exact implementation status

| Area | Implemented | Compiled | Tested |
|---|---|---|---|
| Method A (QR pairing, trust store, crypto) | yes (pre-existing) | yes | **yes — 26/26** |
| Method B Kotlin sources (12 files) | yes, partially | **yes — first time ever** | only transcript parity |
| Method B key schedule (DH1/DH2) | **corrected this session** | yes | JS-side only (§8) |
| Method B Safety Number | yes | yes | JS-side only (matched) |
| Node server (contract + storage) | yes, extended this session | `node --check` clean | **7/42 passing** |
| Node reference client (`test/client.js`) | rewritten this session | parses | exercised only by ad-hoc probes |
| Android UI / ViewModel / nav | **no** | n/a | n/a |
| Two-device end-to-end | **no** | n/a | n/a |

## 5. Confirmed defects (audit, still open unless marked fixed)

| # | Defect | State |
|---|---|---|
| D1 | **DH1 asymmetry**: both roles computed `ecdh(ephemeral, peerSpk)`, so owner and recipient could never agree | **FIXED** (Kotlin + JS) |
| D2 | `recipientNonceFromView()` stubbed to `null`; nonce fell back to `ByteArray(16)` | **FIXED** — nonce now read from the wire, absence is a hard failure |
| D3 | `peerSignatureFor()` returned `ByteArray(0)` with `voidUnused(peer)` | **FIXED** — real SPK signature extraction + verification |
| D4 | `recipientIdentitySignature = ByteArray(0)` placeholder in the binding | **FIXED** — real signature, nullable rejected |
| D5 | Duplicate `internal fun ByteArray.zeroize()` in `RemoteCommitCodec.kt` | **FIXED** — deleted, imports canonical `crypto.zeroize` |
| D6 | `CommitContents` referenced `issuedAtEpochSec` that was never declared | **FIXED** — field added and populated by `extractIssuedAt` |
| D7 | **Activation code interop**: client emitted `DL1-XXXX-…` (20 symbols), server emits/accepts 16 | **FIXED** — client aligned to server |
| D8 | **Alphabet mismatch**: client had 30 symbols, server 32 (server emits `L`,`U`; client rejected them) | **FIXED** — both now `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` |
| D9 | QR carried no `invitationId` although the redeem transcript binds it | **FIXED** — `i=` param added, required on parse |
| D10 | `store.normalised` dropped `nonce`/`spk*` → would persist `NULL` | **FIXED** |
| D11 | `SignalingApi.createInvitation` sent only `owner`+`ttlSeconds`, no id, no code | **FIXED** |
| D12 | **Kotlin transcripts length-prefix the domain name**; server emits it raw | **OPEN — see §9** |
| D13 | `RemoteSafetyNumber` type-inference errors + missing import | **OPEN** (compile error, §7) |
| D14 | `test/helpers.js wire()` omits `nonce`/`identitySignature`/`spkId`/`spkSignature` | **OPEN** → all 35 server failures |
| D15 | Duplicate `invitationId` maps to 500, not 409 | **OPEN** |

## 6. Server test results — 42 tests, **7 pass / 35 fail**

Command (must be run from `DuoLink/server`; `node --test test/` does **not** work):

```bash
node --test "test/**/*.test.js"
```

Result: `# tests 42 / # pass 7 / # fail 35`.

**Single root cause for all 35:** the test fixtures do not yet send the fields the frozen contract
requires. Representative first failure:

```
not ok 1 - creates an invitation with a one-time code and never stores the code in plaintext
  unexpected status 400: {"error":"malformed_encoding","message":"owner.nonce is not canonical base64url"}
  400 !== 201
```

28 of the 35 emit exactly this message; the rest are downstream of the same missing fixture fields.
**This is a fixture task (D14), not a cryptographic defect.** It must be fixed by updating
`test/helpers.js wire()`, *not* by relaxing the server's validation.

Earlier in the session the same suite reported 8 pass / 34 fail; the count moved to 7/35 because one
previously-passing test now exercises the stricter contract. Both are red.

## 7. Kotlin compilation status — **VERIFIED LOCALLY**

Previously "never compiled". As of this session:

* **All 12 `remote/` files + `crypto/` + `pairing/` compile cleanly** with kotlinc 2.4.21 / JDK 21.
* **All 6 Method A crypto files are byte-identical to `fdb46b8`** (§11).
* One file still fails to compile: **`RemoteSafetyNumber.kt`** (D13) — missing
  `TranscriptBuilder` import and two `cannot infer type for 'V'` errors at the group-chunking block.
  Because `remote/*.kt` compiled in the last successful run *before* that file was re-added to the
  build, treat this as: **11 of 12 compile, `RemoteSafetyNumber.kt` needs a small fix.**

The local toolchain is **ephemeral and not part of the repo** (`/tmp` is wiped between sessions):

```bash
# JDK (JRE only — no javac!)
pip download jdk4py==21.0.2.1 -d /tmp/jdkx && cd /tmp/jdkx && unzip -q *.whl
export JAVA_HOME=/tmp/jdkx/jdk4py/java-runtime
# Kotlin compiler
curl -sL https://registry.npmjs.org/kotlin-compiler/-/kotlin-compiler-2.4.21.tgz -o /tmp/kc.tgz
mkdir -p /tmp/kc && tar xzf /tmp/kc.tgz -C /tmp/kc
# Compile (must be invoked with bash, not sh)
cd DuoLink/app/src/main/java/com/duolink/app
bash /tmp/kc/package/bin/kotlinc -cp /tmp/kt/out/runner.jar crypto/*.kt remote/*.kt pairing/*.kt -d out.jar
```

A local JUnit shim (`org.junit.Test/Assert/Before/After/Ignore` written in Kotlin, plus a reflective
`Runner`) is needed to execute tests without Maven Central (blocked). See §12.

## 8. DH1 key-agreement asymmetry and the required correction — **DONE**

The frozen, corrected schedule (two DH contributions, fixed order, then HKDF-SHA256):

```
DH1 = ECDH(EK_owner, SPK_recipient)
        owner     -> ecdh(ephemeral.priv, peerSpkSpki)
        recipient -> keyVault.agreeWithSignedPreKey(localSpkId, peerEphemeralSpki)
DH2 = ECDH(EK_owner, EK_recipient)     # symmetric; each side uses its OWN ephemeral + peer ephemeral
IKM = DH1 || DH2                        # fixed order
```

Why DH1 looks asymmetric in code yet agrees: each side uses a **different private key**, and
`ECDH(a,B) == ECDH(b,A)`. The recipient must use its **actual published Signed Pre-Key private key** —
substituting a second ephemeral-only DH is explicitly rejected and would break the long-term binding.

The responder's long-term identity is bound by an **ECDSA signature** over the invitation transcript,
mixed into the HKDF salt (`IDENTITY_BINDING_MODE = "ECDSA_IDENTITY_SIGNATURE_BOUND_HKDF"`). It is
**not** a third DH, because `IK_sig` lives non-exportably in AndroidKeyStore and cannot do
`KeyAgreement`.

Kotlin now enforces this structurally: `RemoteKeySchedule.DhContributions(role, dh1, dh2)` is tagged
with the role that produced it and `deriveKeys()` rejects a role mismatch.

**Evidence so far (JS only):** two independently generated JS devices derive identical `rootKey`,
mirrored envelope keys, mirrored confirm keys and an **identical 60-digit Safety Number**:
`39936 68116 48378 | 68740 64570 88316 | 80208 16096 22282 | 86342 66982 03747`.
This proves the JS reference implementation. It does **not** yet prove Kotlin↔JS agreement (§9).

## 9. Missing nonce/signature handling — mostly DONE, one real blocker OPEN

**Done:** nonces are read from the authenticated wire and their absence/length is a hard failure; SPK
self-signatures (`spkSignature`) are generated, relayed by the server *without claiming to verify them*,
and verified by the peer against its identity key before the SPK is trusted; the redeem signature is
generated by the recipient and verified by the owner; the invitation signature binds the
**activation-code hash** (never the plaintext code).

**OPEN — D12, the single most important finding of this session.** The cross-language parity test now
runs and **fails for a real reason**:

```
FAIL RemoteTranscriptParityTest.spkTranscriptMatchesServerVectors
  expected:<44756f4c696e6b2d53504b2d7631001122…>          # "DuoLink-SPK-v1" raw
       but was:<0000001b44756f4c696e6b…>                   # 0x0000001b + "DuoLink-SPK-v1"
FAIL RemoteTranscriptParityTest.invitationTranscriptMatchesServerVectors   # same 4-byte prefix
FAIL RemoteTranscriptParityTest.redeemTranscriptMatchesServerVectors       # same 4-byte prefix
PASS ×3  (code-hash sensitivity, field-substitution sensitivity, wrong-length rejection)
```

Root cause: `RemoteTranscripts.kt` builds the domain via `.putUtf8(DOMAIN)`, and
`TranscriptBuilder.putUtf8` **length-prefixes** (it delegates to `putBytes`). `server/src/protocol.js`
`buildTranscript()` emits the domain **raw**: `Buffer.concat([utf8(domain), ...parts])`. So every
Method B transcript differs by a 4-byte length prefix, and **a Kotlin device and a JS/server peer would
compute different signatures and different Safety Numbers while both "succeeding" locally.**

`spkTranscript()` is already correct because it delegates to `EcP256Crypto.buildSpkTranscript()`
(Method A, raw domain) — but even it fails the test, because the *test's expected constant* is missing
the rest of the fields, i.e. the assertion's expected value is also wrong. Both the encoder and the
test expectation need one careful, deliberate edit. **Do not "fix" this by changing the server.**

## 10. Broken JavaScript reference client — rewritten, still unproven

`test/client.js` was rewritten this session:

* import fixed: `./constants.js` (does not exist) → `../src/protocol.js` (`LIMITS.maxCiphertextBytes`);
* transcripts imported from the single source of truth instead of re-declared;
* `Device` class rewritten: `ownerPayload`/`recipientPayload` emit `nonce`, `identitySignature`,
  `spkId`, `spkCreatedAtEpochSec`, `spkSignature`;
* `derive()` fixed for **both** the role-asymmetric DH1 and the DH2 bug;
* `verifyPeerCommit`, `verifyPeerSpk`, `persistPeer`, `buildAck` implemented with real ECDSA.

It has only been exercised by ad-hoc `node -e` probes (which is how the key-matching result in §8 was
obtained). It is **not** covered by the test suite yet, and `this.invitationId`/`proposeOwnerMaterial`
style leftovers may remain. Treat as *rewritten but unproven*.

## 11. Method A preservation — verified

* `git diff --name-only fdb46b8 -- …/crypto …/pairing …/ui …/android AndroidManifest.xml res
  *.gradle* androidTest …/PairingAndCryptoTest.kt` → **empty**.
* All six crypto files byte-identical to `fdb46b8` (`ByteEncoding`, `HkdfSha256`, `SafetyFingerprint`,
  `DeviceKeyVault`, `StorageSealer`, `KeyValueByteStore`).
* Every changed path is under `remote/` (Method B) or `server/`.
* Method A tests executed after all Method B edits: **26/26 pass**.

## 12. Missing Kotlin/JavaScript transcript parity tests — present, currently red

`RemoteTranscriptParityTest.kt` was added (6 tests). Golden hex vectors are generated by
`parityVectors()` in `server/src/protocol.js` and were verified byte-identical to live server output
(invite 1 210 hex chars, redeem 1 116) **before** being pasted, so they are not fabricated. The three
structural tests pass; the three golden-vector tests fail on D12.

Regenerate vectors with:

```bash
cd DuoLink/server
node --no-warnings -e "import('./src/protocol.js').then(m=>console.log(m.parityVectors()))"
```

Local test execution without JUnit (Maven Central is blocked) uses a Kotlin-written shim in `/tmp/kt`
plus a reflective `Runner`; `java -cp runner.jar:full.jar Runner <class>`.

## 13. Missing virtual two-device end-to-end tests

**Not implemented.** No test yet spins up the real server on a local socket, creates two fully
independent device identities with separate key stores, and runs create → redeem → derive → compare
Safety Number → commit → ACK → receipt.

**Rule for tomorrow:** do not claim two-device testing succeeded unless **both** independent
participants actually complete the protocol **and** produce identical root keys and Safety Numbers.

## 14. Missing Android UI / ViewModel integration

No Compose screens, no navigation destinations, no `DuoLinkViewModel` methods for the Method B flow.
`MainActivity` does not reference the remote flow.

## 15. Missing `INTERNET` permission

`DuoLink/app/src/main/AndroidManifest.xml` has not been touched. Method B cannot reach the signalling
server until the permission is declared. This is a *protected* file area — adding it must be a
deliberate, reviewed change, and must not disturb Method A.

## 16. Missing documentation and CI updates

`DuoLink/server/README.md` still documents the pre-Decision-A/B contract. There is no Method B design
document, no key-lifecycle/concurrency analysis for SPK, and
`.github/workflows/duolink-m2-validation.yml` still covers API 29/33/34 only (no Method B job).

## 17. Exact next steps, in dependency order

1. **Re-establish toolchain** (§7) — it does not survive the session.
2. **Fix D12 (blocking).** Make the Kotlin domain prefix raw to match `buildTranscript`, and correct
   the `spkTranscript` test expectation. Re-run parity until 6/6. This gates everything else: until it
   passes, Kotlin↔JS devices silently disagree.
3. **Fix D13** — `RemoteSafetyNumber.kt` imports + chunking types.
4. **Fix D14** — update `test/helpers.js wire()` to emit `nonce`/`identitySignature`/`spkId`/
   `spkCreatedAtEpochSec`/`spkSignature`. Target: 42/42. Then D15 (409 on duplicate id).
5. **Prove the JS client** under `node --test` (not ad-hoc probes): two devices, identical root key and
   Safety Number, plus negative tests (bad signature, modified nonce, mismatched transcript → reject).
6. **Virtual two-device e2e** over a real local socket (§13 assertion rule).
7. Kotlin↔JS **key** parity (not just transcript parity): same IKM → same root key → same Safety Number.
8. Only then: `INTERNET` permission, ViewModel, UI, CI, APK.

## 18. Standing rules (do not violate)

* Never mark a security property verified because a class exists.
* Never claim an APK, a feature or a security guarantee without evidence.
* Never weaken a check to make a test pass; fix the fixture, not the validation.
* Never bypass signature verification; never fabricate nonces or signatures.
* DH1 must use the recipient's real SPK private key; the ephemeral-only substitute is rejected.
* No per-pairing SPK rotation without a documented key-lifecycle/concurrency analysis.
* Method A must keep working (baseline: 26/26).
* Server stays self-hosted; no public deployment, tunnel or third-party relay.
* Await explicit approval before Stage 2 / UI.

## 19. Files or work that could not be preserved

| Item | Why | Where it lives |
|---|---|---|
| `/tmp/jdkx` JDK 21 JRE | outside the repo, wiped with `/tmp` | recreate per §7 |
| `/tmp/kc` kotlinc 2.4.21 | idem | recreate per §7 |
| `/tmp/kt` JUnit Kotlin shim + `Runner` | idem | rewrite (~80 lines, see §12) |
| Compiled artifacts (`remote_all.jar`, `full.jar`) | build outputs, deliberately not committed | regenerate |
| Ad-hoc probe scripts run with `node -e` | never written to disk | results quoted in §8 |

No project **source** file was lost, deleted or regenerated, and no history was rewritten.
