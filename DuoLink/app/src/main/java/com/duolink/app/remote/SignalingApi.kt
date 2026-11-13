package com.duolink.app.remote

/**
 * Typed facade over the signaling protocol.
 *
 * Responsibilities are deliberately narrow: serialise a request, call [SignalingHttpClient], parse the
 * response into an immutable data class, and reject any response that violates the protocol contract.
 * **No security decision is taken here.** In particular this class never says "pairing succeeded"; it
 * reports what the server said, and [RemotePairingCoordinator] decides what that means only after
 * cryptographic verification.
 */
class SignalingApi(private val client: SignalingHttpClient) {

    data class CreatedInvitation(
        val invitationId: String,
        val activationCode: String,
        val ownerToken: String,
        val protocolVersion: Int,
        val createdAtEpochSec: Long,
        val expiresAtEpochSec: Long
    )

    data class RedeemedInvitation(
        val invitationId: String,
        val recipientToken: String,
        val expiresAtEpochSec: Long
    )

    /** Public key material a participant registers for one pairing attempt. */
    /**
     * Public material one device publishes for a pairing.
     *
     * [identitySignature] is an ECDSA signature by [identitySpki] over the canonical invitation (owner)
     * or redeem (recipient) transcript. [spkSignature] is an ECDSA signature by [identitySpki] over the
     * canonical SPK transcript (Decision A). Neither is verifiable by the server; both are verified by
     * the peer. [nonce] is the role's 128-bit contribution to the handshake binding.
     */
    data class ParticipantMaterial(
        val deviceId: ByteArray,
        val identitySpki: ByteArray,
        val ackSpki: ByteArray,
        val spkSpki: ByteArray,
        val ephemeralSpki: ByteArray,
        val nonce: ByteArray,
        val identitySignature: ByteArray,
        val spkId: Int,
        val spkCreatedAtEpochSec: Long,
        val spkSignature: ByteArray
    )

    /**
     * Peer material as relayed by the signalling server. Values here are *claims*: nothing may be trusted
     * until [identitySignature] and [spkSignature] have been verified against [identitySpki].
     */
    data class PeerMaterial(
        val deviceId: ByteArray,
        val identitySpki: ByteArray,
        val ackSpki: ByteArray,
        val spkSpki: ByteArray,
        val ephemeralSpki: ByteArray?,
        val nonce: ByteArray?,
        val identitySignature: ByteArray?,
        val spkId: Int?,
        val spkCreatedAtEpochSec: Long?,
        val spkSignature: ByteArray?
    )

    data class CommitAck(
        val accepted: Boolean,
        val replay: Boolean,
        val quorumReached: Boolean,
        val commitDigestOwner: ByteArray?,
        val commitDigestRecipient: ByteArray?,
        val ciphertextReceiptOnly: Boolean,
        val e2eeValidityVerifiedByServer: Boolean
    )

    /**
     * The caller's view of an invitation.
     *
     * [e2eeValidityVerifiedByServer] and [ciphertextReceipt] are surfaced verbatim from the server so the
     * UI can state, accurately, that receipt ≠ validation.
     */
    data class InvitationView(
        val invitationId: String,
        val state: String,
        val role: RemoteRole,
        val protocolVersion: Int,
        val expiresAtEpochSec: Long,
        val redeemed: Boolean,
        val quorumReached: Boolean,
        val mutualReceipt: Boolean,
        val ciphertextReceiptOwner: Boolean,
        val ciphertextReceiptRecipient: Boolean,
        val e2eeValidityVerifiedByServer: Boolean,
        val ownCommitDigest: ByteArray?,
        val peerCommitDigest: ByteArray?,
        val peerCommitCiphertext: ByteArray?,
        val peer: PeerMaterial?,
        val ownerAckRecorded: Boolean,
        val recipientAckRecorded: Boolean,
        val ownerAckSignature: ByteArray?,
        val recipientAckSignature: ByteArray?
    )

    data class AckResponse(
        val mutualReceipt: Boolean,
        val ackDigestOwner: ByteArray?,
        val ackDigestRecipient: ByteArray?,
        val ackSignatureOwner: ByteArray?,
        val ackSignatureRecipient: ByteArray?,
        val receiptTranscript: ByteArray?,
        val receiptSignature: ByteArray?,
        val e2eeHmacVerifiedByServer: Boolean
    )

    data class ServerInfo(
        val protocolVersion: Int,
        val verifiesEcdsaAckSignatures: Boolean,
        val verifiesPeerHmac: Boolean,
        val decryptsCommitCiphertext: Boolean,
        val storesPlaintextActivationCode: Boolean,
        val invitationTtlSeconds: Long
    )

    /**
     * Creates an invitation.
     *
     * [invitationId] is assigned by the client because the owner's invitation transcript binds it — the
     * signature must exist before anything is uploaded, and the recipient must be able to bind the same
     * id from the QR code alone (so it travels in the QR as well).
     */
    fun createInvitation(
        baseUrl: String,
        invitationId: String,
        owner: ParticipantMaterial,
        activationCode: String,
        ttlSeconds: Long? = null,
        /**
         * The absolute expiry the owner signed into `identitySignature`.
         *
         * Must be uploaded verbatim: the joining device rebuilds the invitation transcript to verify
         * that signature, and the transcript contains this exact number. Letting the server pick its
         * own `createdAt + ttl` would put a different value in the transcript than the one that was
         * signed, and verification would fail for every invitation.
         */
        expiresAtEpochSec: Long? = null
    ): CreatedInvitation {
        val body = SignalingHttpClient.jsonObject(
            "invitationId" to SignalingHttpClient.jsonString(invitationId),
            "activationCode" to SignalingHttpClient.jsonString(activationCode),
            "owner" to participantJson(owner),
            "ttlSeconds" to (ttlSeconds?.toString() ?: "null"),
            "expiresAtEpochSec" to (expiresAtEpochSec?.toString() ?: "null")
        )
        val obj = SignalingJson.parseObject(client.execute(baseUrl, "POST", "/v1/invitations", jsonBody = body))
        return CreatedInvitation(
            invitationId = SignalingJson.requireString(obj, "invitationId"),
            activationCode = SignalingJson.requireString(obj, "activationCode"),
            ownerToken = SignalingJson.requireString(obj, "ownerToken"),
            protocolVersion = SignalingJson.requireLong(obj, "protocolVersion").toInt(),
            createdAtEpochSec = SignalingJson.requireLong(obj, "createdAtEpochSec"),
            expiresAtEpochSec = SignalingJson.requireLong(obj, "expiresAtEpochSec")
        )
    }

    /** Result of a read-only code -> invitation-id lookup. Carries no key material by construction. */
    data class ResolvedInvitation(
        val invitationId: String,
        val expiresAtEpochSec: Long
    )

    /**
     * Resolves a typed activation code to its invitation id, WITHOUT redeeming.
     *
     * The numeric-code flow needs this: the recipient must sign a redeem transcript that binds the
     * invitation id, but a ten-digit code cannot carry an id the way a QR payload can. The QR flow never
     * calls this - it already has the id from `?i=`.
     *
     * Read-only: the invitation stays CREATED and redeemable. Single-use is still enforced only in
     * [redeemInvitation], so calling this twice and then redeeming once is the expected sequence.
     *
     * Only `invitationId` and `expiresAtEpochSec` are read from the response. Every other field the
     * server might ever add is ignored here on purpose: the client should not start depending on
     * unauthenticated data even if the server accidentally starts sending it.
     */
    fun resolveInvitationByCode(baseUrl: String, activationCode: String): ResolvedInvitation {
        // Canonicalise HERE, at the transport boundary, not at each call site. Two devices pairing with
        // one code must put byte-identical bytes on the wire, and a caller passing "4829137462" while
        // another passes "482-913-7462" must not produce two semantically different requests. Putting the
        // canonicalisation in the API means no future caller can forget it.
        val canonical = canonicalCodeOrThrow(activationCode)
        val body = SignalingHttpClient.jsonObject(
            "activationCode" to SignalingHttpClient.jsonString(canonical)
        )
        val obj = SignalingJson.parseObject(
            client.execute(baseUrl, "POST", "/v1/invitations/resolve", jsonBody = body)
        )
        return ResolvedInvitation(
            invitationId = SignalingJson.requireString(obj, "invitationId"),
            expiresAtEpochSec = SignalingJson.requireLong(obj, "expiresAtEpochSec")
        )
    }

    fun redeemInvitation(baseUrl: String, activationCode: String, recipient: ParticipantMaterial): RedeemedInvitation {
        // Same canonicalisation as resolveInvitationByCode: the redemption request must carry exactly the
        // canonical form the lookup used, so the server cannot see two "different" codes for one secret.
        val canonical = canonicalCodeOrThrow(activationCode)
        val body = SignalingHttpClient.jsonObject(
            "activationCode" to SignalingHttpClient.jsonString(canonical),
            "recipient" to participantJson(recipient)
        )
        val obj = SignalingJson.parseObject(client.execute(baseUrl, "POST", "/v1/invitations/redeem", jsonBody = body))
        return RedeemedInvitation(
            invitationId = SignalingJson.requireString(obj, "invitationId"),
            recipientToken = SignalingJson.requireString(obj, "recipientToken"),
            expiresAtEpochSec = SignalingJson.requireLong(obj, "expiresAtEpochSec")
        )
    }

    /**
     * Parses and canonicalises an activation code for transmission, failing closed on anything that is
     * not a real code.
     *
     * Rejecting at the transport boundary matters for more than tidiness: the server's attempt budget is
     * GLOBAL and shared by every user, so a caller that sent obvious garbage would burn a slot of that
     * shared budget and help nobody. Failing locally costs nothing.
     */
    private fun canonicalCodeOrThrow(raw: String): String =
        ActivationCode.parse(raw)?.displayForm
            ?: throw RemotePairingException(
                RemoteFailure.ACTIVATION_CODE_MALFORMED,
                "قالب کد دعوت معتبر نیست"
            )

    fun getInvitation(baseUrl: String, invitationId: String, token: String): InvitationView {
        val obj = SignalingJson.parseObject(
            client.execute(baseUrl, "GET", "/v1/invitations/${pathSegment(invitationId)}", bearerToken = token)
        )
        val role = RemoteRole.fromWire(SignalingJson.requireString(obj, "role"))
            ?: throw RemotePairingException(RemoteFailure.SERVER_REJECTED_REQUEST, "نقش دستگاه در پاسخ سرور نامعتبر است")
        val receipt = SignalingJson.optionalObject(obj, "ciphertextReceipt")
        val peerObj = SignalingJson.optionalObject(obj, "peer")
        val acks = SignalingJson.optionalObject(obj, "acks")
        val state = SignalingJson.requireString(obj, "state")
        return InvitationView(
            invitationId = SignalingJson.requireString(obj, "invitationId"),
            state = state,
            role = role,
            protocolVersion = SignalingJson.requireLong(obj, "protocolVersion").toInt(),
            expiresAtEpochSec = SignalingJson.requireLong(obj, "expiresAtEpochSec"),
            redeemed = SignalingJson.requireBool(obj, "redeemed"),
            quorumReached = SignalingJson.requireBool(obj, "quorumReached"),
            mutualReceipt = SignalingJson.requireBool(obj, "mutualReceipt"),
            ciphertextReceiptOwner = receipt?.let { SignalingJson.optionalBool(it, "owner") } ?: false,
            ciphertextReceiptRecipient = receipt?.let { SignalingJson.optionalBool(it, "recipient") } ?: false,
            e2eeValidityVerifiedByServer = SignalingJson.optionalBool(obj, "e2eeValidityVerifiedByServer") ?: false,
            ownCommitDigest = SignalingJson.optionalBytes(obj, "ownCommitDigestB64u"),
            peerCommitDigest = SignalingJson.optionalBytes(obj, "peerCommitDigestB64u"),
            peerCommitCiphertext = SignalingJson.optionalBytes(obj, "peerCommitCiphertextB64u"),
            peer = peerObj?.let { peer ->
                PeerMaterial(
                    deviceId = SignalingJson.requireBytes(peer, "deviceIdB64u"),
                    identitySpki = SignalingJson.requireBytes(peer, "identitySpkiB64u"),
                    ackSpki = SignalingJson.requireBytes(peer, "ackSpkiB64u"),
                    spkSpki = SignalingJson.requireBytes(peer, "spkSpkiB64u"),
                    ephemeralSpki = SignalingJson.optionalBytes(peer, "ephemeralSpkiB64u"),
                    nonce = SignalingJson.optionalBytes(peer, "nonceB64u"),
                    identitySignature = SignalingJson.optionalBytes(peer, "identitySignatureB64u"),
                    spkId = SignalingJson.optionalLong(peer, "spkId")?.toInt(),
                    spkCreatedAtEpochSec = SignalingJson.optionalLong(peer, "spkCreatedAtEpochSec"),
                    spkSignature = SignalingJson.optionalBytes(peer, "spkSignatureB64u")
                )
            },
            ownerAckRecorded = acks?.let { SignalingJson.optionalBool(it, "ownerRecorded") } ?: false,
            recipientAckRecorded = acks?.let { SignalingJson.optionalBool(it, "recipientRecorded") } ?: false,
            ownerAckSignature = acks?.let { SignalingJson.optionalBytes(it, "ownerSignatureB64u") },
            recipientAckSignature = acks?.let { SignalingJson.optionalBytes(it, "recipientSignatureB64u") }
        )
    }

    fun submitCommit(
        baseUrl: String,
        invitationId: String,
        token: String,
        role: RemoteRole,
        ciphertext: ByteArray
    ): CommitAck {
        val digest = com.duolink.app.crypto.ByteEncoding.sha256(ciphertext)
        val body = SignalingHttpClient.jsonObject(
            "role" to SignalingHttpClient.jsonString(role.wireValue),
            "commitCiphertextB64u" to SignalingHttpClient.b64u(ciphertext),
            "commitDigestB64u" to SignalingHttpClient.b64u(digest)
        )
        val obj = SignalingJson.parseObject(
            client.execute(baseUrl, "POST", "/v1/invitations/${pathSegment(invitationId)}/commit", token, body)
        )
        return CommitAck(
            accepted = SignalingJson.requireBool(obj, "accepted"),
            replay = SignalingJson.requireBool(obj, "replay"),
            quorumReached = SignalingJson.requireBool(obj, "quorumReached"),
            commitDigestOwner = SignalingJson.optionalBytes(obj, "commitDigestOwnerB64u"),
            commitDigestRecipient = SignalingJson.optionalBytes(obj, "commitDigestRecipientB64u"),
            ciphertextReceiptOnly = SignalingJson.optionalBool(obj, "ciphertextReceiptOnly") ?: true,
            e2eeValidityVerifiedByServer = SignalingJson.optionalBool(obj, "e2eeValidityVerifiedByServer") ?: false
        )
    }

    fun submitAck(baseUrl: String, invitationId: String, token: String, role: RemoteRole, signature: ByteArray): AckResponse {
        val body = SignalingHttpClient.jsonObject(
            "role" to SignalingHttpClient.jsonString(role.wireValue),
            "ackSignatureB64u" to SignalingHttpClient.b64u(signature)
        )
        val obj = SignalingJson.parseObject(
            client.execute(baseUrl, "POST", "/v1/invitations/${pathSegment(invitationId)}/ack", token, body)
        )
        val signatures = SignalingJson.optionalObject(obj, "ackSignatures")
        val receipt = SignalingJson.optionalObject(obj, "serverReceipt")
        return AckResponse(
            mutualReceipt = SignalingJson.requireBool(obj, "mutualReceipt"),
            ackDigestOwner = SignalingJson.optionalBytes(obj, "ackDigestOwnerB64u"),
            ackDigestRecipient = SignalingJson.optionalBytes(obj, "ackDigestRecipientB64u"),
            ackSignatureOwner = signatures?.let { SignalingJson.optionalBytes(it, "ownerB64u") },
            ackSignatureRecipient = signatures?.let { SignalingJson.optionalBytes(it, "recipientB64u") },
            receiptTranscript = receipt?.let { SignalingJson.optionalBytes(it, "transcriptB64u") },
            receiptSignature = receipt?.let { SignalingJson.optionalBytes(it, "signatureB64u") },
            e2eeHmacVerifiedByServer = SignalingJson.optionalBool(obj, "e2eeHmacVerifiedByServer") ?: false
        )
    }

    fun revoke(baseUrl: String, invitationId: String, token: String): String {
        val obj = SignalingJson.parseObject(
            client.execute(baseUrl, "POST", "/v1/invitations/${pathSegment(invitationId)}/revoke", token)
        )
        return SignalingJson.requireString(obj, "state")
    }

    fun reject(baseUrl: String, invitationId: String, token: String): String {
        val obj = SignalingJson.parseObject(
            client.execute(baseUrl, "POST", "/v1/invitations/${pathSegment(invitationId)}/reject", token)
        )
        return SignalingJson.requireString(obj, "state")
    }

    fun serverInfo(baseUrl: String): ServerInfo {
        val obj = SignalingJson.parseObject(client.execute(baseUrl, "GET", "/v1/server-info"))
        val capabilities = SignalingJson.optionalObject(obj, "capabilities")
        return ServerInfo(
            protocolVersion = SignalingJson.requireLong(obj, "protocolVersion").toInt(),
            verifiesEcdsaAckSignatures = capabilities?.let { SignalingJson.optionalBool(it, "verifiesEcdsaAckSignatures") } ?: false,
            verifiesPeerHmac = capabilities?.let { SignalingJson.optionalBool(it, "verifiesPeerHmac") } ?: false,
            decryptsCommitCiphertext = capabilities?.let { SignalingJson.optionalBool(it, "decryptsCommitCiphertext") } ?: false,
            storesPlaintextActivationCode = capabilities?.let { SignalingJson.optionalBool(it, "storesPlaintextActivationCode") } ?: false,
            invitationTtlSeconds = SignalingJson.optionalLong(obj, "invitationTtlSeconds") ?: 900L
        )
    }

    private fun participantJson(material: ParticipantMaterial): String = SignalingHttpClient.jsonObject(
        "deviceId" to SignalingHttpClient.b64u(material.deviceId),
        "identitySpki" to SignalingHttpClient.b64u(material.identitySpki),
        "ackSpki" to SignalingHttpClient.b64u(material.ackSpki),
        "spkSpki" to SignalingHttpClient.b64u(material.spkSpki),
        "ephemeralSpki" to SignalingHttpClient.b64u(material.ephemeralSpki),
        "nonce" to SignalingHttpClient.b64u(material.nonce),
        "identitySignature" to SignalingHttpClient.b64u(material.identitySignature),
        "spkId" to material.spkId.toString(),
        "spkCreatedAtEpochSec" to material.spkCreatedAtEpochSec.toString(),
        "spkSignature" to SignalingHttpClient.b64u(material.spkSignature)
    )

    /** Path segments are validated, never interpolated blindly (defence against path traversal). */
    private fun pathSegment(value: String): String {
        if (value.isEmpty() || value.length > 64 || !value.all { it.isLetterOrDigit() || it == '_' || it == '-' }) {
            throw RemotePairingException(RemoteFailure.SERVER_REJECTED_REQUEST, "شناسه دعوت نامعتبر است")
        }
        return value
    }
}
