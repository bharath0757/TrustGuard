# Security Model

The TrustGuard security architecture is built on foundational Zero-Trust security principles:

1. **Zero Trust & Default-to-Deny**:
   - Access to any examination paper is denied by default until all 6 criteria pass: Identity + Role + Request + Quorum + Time Window + Shard Integrity.
2. **Cryptographic Confidentiality & Integrity**:
   - Authenticated Encryption with Associated Data (AES-256-GCM) ensures ciphertext confidentiality and authenticity.
   - SHA-256 integrity hashes verify each individual fragment and the reconstructed manifest.
3. **Encrypted Fragment Distribution**:
   - Plaintext papers are never sharded or stored in plaintext. Ciphertext is sliced into $N$ authenticated shards.
4. **Multi-Party Quorum Authorization**:
   - No single user account can authorize access. $M$ distinct authorized approvers must approve before access is granted.
   - Separation of duties prevents requesters from approving their own requests.
5. **Just-In-Time (JIT) Temporal Access Control**:
   - Examination papers are accessible only during the strictly approved `[start_time, end_time]` window.
6. **Immutable Auditability & Zero Secret Logging**:
   - Every sensitive lifecycle event is immutably logged with WHO, WHAT, WHEN, WHICH RESOURCE, RESULT, and WHY.
   - Passwords, cryptographic keys, tokens, and exam content are strictly redacted.
7. **Secure Lifecycle & Replay Protection**:
   - Concluded sessions are expired, in-memory buffers are zeroed out, and subsequent replay attempts are blocked and flagged as threat events.

Refer to [`docs/SECURITY_SERVICE_GUIDE.md`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md) for backend service interfaces.
