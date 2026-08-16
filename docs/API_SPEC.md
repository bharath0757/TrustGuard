# API Specification & Security Service Mapping

This document maps FastAPI route endpoints to the corresponding centralized security service interfaces in `security/service.py`.

---

## Endpoint to Security Service Mapping

| HTTP Endpoint | Controller Action | Security Service Interface |
|:---|:---|:---|
| `POST /api/papers` | Register & Encrypt Question Paper | [`protect_paper()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#1-protect_paper) |
| `POST /api/papers/{id}/fragment` | Shard Encrypted Ciphertext | [`fragment_paper()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#2-fragment_paper) |
| `GET /api/papers/{id}/fragments/validate` | Verify Shard Integrity | [`validate_fragments()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#3-validate_fragments) |
| `POST /api/papers/{id}/requests` | Submit Access Request | [`create_access_request()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#4-create_access_request) |
| `GET /api/requests/{id}/quorum` | Check Quorum Progress | [`check_quorum()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#5-check_quorum) |
| `GET /api/windows/{id}/validate` | Check Access Window Status | [`is_access_window_valid()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#6-is_access_window_valid) |
| `POST /api/papers/{id}/authorize` | Evaluate JIT Access (6-factor) | [`authorize_access()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#7-authorize_access) |
| `POST /api/papers/{id}/reconstruct` | Reassemble Protected Shards | [`reconstruct_paper()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#8-reconstruct_paper) |
| `POST /api/papers/{id}/decrypt` | Decrypt & Verify Manifest Hash | [`decrypt_paper()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#9-decrypt_paper) |
| `POST /api/papers/{id}/complete` | Close Session & Block Replay | [`complete_access()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#10-complete_access) |
| `POST /api/audit/events` | Record Custom Audit Event | [`create_audit_event()`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md#11-create_audit_event) |

---

## Detailed Service Documentation

For comprehensive signatures, parameter descriptions, exception types, authorization rules, and code examples, see [`docs/SECURITY_SERVICE_GUIDE.md`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md).
