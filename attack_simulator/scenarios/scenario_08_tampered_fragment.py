"""
Scenario 8: Controlled Integrity-Tampering Simulation.

SCENARIO DESCRIPTION:
Adversary or environmental corruption modifies an encrypted fragment or its integrity
metadata in the storage layer.

STEPS EXECUTED:
1. Create protected question paper.
2. Encrypt it with AES-256-GCM.
3. Create fragments (shards).
4. Store fragments in database.
5. Modify fragment in the test environment (both content and metadata).
6. Attempt normal reconstruction/access.

EXPECTED BEHAVIOR:
- Integrity validation must fail.
- Refuses reconstruction (FragmentIntegrityError / FragmentValidationError).
- Refuses decryption (DecryptionFailedError / AccessDeniedError).
- Generates an audit and security threat event (INTEGRITY_FAILURE).
- Avoids returning plaintext (0 bytes leaked).
- Clearly reports integrity failure.

TESTS BOTH:
- Modified fragment content (corrupted payload bytes)
- Invalid fragment integrity metadata (tampered SHA-256 digest)
"""

from datetime import datetime, timedelta, timezone
import hashlib
import uuid
from sqlalchemy.orm import Session

from database.models.access import ApprovalDecision, RequestStatus
from database.models.audit import ThreatEventType, ThreatSeverity
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User, Role, UserRole
from security import (
    validate_fragments,
    reconstruct_paper,
    decrypt_paper,
    create_access_request,
    cast_approval_vote,
    create_access_window,
    authorize_access,
    execute_jit_paper_access,
    AccessDecision,
)
from security.crypto.fragmentation import (
    FragmentPayload,
    FragmentIntegrityError,
    FragmentValidationError,
)
from security.crypto.encryption import DecryptionFailedError
from security.quorum import AccessDeniedError
from security.access_window import JITAccessDeniedError
from security.audit import record_threat_incident
from attack_simulator.fixtures import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario08TamperedFragment(BaseAttackScenario):
    scenario_id = 8
    scenario_name = "Tampered fragment/integrity failure"
    description = "Adversary alters fragment payload ciphertext bytes or recorded SHA-256 digest"

    def run(self, db: Session, client=None) -> SimulationResult:
        now = datetime.now(timezone.utc)
        now_str = now.isoformat()

        # 1. Setup Users & Roles
        r_officer = db.query(Role).filter(Role.name == "OFFICER").first()
        if not r_officer:
            r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
            db.add(r_officer)
        r_approver = db.query(Role).filter(Role.name == "APPROVER").first()
        if not r_approver:
            r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Approver")
            db.add(r_approver)
        db.flush()

        def make_user(email: str, name: str, role: Role) -> User:
            u = User(
                id=uuid.uuid4(),
                email=email,
                password_hash=hashlib.sha256(b"Pass2026!").hexdigest(),
                full_name=name,
                is_active=True,
            )
            db.add(u)
            db.flush()
            db.add(UserRole(user_id=u.id, role_id=role.id))
            db.flush()
            return u

        officer = make_user(f"officer.tamper.{uuid.uuid4().hex[:6]}@synth.local", "Officer Alice", r_officer)
        app1 = make_user(f"app1.tamper.{uuid.uuid4().hex[:6]}@synth.local", "Approver 1", r_approver)
        app2 = make_user(f"app2.tamper.{uuid.uuid4().hex[:6]}@synth.local", "Approver 2", r_approver)
        app3 = make_user(f"app3.tamper.{uuid.uuid4().hex[:6]}@synth.local", "Approver 3", r_approver)

        # 2. Create target paper, encrypt it, create & store fragments
        paper, fragments, master_key = create_simulated_target_paper(db, creator_id=officer.id)
        db_shards = db.query(PaperFragment).filter(PaperFragment.paper_id == paper.id).order_by(PaperFragment.fragment_index).all()
        assert len(db_shards) == 5

        action_attempted = (
            f"Integrity Tampering Simulation on Paper {paper.id}: "
            "1) Modified fragment payload bytes (content tampering). "
            "2) Invalid fragment metadata hash (digest tampering). "
            "3) Full JIT access authorization & reconstruction attempt with tampered storage fragment."
        )
        expected_result = (
            "Integrity validation fails; Reconstruction refused (FragmentIntegrityError); "
            "Decryption refused; JIT access DENIED; ThreatEvent INTEGRITY_FAILURE logged; "
            "Zero plaintext disclosure."
        )

        test_cases_passed = 0
        actual_result_parts = []
        security_decision = "DENY"

        # -------------------------------------------------------------------
        # Test Case 1: Modified Fragment Content (Payload Bit-Flip / Corruption)
        # -------------------------------------------------------------------
        tampered_content_shards = [
            FragmentPayload(
                fragment_index=s.fragment_index,
                fragment_data=(
                    b"CORRUPTED_TAMPERED_PAYLOAD_BYTES_XYZ" if s.fragment_index == 2 else s.fragment_data
                ),
                integrity_hash=s.integrity_hash,  # Kept original hash -> hash mismatch!
                paper_id=s.paper_id,
            )
            for s in db_shards
        ]

        content_tamper_detected = False
        try:
            validate_fragments(tampered_content_shards, expected_paper_id=paper.id, expected_count=5)
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Modified fragment content was NOT detected")
        except (FragmentIntegrityError, FragmentValidationError) as e:
            content_tamper_detected = True
            test_cases_passed += 1
            actual_result_parts.append(f"Case 1 (Content Tampering): BLOCKED ({e})")

        # Refusal of reconstruction on content-tampered shards
        reconstruct_refused_1 = False
        try:
            reconstruct_paper(db, paper.id, fragments=tampered_content_shards)
        except (FragmentIntegrityError, FragmentValidationError):
            reconstruct_refused_1 = True
            test_cases_passed += 1
            actual_result_parts.append("Case 1 (Reconstruction): REFUSED")

        # -------------------------------------------------------------------
        # Test Case 2: Invalid Fragment Integrity Metadata (Tampered Hash)
        # -------------------------------------------------------------------
        tampered_hash_shards = [
            FragmentPayload(
                fragment_index=s.fragment_index,
                fragment_data=s.fragment_data,
                integrity_hash=(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                    if s.fragment_index == 3 else s.integrity_hash
                ),
                paper_id=s.paper_id,
            )
            for s in db_shards
        ]

        hash_tamper_detected = False
        try:
            validate_fragments(tampered_hash_shards, expected_paper_id=paper.id, expected_count=5)
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Tampered fragment hash was NOT detected")
        except (FragmentIntegrityError, FragmentValidationError) as e:
            hash_tamper_detected = True
            test_cases_passed += 1
            actual_result_parts.append(f"Case 2 (Metadata Tampering): BLOCKED ({e})")

        # -------------------------------------------------------------------
        # Test Case 3: End-to-End JIT Access Attempt with Tampered DB Shard
        # -------------------------------------------------------------------
        # Setup approved request & active window
        req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, req.id, app3.id, ApprovalDecision.APPROVED)
        assert req.status == RequestStatus.APPROVED

        create_access_window(
            db=db,
            request_id=req.id,
            start_time=now - timedelta(minutes=10),
            end_time=now + timedelta(minutes=50),
            current_time=now,
        )

        # Modify fragment in database
        original_db_data = db_shards[1].fragment_data
        db_shards[1].fragment_data = b"ADVERSARY_OVERWROTE_SHARD_1_IN_DB"
        db.flush()

        # Attempt JIT access
        auth_res = authorize_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            request_id=req.id,
            current_time=now,
            actor_ip="10.0.0.88",
        )

        jit_blocked = False
        if auth_res.decision == AccessDecision.DENY and not auth_res.is_allowed:
            jit_blocked = True
            test_cases_passed += 1
            actual_result_parts.append(f"Case 3 (JIT Access): DENIED ({auth_res.reason})")
        else:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: JIT Access allowed tampered fragment")

        # Direct execution attempt raises JITAccessDeniedError and returns 0 plaintext
        exec_blocked = False
        try:
            execute_jit_paper_access(
                db=db,
                user_id=officer.id,
                paper_id=paper.id,
                key=master_key,
                request_id=req.id,
                current_time=now,
            )
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: execute_jit_paper_access did not raise on tampered shard")
        except (JITAccessDeniedError, AccessDeniedError):
            exec_blocked = True
            test_cases_passed += 1
            actual_result_parts.append("Case 3 (Direct Execution): REFUSED (0 plaintext returned)")

        # Restore DB fragment for cleanliness
        db_shards[1].fragment_data = original_db_data
        db.flush()

        # -------------------------------------------------------------------
        # Threat & Audit Verification
        # -------------------------------------------------------------------
        threat_events = self._find_recent_threat_events(db, target_id=paper.id)
        threat_types = list(set([t.event_type.value for t in threat_events]))
        threat_event_created = any(t.event_type == ThreatEventType.INTEGRITY_FAILURE for t in threat_events)

        audit_logs = self._find_recent_audit_events(db, target_id=paper.id)
        audit_actions = list(set([l.action for l in audit_logs]))
        audit_event_created = len(audit_logs) > 0 or threat_event_created

        actual_result = " | ".join(actual_result_parts)
        no_disclosure = SYNTHETIC_DEMO_PAYLOAD.decode("utf-8") not in actual_result

        passed = (
            test_cases_passed == 5 and
            threat_event_created and
            no_disclosure and
            (security_decision == "DENY")
        )

        return SimulationResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            timestamp=now_str,
            simulated_actor="Ciphertext Corrupter (tampered shard & metadata injection)",
            target_resource=f"PaperFragment on QuestionPaper:{paper.id}",
            action_attempted=action_attempted,
            expected_result=expected_result,
            actual_result=actual_result,
            security_decision=security_decision,
            audit_event_created=audit_event_created,
            threat_event_created=threat_event_created,
            passed=passed,
            audit_actions_found=audit_actions,
            threat_types_found=threat_types,
            details={
                "test_cases_passed": test_cases_passed,
                "expected_test_cases": 5,
                "content_tamper_detected": content_tamper_detected,
                "hash_tamper_detected": hash_tamper_detected,
                "jit_blocked": jit_blocked,
                "exec_blocked": exec_blocked,
                "no_disclosure": no_disclosure,
            },
        )
