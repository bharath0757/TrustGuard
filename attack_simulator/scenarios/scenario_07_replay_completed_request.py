"""
Scenario 7: Controlled Replay Simulation.

SCENARIO DESCRIPTION:
A legitimate access request has already been completed or expired.
An attacker attempts to reuse the previous request/authorization information.

STEPS EXECUTED:
1. Create and authorize a legitimate question paper access session.
2. Complete the session normally (request closed/expired, window closed).
3. Attempt replay of completed request (Test Case 1).
4. Attempt replay of explicitly expired request (Test Case 2).
5. Attempt replay/reuse of old approvals for a new request (Test Case 3).
6. Attempt reuse of wiped memory buffer / stale context (Test Case 4).

EXPECTED BEHAVIOR:
- Replay is strictly rejected (Decision: DENY).
- No decryption.
- No unauthorized paper access (0 plaintext disclosed).
- Audit / Threat event recorded (REPLAY_ATTEMPT).
- Original request remains closed/expired.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import uuid
from sqlalchemy.orm import Session

from database.models.access import ApprovalDecision, RequestStatus, WindowStatus
from database.models.audit import ThreatEventType, ThreatSeverity
from database.models.paper import PaperStatus
from database.models.user import User, Role, UserRole
from security import (
    authorize_access,
    create_access_request,
    cast_approval_vote,
    create_access_window,
    complete_access,
    expire_access_request,
    check_quorum,
    execute_jit_paper_access,
    AccessDecision,
)
from security.quorum import AccessDeniedError
from security.access_window import JITAccessDeniedError
from security.audit import SecureDecryptedBuffer
from attack_simulator.fixtures import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario07ReplayCompletedRequest(BaseAttackScenario):
    scenario_id = 7
    scenario_name = "Replay of a completed access request"
    description = "Actor attempts to reuse an expired/completed AccessRequest or authorization context"

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

        officer = make_user(f"officer.rep.{uuid.uuid4().hex[:6]}@synth.local", "Officer Alice", r_officer)
        app1 = make_user(f"app1.rep.{uuid.uuid4().hex[:6]}@synth.local", "Approver 1", r_approver)
        app2 = make_user(f"app2.rep.{uuid.uuid4().hex[:6]}@synth.local", "Approver 2", r_approver)

        paper, fragments, master_key = create_simulated_target_paper(db, creator_id=officer.id)

        action_attempted = (
            f"Replay Simulation on Paper {paper.id}: "
            "1) Completed request reused. "
            "2) Expired request reused. "
            "3) Old approval reused for a new request. "
            "4) Wiped buffer / stale context reuse."
        )
        expected_result = (
            "All replay attempts rejected (DENY); No decryption; Threat event REPLAY_ATTEMPT logged; "
            "Original request remains closed/expired; Zero plaintext disclosure"
        )

        test_cases_passed = 0
        actual_result_parts = []
        security_decision = "DENY"

        # -------------------------------------------------------------------
        # Test Case 1: Completed Request Reused
        # -------------------------------------------------------------------
        req_completed = create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=officer.id,
            required_approvals=2,
            reason="Legitimate first access",
        )
        cast_approval_vote(db, req_completed.id, app1.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, req_completed.id, app2.id, ApprovalDecision.APPROVED)
        window = create_access_window(
            db=db,
            request_id=req_completed.id,
            start_time=now - timedelta(minutes=5),
            end_time=now + timedelta(minutes=60),
            current_time=now,
        )

        # Legitimate first access
        first_auth = authorize_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            request_id=req_completed.id,
            current_time=now,
        )
        assert first_auth.decision == AccessDecision.ALLOW

        # Complete session normally
        complete_access(
            db=db,
            paper_id=paper.id,
            request_id=req_completed.id,
            actor_id=officer.id,
            reason="Examination concluded",
        )
        assert req_completed.status == RequestStatus.EXPIRED
        assert window.status == WindowStatus.CLOSED

        # Replay attempt: Re-authorize with completed request
        replay_auth = authorize_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            request_id=req_completed.id,
            current_time=now,
            actor_ip="10.0.0.77",
        )

        if replay_auth.decision == AccessDecision.DENY and not replay_auth.is_allowed:
            test_cases_passed += 1
            actual_result_parts.append(f"Case 1 (Completed Request Replay): DENIED ({replay_auth.reason})")
        else:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Completed request replay was allowed")

        # Direct execution attempt raises error
        exec_blocked = False
        try:
            execute_jit_paper_access(
                db=db,
                user_id=officer.id,
                paper_id=paper.id,
                key=master_key,
                request_id=req_completed.id,
                current_time=now,
            )
        except (JITAccessDeniedError, AccessDeniedError):
            exec_blocked = True
            test_cases_passed += 1
            actual_result_parts.append("Case 1 (Execution): REFUSED (0 plaintext)")

        if not exec_blocked:
            security_decision = "ALLOW"

        # -------------------------------------------------------------------
        # Test Case 2: Expired Request Reused
        # -------------------------------------------------------------------
        req_expired = create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=officer.id,
            required_approvals=2,
            reason="Request destined to expire",
        )
        expire_access_request(db, req_expired.id, reason="Timed out before quorum")
        assert req_expired.status == RequestStatus.EXPIRED

        expired_replay_auth = authorize_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            request_id=req_expired.id,
            current_time=now,
        )
        if expired_replay_auth.decision == AccessDecision.DENY and not expired_replay_auth.is_allowed:
            test_cases_passed += 1
            actual_result_parts.append(f"Case 2 (Expired Request Replay): DENIED ({expired_replay_auth.reason})")
        else:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Expired request replay was allowed")

        # -------------------------------------------------------------------
        # Test Case 3: Old Approvals Reused for a New Request
        # -------------------------------------------------------------------
        req_new = create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=officer.id,
            required_approvals=2,
            reason="Fresh second request",
        )
        # Verify fresh request starts at 0 approvals and does NOT inherit old approvals
        q_new = check_quorum(db, req_new.id)
        if q_new.approved_count == 0 and not q_new.is_authorized and req_new.status == RequestStatus.PENDING:
            test_cases_passed += 1
            actual_result_parts.append("Case 3 (Fresh Request Isolation): ENFORCED (0/2 approvals)")
        else:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: New request inherited old approvals")

        # -------------------------------------------------------------------
        # Test Case 4: Wiped Memory Buffer / Stale Context Reuse
        # -------------------------------------------------------------------
        with SecureDecryptedBuffer(SYNTHETIC_DEMO_PAYLOAD) as sec_buf:
            assert sec_buf.get_data() == SYNTHETIC_DEMO_PAYLOAD

        # Outside context manager, buffer is wiped and throws RuntimeError
        buffer_reused = False
        try:
            _ = sec_buf.get_data()
            buffer_reused = True
        except RuntimeError:
            test_cases_passed += 1
            actual_result_parts.append("Case 4 (Wiped Buffer Access): PREVENTED (RuntimeError)")

        if buffer_reused:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Wiped buffer was accessible")

        # -------------------------------------------------------------------
        # Verify Request Remains Closed & Threat Logged
        # -------------------------------------------------------------------
        db.refresh(req_completed)
        assert req_completed.status == RequestStatus.EXPIRED

        threat_events = self._find_recent_threat_events(db, target_id=paper.id)
        threat_types = list(set([t.event_type.value for t in threat_events]))
        threat_event_created = any(t.event_type == ThreatEventType.REPLAY_ATTEMPT for t in threat_events)

        audit_logs = self._find_recent_audit_events(db, target_id=paper.id)
        audit_actions = list(set([l.action for l in audit_logs]))
        audit_event_created = len(audit_logs) > 0 or threat_event_created

        actual_result = " | ".join(actual_result_parts)
        no_disclosure = SYNTHETIC_DEMO_PAYLOAD.decode("utf-8") not in actual_result

        passed = (
            test_cases_passed == 5 and
            threat_event_created and
            req_completed.status == RequestStatus.EXPIRED and
            no_disclosure and
            (security_decision == "DENY")
        )

        return SimulationResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            timestamp=now_str,
            simulated_actor=f"Replay Attacker using Stale Context ({officer.id})",
            target_resource=f"AccessRequest:{req_completed.id} on QuestionPaper:{paper.id}",
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
                "completed_req_status": req_completed.status.value,
                "threat_event_created": threat_event_created,
                "no_disclosure": no_disclosure,
            },
        )
