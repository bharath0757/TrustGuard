"""
Scenario 3: Controlled Insider Misuse — Access Without Required Quorum.

SCENARIO DESCRIPTION:
A valid authenticated user (e.g. Exam Officer) attempts to obtain or reconstruct
the protected paper without satisfying the required quorum.

IMPORTANT:
The user is NOT an external attacker.
The user has valid credentials and active roles.
The security decision must still be DENY.

DEMONSTRATES:
Valid identity + Valid account + Insufficient authorization/quorum = DENY

TEST CASES COVERED:
1. Valid officer, 0 approvals ($k=3$).
2. Valid officer, 1/3 approvals.
3. Valid officer, 2/3 approvals.
4. Attempt by one officer/approver to approve multiple times (duplicate vote).
5. Valid officer tries to bypass the approval API (e.g. direct window creation / execution).
6. Valid user requests direct decryption without quorum.

EXPECTED:
- No reconstruction
- No decryption
- No paper disclosure (0 plaintext leakage)
- Audit event created
- Security event created where appropriate (INVALID_QUORUM)
"""

from datetime import datetime, timedelta, timezone
import hashlib
import uuid
from sqlalchemy.orm import Session

from database.models.access import ApprovalDecision, RequestStatus, RequestType
from database.models.audit import ThreatEventType, ThreatSeverity
from database.models.paper import PaperStatus
from database.models.user import User, Role, UserRole
from security import (
    authorize_access,
    check_quorum,
    AccessDecision,
    create_access_request,
    cast_approval_vote,
    create_access_window,
    execute_jit_paper_access,
)
from security.quorum import (
    DuplicateApprovalError,
    QuorumValidationError,
    AccessDeniedError,
)
from security.access_window import WindowScheduleError, JITAccessDeniedError
from attack_simulator.fixtures import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario03NoQuorum(BaseAttackScenario):
    scenario_id = 3
    scenario_name = "Valid user attempts access without required quorum"
    description = "Authenticated Officer attempts access and decryption without required multi-party quorum"

    def run(self, db: Session, client=None) -> SimulationResult:
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Setup Valid Officer and Approvers
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

        valid_officer = make_user(f"officer.{uuid.uuid4().hex[:6]}@synth.local", "Officer Alice", r_officer)
        approver_1 = make_user(f"approver.1.{uuid.uuid4().hex[:6]}@synth.local", "Approver Bob", r_approver)
        approver_2 = make_user(f"approver.2.{uuid.uuid4().hex[:6]}@synth.local", "Approver Charlie", r_approver)

        # 2. Setup Target Paper
        paper, fragments, master_key = create_simulated_target_paper(db, creator_id=valid_officer.id)
        assert paper.status in (PaperStatus.PROTECTED, PaperStatus.FRAGMENTED)

        action_attempted = (
            f"Insider Misuse Progression by Officer {valid_officer.id}: "
            "1) Access at 0/3 approvals. "
            "2) Access at 1/3 approvals. "
            "3) Access at 2/3 approvals. "
            "4) Duplicate vote attempt by Approver 1. "
            "5) Bypass approval API / direct access window creation. "
            "6) Direct unauthorized reconstruction/decryption."
        )
        expected_result = (
            "All 6 insider misuse test cases rejected (DENY / QuorumValidationError / DuplicateApprovalError / WindowScheduleError); "
            "No reconstruction; No decryption; Zero paper disclosure; Audit and INVALID_QUORUM threat logged"
        )

        test_cases_passed = 0
        actual_result_parts = []
        security_decision = "DENY"

        # -------------------------------------------------------------------
        # Test Case 1: Valid officer, 0 approvals (k=3)
        # -------------------------------------------------------------------
        req_0 = create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=valid_officer.id,
            required_approvals=3,
            reason="Insider attempt with 0 approvals",
        )
        auth_0 = authorize_access(
            db=db,
            user_id=valid_officer.id,
            paper_id=paper.id,
            request_id=req_0.id,
            actor_ip="10.0.0.10",
        )
        if auth_0.decision == AccessDecision.DENY and not auth_0.is_allowed:
            test_cases_passed += 1
            actual_result_parts.append(f"Case 1 (0/3 approvals): DENIED ({auth_0.reason})")
        else:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Case 1 (0/3 approvals) was permitted")

        # -------------------------------------------------------------------
        # Test Case 2: Valid officer, 1/3 approvals
        # -------------------------------------------------------------------
        cast_approval_vote(db, req_0.id, approver_1.id, ApprovalDecision.APPROVED)
        auth_1 = authorize_access(
            db=db,
            user_id=valid_officer.id,
            paper_id=paper.id,
            request_id=req_0.id,
            actor_ip="10.0.0.11",
        )
        if auth_1.decision == AccessDecision.DENY and not auth_1.is_allowed:
            test_cases_passed += 1
            actual_result_parts.append(f"Case 2 (1/3 approvals): DENIED ({auth_1.reason})")
        else:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Case 2 (1/3 approvals) was permitted")

        # -------------------------------------------------------------------
        # Test Case 3: Valid officer, 2/3 approvals
        # -------------------------------------------------------------------
        cast_approval_vote(db, req_0.id, approver_2.id, ApprovalDecision.APPROVED)
        auth_2 = authorize_access(
            db=db,
            user_id=valid_officer.id,
            paper_id=paper.id,
            request_id=req_0.id,
            actor_ip="10.0.0.12",
        )
        if auth_2.decision == AccessDecision.DENY and not auth_2.is_allowed:
            test_cases_passed += 1
            actual_result_parts.append(f"Case 3 (2/3 approvals): DENIED ({auth_2.reason})")
        else:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Case 3 (2/3 approvals) was permitted")

        # -------------------------------------------------------------------
        # Test Case 4: Attempt by one officer/approver to approve multiple times
        # -------------------------------------------------------------------
        duplicate_blocked = False
        try:
            cast_approval_vote(
                db=db,
                request_id=req_0.id,
                approver_id=approver_1.id,  # Already voted in Case 2!
                decision=ApprovalDecision.APPROVED,
            )
        except DuplicateApprovalError as e:
            duplicate_blocked = True
            test_cases_passed += 1
            actual_result_parts.append(f"Case 4 (Duplicate vote): BLOCKED ({e})")

        if not duplicate_blocked:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Case 4 duplicate vote was accepted")

        # -------------------------------------------------------------------
        # Test Case 5: Valid officer tries to bypass the approval API
        # -------------------------------------------------------------------
        bypass_blocked = False
        try:
            # Attempting to create an access window on an unapproved request (req_0 is still PENDING at 2/3)
            create_access_window(
                db=db,
                request_id=req_0.id,
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        except WindowScheduleError as e:
            bypass_blocked = True
            test_cases_passed += 1
            actual_result_parts.append(f"Case 5 (Bypass approval API): BLOCKED ({e})")

        if not bypass_blocked:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Case 5 window creation bypass was permitted")

        # -------------------------------------------------------------------
        # Test Case 6: Valid user requests direct decryption without quorum
        # -------------------------------------------------------------------
        direct_decrypt_blocked = False
        try:
            execute_jit_paper_access(
                db=db,
                user_id=valid_officer.id,
                paper_id=paper.id,
                key=master_key,
                request_id=req_0.id,
                actor_ip="10.0.0.13",
            )
        except (JITAccessDeniedError, AccessDeniedError) as e:
            direct_decrypt_blocked = True
            test_cases_passed += 1
            actual_result_parts.append(f"Case 6 (Direct decryption without quorum): BLOCKED ({e})")

        if not direct_decrypt_blocked:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Case 6 direct decryption without quorum was permitted")

        # -------------------------------------------------------------------
        # Invariants & Threat Logging Verification
        # -------------------------------------------------------------------
        db.refresh(paper)
        paper_protected = paper.status in (PaperStatus.PROTECTED, PaperStatus.FRAGMENTED, PaperStatus.AWAITING_APPROVAL)

        threat_events = self._find_recent_threat_events(db, actor_id=valid_officer.id)
        threat_types = list(set([t.event_type.value for t in threat_events]))
        threat_event_created = len(threat_events) > 0

        audit_logs = self._find_recent_audit_events(db, target_id=paper.id)
        audit_actions = list(set([l.action for l in audit_logs]))
        audit_event_created = len(audit_logs) > 0 or threat_event_created

        # Verify zero content disclosure
        actual_result = " | ".join(actual_result_parts)
        no_disclosure = SYNTHETIC_DEMO_PAYLOAD.decode("utf-8") not in actual_result

        passed = (
            test_cases_passed == 6 and
            paper_protected and
            no_disclosure and
            (security_decision == "DENY")
        )

        return SimulationResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            timestamp=now_str,
            simulated_actor=f"Valid Officer Alice [Valid Credentials, Role: OFFICER] ({valid_officer.id})",
            target_resource=f"AccessRequest:{req_0.id} for QuestionPaper:{paper.id}",
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
                "expected_test_cases": 6,
                "request_status": req_0.status.value,
                "paper_status": paper.status.value,
                "no_disclosure": no_disclosure,
            },
        )
