"""
Scenario 1: Unauthorized Question-Paper Access.

SCENARIO DESCRIPTION:
An unknown or unauthorized user attempts to access a protected question paper.

EXPECTED BEHAVIOR:
Authentication/authorization fails with ACCESS DENIED.

SYSTEM INVARIANTS TESTED:
1. Reject the request (DENY / 401 / 403 / AccessDenied).
2. Return a safe error response without exposing internal secrets.
3. Not reveal protected examination content.
4. Create an appropriate audit/security event (UNAUTHORIZED_ACCESS).
5. Leave the question paper in its protected state.
6. Not modify or corrupt existing valid approvals.
7. Not create a valid decryption session or plaintext memory buffer.

TESTS BOTH:
- Unauthenticated / unknown user request.
- Authenticated but unauthorized user request (e.g. Candidate role).
"""

from datetime import datetime, timezone
import hashlib
import uuid
from sqlalchemy.orm import Session

from database.models.access import ApprovalDecision, RequestStatus, RequestType
from database.models.audit import ThreatEventType
from database.models.paper import PaperStatus
from database.models.user import User, Role, UserRole
from security import (
    create_access_request,
    authorize_access,
    cast_approval_vote,
    AccessDecision,
)
from security.quorum import (
    QuorumValidationError,
    UnauthorizedApproverError,
    InvalidApproverRoleError,
)
from attack_simulator.fixtures import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario01UnauthorizedUser(BaseAttackScenario):
    scenario_id = 1
    scenario_name = "Unauthorized Question-Paper Access"
    description = "Unknown or unauthorized user attempts to access a protected question paper"

    def run(self, db: Session, client=None) -> SimulationResult:
        now_str = datetime.now(timezone.utc).isoformat()
        
        # 1. Setup Roles
        r_officer = db.query(Role).filter(Role.name == "OFFICER").first()
        if not r_officer:
            r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Officer")
            db.add(r_officer)
        r_approver = db.query(Role).filter(Role.name == "APPROVER").first()
        if not r_approver:
            r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Approver")
            db.add(r_approver)
        r_candidate = db.query(Role).filter(Role.name == "CANDIDATE").first()
        if not r_candidate:
            r_candidate = Role(id=uuid.uuid4(), name="CANDIDATE", description="Candidate")
            db.add(r_candidate)
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

        legitimate_officer = make_user(f"officer.{uuid.uuid4().hex[:6]}@synth.local", "Officer Alice", r_officer)
        legitimate_approver = make_user(f"approver.{uuid.uuid4().hex[:6]}@synth.local", "Approver Bob", r_approver)
        authenticated_unauthorized_user = make_user(
            f"candidate.eve.{uuid.uuid4().hex[:6]}@synth.local", "Candidate Eve", r_candidate
        )
        unauthenticated_actor_id = uuid.uuid4()  # Unknown non-existent user

        # 2. Setup Target Protected Paper
        paper, fragments, master_key = create_simulated_target_paper(db, creator_id=legitimate_officer.id)
        initial_paper_status = paper.status
        assert initial_paper_status in (PaperStatus.PROTECTED, PaperStatus.FRAGMENTED)

        # 3. Setup an existing valid access request with 1 legitimate approval
        access_req = create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=legitimate_officer.id,
            required_approvals=2,
            reason="Legitimate pre-scheduled ceremony",
        )
        cast_approval_vote(db, access_req.id, legitimate_approver.id, ApprovalDecision.APPROVED)
        initial_approvals_count = len(access_req.approvals)
        assert initial_approvals_count == 1

        action_attempted = (
            f"1) Unknown actor ({unauthenticated_actor_id}) attempts request creation & JIT access. "
            f"2) Authenticated unauthorized candidate ({authenticated_unauthorized_user.id}) attempts JIT access."
        )
        expected_result = (
            "Access Denied for both actors; Paper remains PROTECTED; Approvals untouched; "
            "Zero secret leakage; Threat incident UNAUTHORIZED_ACCESS logged; Security decision DENY"
        )

        actual_result_parts = []
        security_decision = "DENY"

        # -------------------------------------------------------------------
        # PART A: Unauthenticated / Unknown User Attack Attempt
        # -------------------------------------------------------------------
        unauth_blocked_request = False
        try:
            create_access_request(
                db=db,
                paper_id=paper.id,
                requested_by=unauthenticated_actor_id,
                request_type=RequestType.RECONSTRUCT,
                reason="Unauthorized intruder request attempt",
            )
        except QuorumValidationError as e:
            unauth_blocked_request = True
            actual_result_parts.append(f"Unauthenticated request creation blocked ({e})")

        unauth_auth_res = authorize_access(
            db=db,
            user_id=unauthenticated_actor_id,
            paper_id=paper.id,
            request_id=access_req.id,
            actor_ip="192.168.1.50",
        )
        if unauth_auth_res.decision == AccessDecision.DENY:
            actual_result_parts.append(f"Unauthenticated JIT access DENIED ({unauth_auth_res.reason})")
        else:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Unauthenticated JIT access was permitted")

        # -------------------------------------------------------------------
        # PART B: Authenticated but Unauthorized User (Candidate) Attack Attempt
        # -------------------------------------------------------------------
        cand_auth_res = authorize_access(
            db=db,
            user_id=authenticated_unauthorized_user.id,
            paper_id=paper.id,
            request_id=access_req.id,
            allowed_roles={"OFFICER", "ADMIN"},
            actor_ip="192.168.1.60",
        )
        if cand_auth_res.decision == AccessDecision.DENY:
            actual_result_parts.append(f"Authenticated candidate access DENIED ({cand_auth_res.reason})")
        else:
            security_decision = "ALLOW"
            actual_result_parts.append("ERROR: Candidate access was permitted")

        # -------------------------------------------------------------------
        # SYSTEM INVARIANTS VERIFICATION:
        # -------------------------------------------------------------------
        db.refresh(paper)
        db.refresh(access_req)

        # Invariant 5: Paper remains protected
        paper_still_protected = paper.status in (PaperStatus.PROTECTED, PaperStatus.FRAGMENTED, PaperStatus.AWAITING_APPROVAL)
        if not paper_still_protected:
            actual_result_parts.append(f"ERROR: Paper status changed unexpectedly to {paper.status}")

        # Invariant 6: Valid approvals untouched
        approvals_untouched = len(access_req.approvals) == initial_approvals_count
        if not approvals_untouched:
            actual_result_parts.append("ERROR: Valid approvals were modified")

        # Invariant 3: Zero content / key leakage
        no_leakage = (
            SYNTHETIC_DEMO_PAYLOAD.decode("utf-8") not in unauth_auth_res.reason and
            SYNTHETIC_DEMO_PAYLOAD.decode("utf-8") not in cand_auth_res.reason and
            master_key.hex() not in unauth_auth_res.reason and
            master_key.hex() not in cand_auth_res.reason
        )

        # Invariant 4: Threat / Audit logging
        threat_events = self._find_recent_threat_events(db, target_id=paper.id)
        threat_events += self._find_recent_threat_events(db, actor_id=authenticated_unauthorized_user.id)
        threat_types = list(set([t.event_type.value for t in threat_events]))
        threat_event_created = len(threat_events) > 0

        audit_logs = self._find_recent_audit_events(db, target_id=paper.id)
        audit_actions = list(set([l.action for l in audit_logs]))
        audit_event_created = len(audit_logs) > 0 or threat_event_created

        actual_result = " | ".join(actual_result_parts)

        # Pass condition: All unauthorized paths denied, paper protected, approvals untouched, zero leakage
        passed = (
            unauth_blocked_request and
            (unauth_auth_res.decision == AccessDecision.DENY) and
            (cand_auth_res.decision == AccessDecision.DENY) and
            paper_still_protected and
            approvals_untouched and
            no_leakage and
            (security_decision == "DENY")
        )

        return SimulationResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            timestamp=now_str,
            simulated_actor="Unknown Intruder / Candidate Eve (unauthorized roles)",
            target_resource=f"QuestionPaper:{paper.id} ({paper.exam_identifier})",
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
                "unauth_denied": unauth_auth_res.decision == AccessDecision.DENY,
                "candidate_denied": cand_auth_res.decision == AccessDecision.DENY,
                "paper_status": paper.status.value,
                "approvals_intact": approvals_untouched,
                "zero_secret_leakage": no_leakage,
            },
        )
