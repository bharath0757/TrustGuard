"""
Scenario 5: Unauthorized person attempts to approve.

Simulates a user holding only a CANDIDATE role (or unprivileged user)
attempting to cast an approval vote in the multi-party quorum ceremony.
"""

from datetime import datetime, timezone
import hashlib
import uuid
from sqlalchemy.orm import Session

from database.models.access import ApprovalDecision
from database.models.user import User, Role, UserRole
from security import (
    create_access_request,
    cast_approval_vote,
)
from security.quorum import InvalidApproverRoleError, UnauthorizedApproverError
from attack_simulator.fixtures import create_simulated_target_paper
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario05UnauthorizedApprover(BaseAttackScenario):
    scenario_id = 5
    scenario_name = "Unauthorized person attempts to approve"
    description = "Candidate user attempts to submit an approval vote in the quorum consensus ceremony"

    def run(self, db: Session, client=None) -> SimulationResult:
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Setup Roles & Users
        r_officer = db.query(Role).filter(Role.name == "OFFICER").first()
        if not r_officer:
            r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
            db.add(r_officer)
        r_candidate = db.query(Role).filter(Role.name == "CANDIDATE").first()
        if not r_candidate:
            r_candidate = Role(id=uuid.uuid4(), name="CANDIDATE", description="Exam Candidate")
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

        officer = make_user(f"officer.{uuid.uuid4().hex[:6]}@synth.local", "Officer Alice", r_officer)
        candidate = make_user(f"candidate.{uuid.uuid4().hex[:6]}@synth.local", "Candidate Mallory", r_candidate)

        paper, fragments, key = create_simulated_target_paper(db, creator_id=officer.id)
        access_req = create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=officer.id,
            required_approvals=3,
            reason="Quorum approval ceremony",
        )

        action_attempted = f"Candidate Mallory ({candidate.id}) attempts to cast approval vote on Request {access_req.id}"
        expected_result = "Approval rejected; InvalidApproverRoleError raised; Security decision DENY; Threat incident logged"

        actual_result = ""
        security_decision = "DENY"
        blocked = False

        try:
            cast_approval_vote(
                db=db,
                request_id=access_req.id,
                approver_id=candidate.id,
                decision=ApprovalDecision.APPROVED,
                reason="Unauthorized candidate vote attempt",
                allowed_roles={"APPROVER", "OFFICER", "ADMIN"},
            )
            actual_result = "ERROR: Candidate vote was incorrectly accepted"
            security_decision = "ALLOW"
        except (InvalidApproverRoleError, UnauthorizedApproverError) as e:
            blocked = True
            actual_result = f"Approval vote blocked: {e}"
            security_decision = "DENY"

        threat_events = self._find_recent_threat_events(db, actor_id=candidate.id)
        threat_types = [t.event_type.value for t in threat_events]
        threat_event_created = len(threat_events) > 0

        audit_logs = self._find_recent_audit_events(db, target_id=access_req.id)
        audit_actions = [l.action for l in audit_logs]
        audit_event_created = len(audit_logs) > 0 or threat_event_created

        passed = blocked and (security_decision == "DENY")

        return SimulationResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            timestamp=now_str,
            simulated_actor=f"Candidate Mallory [Role: CANDIDATE] ({candidate.id})",
            target_resource=f"AccessRequest:{access_req.id}",
            action_attempted=action_attempted,
            expected_result=expected_result,
            actual_result=actual_result,
            security_decision=security_decision,
            audit_event_created=audit_event_created,
            threat_event_created=threat_event_created,
            passed=passed,
            audit_actions_found=audit_actions,
            threat_types_found=threat_types,
            details={"candidate_role": "CANDIDATE", "blocked": blocked},
        )
