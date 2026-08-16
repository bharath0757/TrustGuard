"""
Scenario 4: Duplicate approval attempt.

Simulates a Key Guardian / Approver attempting to submit multiple approval votes
on the same access request to illegally inflate the quorum count.
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
from security.quorum import DuplicateApprovalError
from attack_simulator.fixtures import create_simulated_target_paper
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario04DuplicateApproval(BaseAttackScenario):
    scenario_id = 4
    scenario_name = "Duplicate approval attempt"
    description = "Approver attempts to cast a second approval vote on the same access request"

    def run(self, db: Session, client=None) -> SimulationResult:
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Setup Users
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

        officer = make_user(f"officer.{uuid.uuid4().hex[:6]}@synth.local", "Officer Alice", r_officer)
        approver = make_user(f"approver.{uuid.uuid4().hex[:6]}@synth.local", "Approver Bob", r_approver)

        paper, fragments, key = create_simulated_target_paper(db, creator_id=officer.id)
        access_req = create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=officer.id,
            required_approvals=3,
            reason="Duplicate vote simulation",
        )

        # First legitimate vote
        vote1, q1 = cast_approval_vote(
            db=db,
            request_id=access_req.id,
            approver_id=approver.id,
            decision=ApprovalDecision.APPROVED,
            reason="First legitimate vote",
        )
        assert vote1.decision == ApprovalDecision.APPROVED

        # Second duplicate vote attempt
        action_attempted = f"Approver Bob ({approver.id}) attempts to cast a second approval vote on Request {access_req.id}"
        expected_result = "Duplicate vote rejected; DuplicateApprovalError raised; Security decision DENY; Threat incident logged"

        actual_result = ""
        security_decision = "DENY"
        blocked = False

        try:
            cast_approval_vote(
                db=db,
                request_id=access_req.id,
                approver_id=approver.id,
                decision=ApprovalDecision.APPROVED,
                reason="Duplicate replay vote attempt",
            )
            actual_result = "ERROR: Duplicate vote was incorrectly accepted"
            security_decision = "ALLOW"
        except DuplicateApprovalError as e:
            blocked = True
            actual_result = f"Duplicate vote blocked: {e}"
            security_decision = "DENY"

        threat_events = self._find_recent_threat_events(db, actor_id=approver.id)
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
            simulated_actor=f"Approver Bob [Role: APPROVER] ({approver.id})",
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
            details={"initial_vote_id": str(vote1.id), "blocked": blocked},
        )
