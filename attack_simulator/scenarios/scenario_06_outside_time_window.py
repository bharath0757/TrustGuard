"""
Scenario 6: Access attempted outside the valid time window.

Simulates an authorized Officer attempting to deliver/authorize a question paper
outside the designated examination window (both BEFORE start_time and AFTER end_time).
"""

from datetime import datetime, timedelta, timezone
import hashlib
import uuid
from sqlalchemy.orm import Session

from database.models.access import ApprovalDecision, RequestStatus
from database.models.user import User, Role, UserRole
from security import (
    authorize_access,
    create_access_request,
    cast_approval_vote,
    create_access_window,
    is_access_window_valid,
    AccessDecision,
    WindowTimeState,
)
from attack_simulator.fixtures import create_simulated_target_paper
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario06OutsideTimeWindow(BaseAttackScenario):
    scenario_id = 6
    scenario_name = "Access attempted outside the valid time window"
    description = "Authorized Officer attempts access before start_time and after end_time"

    def run(self, db: Session, client=None) -> SimulationResult:
        now_str = datetime.now(timezone.utc).isoformat()
        now = datetime.now(timezone.utc)

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
        app1 = make_user(f"app1.{uuid.uuid4().hex[:6]}@synth.local", "Approver 1", r_approver)
        app2 = make_user(f"app2.{uuid.uuid4().hex[:6]}@synth.local", "Approver 2", r_approver)

        paper, fragments, key = create_simulated_target_paper(db, creator_id=officer.id)
        access_req = create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=officer.id,
            required_approvals=2,
            reason="Time-lock simulation",
        )
        cast_approval_vote(db, access_req.id, app1.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, access_req.id, app2.id, ApprovalDecision.APPROVED)
        assert access_req.status == RequestStatus.APPROVED

        # Setup Future Window (opens in +60 min)
        future_window = create_access_window(
            db=db,
            request_id=access_req.id,
            start_time=now + timedelta(minutes=60),
            end_time=now + timedelta(minutes=180),
        )

        action_attempted = f"Officer Alice ({officer.id}) attempts authorize_access BEFORE window opens (current: {now.isoformat()}, start: {future_window.start_time.isoformat()})"
        expected_result = "Access Denied (BEFORE_WINDOW); Security decision DENY; Threat incident logged"

        # Attempt 1: Before window opens
        auth_before = authorize_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            request_id=access_req.id,
            current_time=now,
            actor_ip="10.0.0.99",
        )

        # Attempt 2: After window closes
        auth_after = authorize_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            request_id=access_req.id,
            current_time=now + timedelta(minutes=200),
            actor_ip="10.0.0.99",
        )

        actual_result = (
            f"Before Window: {auth_before.decision.value} ({auth_before.reason}) | "
            f"After Window: {auth_after.decision.value} ({auth_after.reason})"
        )
        security_decision = "DENY" if (auth_before.decision == AccessDecision.DENY and auth_after.decision == AccessDecision.DENY) else "ALLOW"

        threat_events = self._find_recent_threat_events(db, actor_id=officer.id)
        threat_types = [t.event_type.value for t in threat_events]
        threat_event_created = len(threat_events) > 0

        audit_logs = self._find_recent_audit_events(db, target_id=paper.id)
        audit_actions = [l.action for l in audit_logs]
        audit_event_created = len(audit_logs) > 0 or threat_event_created

        passed = (
            auth_before.decision == AccessDecision.DENY and
            auth_after.decision == AccessDecision.DENY and
            not auth_before.is_allowed and
            not auth_after.is_allowed and
            security_decision == "DENY"
        )

        return SimulationResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            timestamp=now_str,
            simulated_actor=f"Officer Alice [Role: OFFICER] ({officer.id})",
            target_resource=f"AccessWindow:{future_window.id} for QuestionPaper:{paper.id}",
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
                "before_decision": auth_before.decision.value,
                "after_decision": auth_after.decision.value,
            },
        )
