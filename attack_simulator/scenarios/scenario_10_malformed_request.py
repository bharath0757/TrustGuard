"""
Scenario 10: Malformed/invalid authorization request.

Simulates an adversary or corrupted client sending malformed parameters:
- Empty justification reason
- Invalid / negative quorum count (required_approvals <= 0)
- Inverted access window timeline (end_time < start_time)
"""

from datetime import datetime, timedelta, timezone
import hashlib
import uuid
from sqlalchemy.orm import Session

from database.models.access import RequestType, ApprovalDecision
from database.models.user import User, Role, UserRole
from security import (
    create_access_request,
    create_access_window,
    cast_approval_vote,
)
from security.quorum import QuorumValidationError
from security.access_window import WindowScheduleError
from attack_simulator.fixtures import create_simulated_target_paper
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario10MalformedRequest(BaseAttackScenario):
    scenario_id = 10
    scenario_name = "Malformed/invalid authorization request"
    description = "Submitting schema-violating, empty-reason, zero-quorum, or inverted-time window parameters"

    def run(self, db: Session, client=None) -> SimulationResult:
        now_str = datetime.now(timezone.utc).isoformat()
        now = datetime.now(timezone.utc)

        # 1. Setup User & Target
        r_officer = db.query(Role).filter(Role.name == "OFFICER").first()
        if not r_officer:
            r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
            db.add(r_officer)
            db.flush()

        officer = User(
            id=uuid.uuid4(),
            email=f"officer.malformed.{uuid.uuid4().hex[:6]}@synth.local",
            password_hash=hashlib.sha256(b"Pass2026!").hexdigest(),
            full_name="Officer Malformed",
            is_active=True,
        )
        db.add(officer)
        db.flush()
        db.add(UserRole(user_id=officer.id, role_id=r_officer.id))
        db.flush()

        paper, fragments, key = create_simulated_target_paper(db, creator_id=officer.id)

        action_attempted = "Submit malformed access request (zero quorum threshold & inverted time window)"
        expected_result = "Blocked with QuorumValidationError / WindowScheduleError; Security decision DENY"

        actual_result = ""
        security_decision = "DENY"
        blocked_count = 0

        # Attempt 1: required_approvals = 0
        try:
            create_access_request(
                db=db,
                paper_id=paper.id,
                requested_by=officer.id,
                required_approvals=0,
                reason="Invalid zero quorum attempt",
            )
        except QuorumValidationError as e:
            blocked_count += 1
            actual_result += f"Zero quorum blocked: {e}. "

        # Attempt 2: empty reason string
        try:
            create_access_request(
                db=db,
                paper_id=paper.id,
                requested_by=officer.id,
                required_approvals=2,
                reason="   ",
            )
        except QuorumValidationError as e:
            blocked_count += 1
            actual_result += f"Empty reason blocked: {e}. "

        # Attempt 3: inverted window (end_time < start_time) on a valid request
        valid_req = create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=officer.id,
            required_approvals=1,
            reason="Legitimate setup for window timing test",
        )
        cast_approval_vote(db, valid_req.id, officer.id, ApprovalDecision.APPROVED, allow_self_approval=True)

        try:
            create_access_window(
                db=db,
                request_id=valid_req.id,
                start_time=now + timedelta(hours=2),
                end_time=now + timedelta(hours=1),  # end_time before start_time!
            )
        except WindowScheduleError as e:
            blocked_count += 1
            actual_result += f"Inverted window timing blocked: {e}. "

        passed = (blocked_count == 3) and (security_decision == "DENY")

        threat_events = self._find_recent_threat_events(db, actor_id=officer.id)
        threat_types = [t.event_type.value for t in threat_events]
        threat_event_created = len(threat_events) > 0

        audit_logs = self._find_recent_audit_events(db, target_id=paper.id)
        audit_actions = [l.action for l in audit_logs]
        audit_event_created = len(audit_logs) > 0 or threat_event_created

        return SimulationResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            timestamp=now_str,
            simulated_actor=f"Malformed Request Client ({officer.id})",
            target_resource=f"AccessRequest & Window for QuestionPaper:{paper.id}",
            action_attempted=action_attempted,
            expected_result=expected_result,
            actual_result=actual_result,
            security_decision=security_decision,
            audit_event_created=audit_event_created,
            threat_event_created=threat_event_created,
            passed=passed,
            audit_actions_found=audit_actions,
            threat_types_found=threat_types,
            details={"malformed_tests_blocked": blocked_count, "expected_blocked": 3},
        )
