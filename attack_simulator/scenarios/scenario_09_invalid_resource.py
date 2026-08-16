"""
Scenario 9: Invalid paper ID/resource access attempt.

Simulates an attacker requesting or probing an invalid/non-existent QuestionPaper UUID.
"""

from datetime import datetime, timezone
import hashlib
import uuid
from sqlalchemy.orm import Session

from database.models.access import RequestType
from database.models.user import User, Role, UserRole
from security import (
    create_access_request,
    authorize_access,
    AccessDecision,
)
from security.quorum import QuorumValidationError
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario09InvalidResource(BaseAttackScenario):
    scenario_id = 9
    scenario_name = "Invalid paper ID/resource access attempt"
    description = "Probing non-existent QuestionPaper UUID during access request and authorization"

    def run(self, db: Session, client=None) -> SimulationResult:
        now_str = datetime.now(timezone.utc).isoformat()
        fake_paper_id = uuid.UUID("00000000-0000-0000-0000-000000000000")

        # 1. Setup Valid Officer User
        r_officer = db.query(Role).filter(Role.name == "OFFICER").first()
        if not r_officer:
            r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
            db.add(r_officer)
            db.flush()

        officer = User(
            id=uuid.uuid4(),
            email=f"officer.probe.{uuid.uuid4().hex[:6]}@synth.local",
            password_hash=hashlib.sha256(b"Pass2026!").hexdigest(),
            full_name="Officer Probe",
            is_active=True,
        )
        db.add(officer)
        db.flush()
        db.add(UserRole(user_id=officer.id, role_id=r_officer.id))
        db.flush()

        action_attempted = f"Create AccessRequest and authorize_access targeting non-existent QuestionPaper {fake_paper_id}"
        expected_result = "Blocked with QuorumValidationError; Decision DENY; Zero secret leakage; Threat incident logged"

        actual_result = ""
        security_decision = "DENY"
        blocked_on_request = False

        # Attempt 1: create_access_request on fake paper ID
        try:
            create_access_request(
                db=db,
                paper_id=fake_paper_id,
                requested_by=officer.id,
                request_type=RequestType.RECONSTRUCT,
                reason="Probing non-existent resource",
            )
        except QuorumValidationError as e:
            blocked_on_request = True
            actual_result += f"create_access_request rejected: {e}. "

        # Attempt 2: direct authorization evaluation on fake paper ID
        auth_res = authorize_access(
            db=db,
            user_id=officer.id,
            paper_id=fake_paper_id,
            actor_ip="10.0.0.77",
        )
        security_decision = auth_res.decision.value
        actual_result += f"authorize_access decision: {auth_res.decision.value} ({auth_res.reason})"

        threat_events = self._find_recent_threat_events(db, actor_id=officer.id)
        threat_types = [t.event_type.value for t in threat_events]
        threat_event_created = len(threat_events) > 0

        audit_logs = self._find_recent_audit_events(db, actor_id=officer.id)
        audit_actions = [l.action for l in audit_logs]
        audit_event_created = len(audit_logs) > 0 or threat_event_created

        passed = (blocked_on_request or not auth_res.is_allowed) and (security_decision == "DENY")

        return SimulationResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            timestamp=now_str,
            simulated_actor=f"Officer Probe ({officer.id})",
            target_resource=f"QuestionPaper:{fake_paper_id} (NON-EXISTENT)",
            action_attempted=action_attempted,
            expected_result=expected_result,
            actual_result=actual_result,
            security_decision=security_decision,
            audit_event_created=audit_event_created,
            threat_event_created=threat_event_created,
            passed=passed,
            audit_actions_found=audit_actions,
            threat_types_found=threat_types,
            details={"blocked_on_request": blocked_on_request, "is_allowed": auth_res.is_allowed},
        )
