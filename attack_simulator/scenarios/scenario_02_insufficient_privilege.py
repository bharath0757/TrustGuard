"""
Scenario 2: Authenticated user without sufficient privilege attempts access.

Simulates a valid registered candidate user (holding only CANDIDATE role)
attempting to access/deliver an examination paper meant exclusively for OFFICER / ADMIN.
"""

from datetime import datetime, timezone
import hashlib
import uuid
from sqlalchemy.orm import Session

from database.models.access import RequestType
from database.models.user import User, Role, UserRole
from security import authorize_access, AccessDecision
from attack_simulator.fixtures import create_simulated_target_paper
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult


class Scenario02InsufficientPrivilege(BaseAttackScenario):
    scenario_id = 2
    scenario_name = "Authenticated user without sufficient privilege attempts access"
    description = "Authenticated candidate (CANDIDATE role) attempts to authorize access to protected paper"

    def run(self, db: Session, client=None) -> SimulationResult:
        now_str = datetime.now(timezone.utc).isoformat()
        
        # 1. Setup Candidate Role and User
        r_candidate = db.query(Role).filter(Role.name == "CANDIDATE").first()
        if not r_candidate:
            r_candidate = Role(id=uuid.uuid4(), name="CANDIDATE", description="Exam Candidate")
            db.add(r_candidate)
            db.flush()

        candidate_user = User(
            id=uuid.uuid4(),
            email=f"candidate.eve.{uuid.uuid4().hex[:6]}@synth.local",
            password_hash=hashlib.sha256(b"Password2026!").hexdigest(),
            full_name="Candidate Eve",
            is_active=True,
        )
        db.add(candidate_user)
        db.flush()
        db.add(UserRole(user_id=candidate_user.id, role_id=r_candidate.id))
        db.flush()

        # 2. Setup Target Paper
        paper, fragments, key = create_simulated_target_paper(db)

        action_attempted = f"Candidate Eve ({candidate_user.id}) invokes authorize_access for paper {paper.id}"
        expected_result = "Access Denied due to insufficient role permissions; Security decision DENY; Threat incident logged"

        auth_res = authorize_access(
            db=db,
            user_id=candidate_user.id,
            paper_id=paper.id,
            allowed_roles={"OFFICER", "ADMIN"},
            actor_ip="10.0.0.45",
        )

        security_decision = auth_res.decision.value
        actual_result = f"Decision: {auth_res.decision.value} (Reason: {auth_res.reason})"

        threat_events = self._find_recent_threat_events(db, actor_id=candidate_user.id)
        threat_types = [t.event_type.value for t in threat_events]
        threat_event_created = len(threat_events) > 0

        audit_logs = self._find_recent_audit_events(db, target_id=paper.id)
        audit_actions = [l.action for l in audit_logs]
        audit_event_created = len(audit_logs) > 0 or threat_event_created

        passed = (auth_res.decision == AccessDecision.DENY) and (not auth_res.is_allowed) and ("role" in auth_res.reason.lower() or "privilege" in auth_res.reason.lower() or "denied" in auth_res.reason.lower())

        return SimulationResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            timestamp=now_str,
            simulated_actor=f"Candidate Eve [Role: CANDIDATE] ({candidate_user.id})",
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
            details={"user_roles": ["CANDIDATE"], "required_roles": ["OFFICER", "ADMIN"], "decision": auth_res.decision.value},
        )
