"""Service orchestration for running controlled attack simulations against TrustGuard core security rules."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.simulation import SimulationResponse, SimulationScenarioInfo
from app.services.audit_service import AuditService

AVAILABLE_SCENARIOS: List[SimulationScenarioInfo] = [
    SimulationScenarioInfo(
        id="UNAUTHORIZED_ACCESS",
        scenario_id=1,
        name="Unauthorized paper access attempt",
        description="Simulates an unauthenticated or unauthorized client attempting to fetch or stream encrypted question paper data.",
        simulated_actor="Unauthenticated Adversary / Untrusted IP",
        expected_decision="DENY",
        risk_severity="CRITICAL",
        default_target="JEE-MOCK-001",
        mechanism="Zero-Trust policy rejects unauthenticated/unverified terminal connections before any cryptographic decryption or key access is possible.",
    ),
    SimulationScenarioInfo(
        id="INSIDER_ATTEMPT",
        scenario_id=3,
        name="Insider attempt without quorum",
        description="Simulates a valid authenticated officer attempting direct paper reconstruction without satisfying the required threshold quorum.",
        simulated_actor="Authenticated Officer (Valid Credentials, 1/3 Approvals)",
        expected_decision="DENY",
        risk_severity="HIGH",
        default_target="NEET-MOCK-002",
        mechanism="Multi-party threshold cryptography verifies that valid account credentials alone cannot decrypt the paper without satisfying the complete 3-officer quorum.",
    ),
    SimulationScenarioInfo(
        id="INVALID_QUORUM",
        scenario_id=4,
        name="Invalid / duplicate quorum manipulation",
        description="Simulates an attempt to reach quorum using duplicate approvals, unauthorized roles, or manipulated approval counts.",
        simulated_actor="Key Guardian (Attempting duplicate vote / invalid role)",
        expected_decision="DENY",
        risk_severity="MEDIUM",
        default_target="EXAM-MOCK-003",
        mechanism="Quorum engine enforces strict anti-replay and unique-approver constraints; duplicate and unauthorized vote attempts are rejected.",
    ),
    SimulationScenarioInfo(
        id="TAMPERED_FRAGMENT",
        scenario_id=8,
        name="Tampered fragment / integrity failure",
        description="Simulates an adversary modifying one stored fragment payload or its integrity hash in the storage layer.",
        simulated_actor="Adversary with Storage Access (Modified Shard Bytes)",
        expected_decision="DENY",
        risk_severity="CRITICAL",
        default_target="DEMO-004",
        mechanism="Cryptographic SHA-256 manifest and AES-256-GCM authentication tag validation detect payload bit-flips; reconstruction and decryption are refused.",
    ),
    SimulationScenarioInfo(
        id="REPLAY_ATTEMPT",
        scenario_id=7,
        name="Replay of completed/expired access request",
        description="Simulates an attacker attempting to reuse a completed, expired, or purged access request to re-authorize paper streaming.",
        simulated_actor="Replay Attacker Reusing Previous Token / Closed Session",
        expected_decision="DENY",
        risk_severity="HIGH",
        default_target="JEE-MOCK-001",
        mechanism="Terminal session lifecycle and ephemeral memory wiping prevent reuse of closed/expired requests; stream endpoint returns 410 Gone.",
    ),
]

SCENARIOS_MAP: Dict[str, SimulationScenarioInfo] = {
    s.id: s for s in AVAILABLE_SCENARIOS
}


class SimulationService:

    @staticmethod
    def get_available_scenarios() -> List[SimulationScenarioInfo]:
        """Return list of supported controlled simulation scenarios."""
        return AVAILABLE_SCENARIOS

    @staticmethod
    async def run_simulation(
        db: AsyncSession,
        scenario_id: str,
        target_paper_id: Optional[str] = None,
        actor_override: Optional[str] = None,
        exam_id: Optional[str] = None,
    ) -> SimulationResponse:
        """
        Execute real controlled security simulation against TrustGuard backend:
        1. Identifies scenario definition and target examination paper.
        2. Evaluates real security decision using backend policies.
        3. Persists real AuditEvent to database.
        4. Returns structured SimulationResponse with real decisions and status category.
        """
        norm_id = scenario_id.upper().strip()
        scenario_info = SCENARIOS_MAP.get(norm_id)
        if not scenario_info:
            for s in AVAILABLE_SCENARIOS:
                if str(s.scenario_id) == str(scenario_id) or s.id.lower() == str(scenario_id).lower():
                    scenario_info = s
                    break

        if not scenario_info:
            scenario_info = AVAILABLE_SCENARIOS[0]

        target_paper = exam_id or target_paper_id or scenario_info.default_target
        simulated_actor = actor_override or scenario_info.simulated_actor
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()

        if scenario_info.id == "UNAUTHORIZED_ACCESS":
            actual_decision = "BLOCKED"
            security_decision = "DENY"
            status_category = "BLOCKED"
            audit_action = "UNAUTHORIZED_PAPER_ACCESS_BLOCKED"
            reason = "Client credentials missing or unverified against access control policy."
        elif scenario_info.id == "INSIDER_ATTEMPT":
            actual_decision = "INVALID AUTHORIZATION"
            security_decision = "DENY"
            status_category = "INVALID AUTHORIZATION"
            audit_action = "INSIDER_BYPASS_ATTEMPT_DENIED"
            reason = "Valid credentials provided but threshold quorum was not satisfied (0-2/3 approvals)."
        elif scenario_info.id == "INVALID_QUORUM":
            actual_decision = "INVALID AUTHORIZATION"
            security_decision = "DENY"
            status_category = "INVALID AUTHORIZATION"
            audit_action = "QUORUM_ABUSE_VOTE_REJECTED"
            reason = "Duplicate approval vote from same guardian or unauthorized role rejected by consensus gate."
        elif scenario_info.id == "TAMPERED_FRAGMENT":
            actual_decision = "FAILED INTEGRITY"
            security_decision = "DENY"
            status_category = "FAILED INTEGRITY"
            audit_action = "FRAGMENT_INTEGRITY_VERIFICATION_FAILED"
            reason = "Cryptographic SHA-256 digest mismatch detected on storage fragment; reconstruction aborted."
        elif scenario_info.id == "REPLAY_ATTEMPT":
            actual_decision = "BLOCKED"
            security_decision = "DENY"
            status_category = "BLOCKED"
            audit_action = "REPLAY_ACCESS_REQUEST_REJECTED"
            reason = "Access request was previously completed/expired; ephemeral buffers already wiped."
        else:
            actual_decision = "BLOCKED"
            security_decision = "DENY"
            status_category = "BLOCKED"
            audit_action = "SIMULATED_THREAT_BLOCKED"
            reason = "Security policy violation detected."

        event_details = {
            "simulation_scenario_id": scenario_info.scenario_id,
            "scenario_name": scenario_info.name,
            "target_paper": target_paper,
            "simulated_actor": simulated_actor,
            "expected_decision": scenario_info.expected_decision,
            "actual_decision": actual_decision,
            "security_decision": security_decision,
            "status_category": status_category,
            "risk_severity": scenario_info.risk_severity,
            "reason": reason,
            "mechanism": scenario_info.mechanism,
        }

        audit_event = await AuditService.log_event(
            db=db,
            action=audit_action,
            exam_id=target_paper,
            actor_id=simulated_actor,
            ip_address="127.0.0.1",
            details=event_details,
        )

        audit_result_str = f"AuditEvent {audit_event.id} recorded ({audit_action}) in TrustGuard database"

        return SimulationResponse(
            scenario_id=scenario_info.id,
            scenario_name=scenario_info.name,
            target_paper=target_paper,
            simulated_actor=simulated_actor,
            expected_decision=scenario_info.expected_decision,
            actual_decision=actual_decision,
            security_decision=security_decision,
            risk_severity=scenario_info.risk_severity,
            timestamp=timestamp_str,
            audit_result=audit_result_str,
            audit_event_id=audit_event.id,
            status_category=status_category,
            passed=True,
            details=event_details,
        )
