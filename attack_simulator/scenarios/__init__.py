"""
TrustGuard Attack Simulator — Scenarios Package.

Registry of all 10 controlled attack simulation scenarios.
"""

from typing import Dict, List, Type

from .base import BaseAttackScenario
from .models import SimulationResult
from .scenario_01_unauthorized_user import Scenario01UnauthorizedUser
from .scenario_02_insufficient_privilege import Scenario02InsufficientPrivilege
from .scenario_03_no_quorum import Scenario03NoQuorum
from .scenario_04_duplicate_approval import Scenario04DuplicateApproval
from .scenario_05_unauthorized_approver import Scenario05UnauthorizedApprover
from .scenario_06_outside_time_window import Scenario06OutsideTimeWindow
from .scenario_07_replay_completed_request import Scenario07ReplayCompletedRequest
from .scenario_08_tampered_fragment import Scenario08TamperedFragment
from .scenario_09_invalid_resource import Scenario09InvalidResource
from .scenario_10_malformed_request import Scenario10MalformedRequest

ALL_SCENARIOS: List[Type[BaseAttackScenario]] = [
    Scenario01UnauthorizedUser,
    Scenario02InsufficientPrivilege,
    Scenario03NoQuorum,
    Scenario04DuplicateApproval,
    Scenario05UnauthorizedApprover,
    Scenario06OutsideTimeWindow,
    Scenario07ReplayCompletedRequest,
    Scenario08TamperedFragment,
    Scenario09InvalidResource,
    Scenario10MalformedRequest,
]

SCENARIOS_BY_ID: Dict[int, Type[BaseAttackScenario]] = {
    s.scenario_id: s for s in ALL_SCENARIOS
}

__all__ = [
    "BaseAttackScenario",
    "SimulationResult",
    "ALL_SCENARIOS",
    "SCENARIOS_BY_ID",
    "Scenario01UnauthorizedUser",
    "Scenario02InsufficientPrivilege",
    "Scenario03NoQuorum",
    "Scenario04DuplicateApproval",
    "Scenario05UnauthorizedApprover",
    "Scenario06OutsideTimeWindow",
    "Scenario07ReplayCompletedRequest",
    "Scenario08TamperedFragment",
    "Scenario09InvalidResource",
    "Scenario10MalformedRequest",
]
