"""
TrustGuard Attack Simulator — Fixtures Package.
"""
from .mock_actors import SIMULATED_ACTORS, SimulatedActor
from .synthetic_targets import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
    create_simulated_access_setup,
)

__all__ = [
    "SIMULATED_ACTORS",
    "SimulatedActor",
    "SYNTHETIC_DEMO_PAYLOAD",
    "create_simulated_target_paper",
    "create_simulated_access_setup",
]
