"""
TrustGuard Attack Simulator — Synthetic Mock Actors.

SAFE LOCAL SIMULATION ONLY.
Defines simulated personas used to test defensive security boundaries.
Zero real credentials, zero external connections.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import uuid


@dataclass
class SimulatedActor:
    """Represents a simulated actor in a controlled attack scenario."""
    name: str
    description: str
    role_name: Optional[str]
    is_authenticated: bool
    is_active: bool
    email: str
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)


# Predefined Synthetic Threat Actors for Controlled Simulations
SIMULATED_ACTORS: Dict[str, SimulatedActor] = {
    "UNAUTHORIZED_ANONYMOUS": SimulatedActor(
        name="Anonymous Intruder",
        description="Unauthenticated external party with zero credentials or session",
        role_name=None,
        is_authenticated=False,
        is_active=False,
        email="unauthorized.intruder@synth.local",
    ),
    "CANDIDATE_EVE": SimulatedActor(
        name="Candidate Eve",
        description="Authenticated exam candidate attempting unauthorized administrative access",
        role_name="CANDIDATE",
        is_authenticated=True,
        is_active=True,
        email="eve.candidate@synth.local",
    ),
    "UNASSIGNED_MALLORY": SimulatedActor(
        name="Unassigned Approver Mallory",
        description="Legitimate approver persona attempting to vote on an exam they are not assigned to",
        role_name="APPROVER",
        is_authenticated=True,
        is_active=True,
        email="mallory.unassigned@synth.local",
    ),
    "IMPATIENT_OFFICER": SimulatedActor(
        name="Impatient Officer Dave",
        description="Authorized officer attempting early access before quorum is established or window opens",
        role_name="OFFICER",
        is_authenticated=True,
        is_active=True,
        email="dave.officer@synth.local",
    ),
    "REPLAY_ATTACKER": SimulatedActor(
        name="Replay Attacker",
        description="Entity attempting to reuse expired or completed access tokens and requests",
        role_name="OFFICER",
        is_authenticated=True,
        is_active=True,
        email="replay.attacker@synth.local",
    ),
    "CORRUPTER": SimulatedActor(
        name="Ciphertext Corrupter",
        description="Entity attempting to inject tampered or bit-flipped fragments into reconstruction",
        role_name=None,
        is_authenticated=False,
        is_active=False,
        email="tamper.agent@synth.local",
    ),
}
