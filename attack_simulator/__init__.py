"""
TrustGuard Attack Simulator Package.

Controlled cybersecurity simulation layer for local Zero-Trust verification.
"""

from .scenarios import ALL_SCENARIOS, SCENARIOS_BY_ID, BaseAttackScenario, SimulationResult
from .runner import AttackSimulator, format_text_report, format_markdown_report, format_json_report

__all__ = [
    "ALL_SCENARIOS",
    "SCENARIOS_BY_ID",
    "BaseAttackScenario",
    "SimulationResult",
    "AttackSimulator",
    "format_text_report",
    "format_markdown_report",
    "format_json_report",
]
