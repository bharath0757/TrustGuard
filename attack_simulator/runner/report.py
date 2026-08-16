"""
TrustGuard Attack Simulator — Reporting Engine.

Formats simulation results into formatted text, tables, JSON, and Markdown summaries.
"""

from datetime import datetime
import json
from typing import Any, Dict, List
from attack_simulator.scenarios.models import SimulationResult


def format_text_report(results: List[SimulationResult]) -> str:
    """Format simulation results into a clear terminal summary."""
    lines = []
    lines.append("=" * 80)
    lines.append("        TRUSTGUARD CONTROLLED ATTACK SIMULATION REPORT")
    lines.append("        SAFE LOCAL DEFENSE VERIFICATION")
    lines.append("=" * 80)
    lines.append(f"Total Scenarios Executed: {len(results)}")
    passed_count = sum(1 for r in results if r.passed)
    failed_count = len(results) - passed_count
    lines.append(f"Defense Success Rate: {passed_count}/{len(results)} ({(passed_count/len(results))*100:.1f}%)")
    lines.append("-" * 80)

    for r in results:
        status_symbol = "[PASS - BLOCKED]" if r.passed else "[FAIL - PERMITTED]"
        lines.append(f"Scenario {r.scenario_id:02d}: {r.scenario_name}")
        lines.append(f"  Status:            {status_symbol}")
        lines.append(f"  Simulated Actor:   {r.simulated_actor}")
        lines.append(f"  Target Resource:   {r.target_resource}")
        lines.append(f"  Action Attempted:  {r.action_attempted}")
        lines.append(f"  Expected Result:   {r.expected_result}")
        lines.append(f"  Actual Result:     {r.actual_result}")
        lines.append(f"  Security Decision: {r.security_decision}")
        lines.append(f"  Audit Logged:      {'YES' if r.audit_event_created else 'NO'}")
        lines.append(f"  Threat Logged:     {'YES' if r.threat_event_created else 'NO'}")
        if r.audit_actions_found:
            lines.append(f"  Audit Actions:     {', '.join(r.audit_actions_found)}")
        if r.threat_types_found:
            lines.append(f"  Threat Incidents:  {', '.join(r.threat_types_found)}")
        lines.append("-" * 80)

    lines.append("=" * 80)
    return "\n".join(lines)


def format_markdown_report(results: List[SimulationResult]) -> str:
    """Format simulation results into a GitHub-flavored Markdown table."""
    lines = []
    lines.append("# TrustGuard Attack Simulation Summary Report\n")
    lines.append("**Environment**: Safe Local Simulation (Zero External Traffic)")
    lines.append(f"**Execution Timestamp**: {datetime.utcnow().isoformat()}Z\n")
    
    passed_count = sum(1 for r in results if r.passed)
    lines.append(f"### Defense Scorecard: {passed_count}/{len(results)} Scenarios Successfully Blocked\n")
    
    lines.append("| ID | Scenario Name | Simulated Actor | Decision | Audit / Threat | Defense Result |")
    lines.append("|:---|:---|:---|:---:|:---:|:---:|")

    for r in results:
        status = "PASSED (BLOCKED)" if r.passed else "**FAILED (BREACHED)**"
        audit_flag = "Audit & Threat" if (r.audit_event_created and r.threat_event_created) else ("Audit Only" if r.audit_event_created else "None")
        lines.append(
            f"| {r.scenario_id} | {r.scenario_name} | `{r.simulated_actor.split('(')[0].strip()}` | **{r.security_decision}** | {audit_flag} | {status} |"
        )

    lines.append("\n### Detailed Scenario Findings\n")
    for r in results:
        lines.append(f"#### Scenario {r.scenario_id}: {r.scenario_name}\n")
        lines.append(f"- **Simulated Actor**: {r.simulated_actor}")
        lines.append(f"- **Target Resource**: {r.target_resource}")
        lines.append(f"- **Action Attempted**: {r.action_attempted}")
        lines.append(f"- **Expected Result**: {r.expected_result}")
        lines.append(f"- **Actual Result**: {r.actual_result}")
        lines.append(f"- **Security Decision**: `{r.security_decision}`")
        lines.append(f"- **Audit Event Recorded**: `{'True' if r.audit_event_created else 'False'}`")
        lines.append(f"- **Threat Incident Recorded**: `{'True' if r.threat_event_created else 'False'}`\n")

    return "\n".join(lines)


def format_json_report(results: List[SimulationResult]) -> str:
    """Format simulation results into structured JSON."""
    return json.dumps([r.to_dict() for r in results], indent=2)
