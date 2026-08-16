# TrustGuard Controlled Attack Simulator

**Purpose**: Demonstrate and verify defensive Zero-Trust security behavior against controlled unauthorized actions within the TrustGuard application.

---

## Safety & Operational Guardrails

> [!IMPORTANT]
> **SAFE LOCAL SIMULATION ONLY**
> - Zero external network traffic or external system scanning.
> - Zero real examination questions (only synthetic test data, e.g., `TRUSTGUARD_DEMO_PAPER`).
> - Zero offensive exploit tooling or dangerous capabilities.
> - Strict local database sandboxing and in-memory execution.

---

## Directory Architecture

```
attack-simulator/
├── fixtures/
│   ├── __init__.py
│   ├── mock_actors.py          # Simulated personas (Anonymous, Candidate, Unassigned, Replay)
│   └── synthetic_targets.py    # Synthetic papers, keys, and access setup factories
├── scenarios/
│   ├── __init__.py             # Scenario registry (ALL_SCENARIOS, SCENARIOS_BY_ID)
│   ├── base.py                 # Abstract BaseAttackScenario class
│   ├── models.py               # SimulationResult dataclass
│   ├── scenario_01_unauthorized_user.py
│   ├── scenario_02_insufficient_privilege.py
│   ├── scenario_03_no_quorum.py
│   ├── scenario_04_duplicate_approval.py
│   ├── scenario_05_unauthorized_approver.py
│   ├── scenario_06_outside_time_window.py
│   ├── scenario_07_replay_completed_request.py
│   ├── scenario_08_tampered_fragment.py
│   ├── scenario_09_invalid_resource.py
│   └── scenario_10_malformed_request.py
├── runner/
│   ├── __init__.py
│   ├── simulator.py            # AttackSimulator orchestration engine
│   ├── report.py               # Text, Markdown, and JSON report formatters
│   └── cli.py                  # Command-line interface
└── README.md
```

---

## Implemented Attack Scenarios

| # | Scenario | Simulated Threat Actor | Expected Defense Behavior | Security Decision |
|---|---|---|---|:---:|
| **01** | **Unauthorized User Request** | Anonymous / Unregistered Actor | Rejection on request / direct authorization denial (`UNAUTHORIZED_ACCESS`) | `DENY` |
| **02** | **Insufficient Privilege Access** | Authenticated Candidate (`CANDIDATE` role) | 6-factor JIT check blocks access due to role requirement (`OFFICER`/`ADMIN`) | `DENY` |
| **03** | **Access Without Quorum** | Authorized Officer ($1 < 3$ approvals) | Blocked due to incomplete multi-party consensus (`INVALID_QUORUM`) | `DENY` |
| **04** | **Duplicate Approval Vote** | Key Guardian / Approver | Replay vote rejection; prevents artificial quorum inflation (`REPLAY_ATTEMPT`) | `DENY` |
| **05** | **Unauthorized Approver Vote** | Candidate / Unprivileged User | Approval vote rejected (`InvalidApproverRoleError`) | `DENY` |
| **06** | **Outside Time Window Access** | Authorized Officer ($now < start$ or $now > end$) | Time-lock enforcement blocks premature or expired access (`BEFORE_WINDOW` / `AFTER_WINDOW`) | `DENY` |
| **07** | **Replay of Completed Request** | Replay Attacker with expired session | Replay blocked; request status is `EXPIRED` / window `CLOSED` (`REPLAY_ATTEMPT`) | `DENY` |
| **08** | **Tampered Fragment Injection** | Ciphertext Corrupter (bit-flip) | Shard hash mismatch detected; reconstruction aborted (`INTEGRITY_FAILURE`) | `DENY` |
| **09** | **Invalid Paper ID Probing** | Probing Client (non-existent UUID) | Query rejected (`QuorumValidationError`); zero secret leakage | `DENY` |
| **10** | **Malformed Request Parameters** | Malformed Client ($k \le 0$, empty reason, end < start) | Schema and logic validation rejection before state transition | `DENY` |

---

## Execution & Usage

### 1. Command Line Interface (CLI)

```bash
# Run all 10 simulation scenarios with formatted text output
python -m attack-simulator.runner.cli --all

# Run a specific scenario (e.g. Scenario 3)
python -m attack-simulator.runner.cli --scenario 3

# Export results to JSON
python -m attack-simulator.runner.cli --all --json

# Export results to Markdown
python -m attack-simulator.runner.cli --all --markdown
```

### 2. Programmatic Python API

```python
from attack_simulator import AttackSimulator, format_text_report

simulator = AttackSimulator()
results = simulator.run_all()

print(format_text_report(results))
summary = simulator.get_summary()
print(f"Defensive Success Rate: {summary['success_rate_percent']}%")
```

---

## Simulation Result Record Model

Every simulation execution produces a `SimulationResult` object containing:
- `scenario_id`: Integer ID (1–10)
- `scenario_name`: Human-readable name
- `timestamp`: ISO-8601 UTC timestamp
- `simulated_actor`: Persona details and role
- `target_resource`: Affected QuestionPaper, AccessRequest, or Fragment
- `action_attempted`: Technical action performed
- `expected_result`: Expected defensive policy enforcement
- `actual_result`: Concrete exception / status received
- `security_decision`: Defensive verdict (`DENY` or `ALLOW`)
- `audit_event_created`: Boolean flag indicating audit log entry
- `threat_event_created`: Boolean flag indicating threat incident log entry
