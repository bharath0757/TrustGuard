"""
TrustGuard Attack Simulator — Command Line Interface (CLI).

Usage:
  python -m attack-simulator.runner.cli --all
  python -m attack-simulator.runner.cli --scenario 3
  python -m attack-simulator.runner.cli --all --json
  python -m attack-simulator.runner.cli --all --markdown
"""

import argparse
import sys

from .simulator import AttackSimulator
from .report import format_text_report, format_markdown_report, format_json_report


def main():
    parser = argparse.ArgumentParser(
        description="TrustGuard Controlled Attack Simulator (Safe Local Simulation)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Execute all 10 attack simulation scenarios",
    )
    parser.add_argument(
        "--scenario",
        type=int,
        choices=range(1, 11),
        help="Execute a specific scenario by ID (1-10)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Output results in Markdown format",
    )

    args = parser.parse_args()

    simulator = AttackSimulator()

    if args.scenario:
        results = [simulator.run_scenario(args.scenario)]
    else:
        # Default to running all scenarios
        results = simulator.run_all()

    if args.json:
        print(format_json_report(results))
    elif args.markdown:
        print(format_markdown_report(results))
    else:
        print(format_text_report(results))

    # Exit code: 0 if all attacks were successfully blocked, 1 if any breached
    all_blocked = all(r.passed for r in results)
    sys.exit(0 if all_blocked else 1)


if __name__ == "__main__":
    main()
