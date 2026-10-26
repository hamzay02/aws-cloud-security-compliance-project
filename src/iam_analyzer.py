import argparse
import json
from pathlib import Path


def analyze_iam_policy(policy: dict) -> list[dict]:
    """Identify potentially over-permissive IAM policy statements."""
    findings = []

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for index, statement in enumerate(statements, start=1):
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions and "*" in resources:
            findings.append({
                "rule_id": "IAM-001",
                "title": "Overly permissive IAM policy",
                "severity": "HIGH",
                "evidence": (
                    f"Statement {index} allows all actions on all resources."
                ),
                "remediation": (
                    "Apply least privilege by specifying only the required "
                    "actions and resources."
                ),
                "soc2_reference": (
                    "CC6.1 - preliminary logical access control mapping; "
                    "validate applicability against the organization's controls."
                ),
            })

        elif "*" in actions:
            findings.append({
                "rule_id": "IAM-002",
                "title": "Wildcard actions on scoped resources",
                "severity": "HIGH",
                "evidence": (
                    f"Statement {index} allows all actions on these resources: "
                    f"{', '.join(resources)}."
                ),
                "remediation": (
                    "Replace the wildcard action with only the specific "
                    "permissions required by the workload."
                ),
                "soc2_reference": (
                    "CC6.1 - preliminary logical access control mapping; "
                    "validate applicability against the organization's controls."
                ),
            })

    return findings


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    default_policy = project_root / "sample_data" / "iam_policy_wildcard.json"

    parser = argparse.ArgumentParser(
        description="Analyze a JSON IAM policy for overly broad permissions."
    )
    parser.add_argument(
        "--policy",
        default=str(default_policy),
        help="Path to an IAM policy JSON file.",
    )
    args = parser.parse_args()

    policy_path = Path(args.policy)
    if not policy_path.is_absolute():
        policy_path = project_root / policy_path

    with policy_path.open("r", encoding="utf-8-sig") as policy_file:
        policy = json.load(policy_file)

    findings = analyze_iam_policy(policy)

    print(json.dumps(findings, indent=2))
    print(f"\nTotal findings: {len(findings)}")


if __name__ == "__main__":
    main()
