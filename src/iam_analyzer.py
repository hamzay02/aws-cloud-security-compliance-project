
import argparse
import json
from pathlib import Path
from typing import Any


def analyze_iam_policy(policy: dict) -> list[dict]:
    """Identify selected potentially over-permissive IAM policy patterns."""
    if not isinstance(policy, dict):
        raise ValueError("IAM policy must be a JSON object.")

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        raise ValueError("'Statement' must be an object or a list.")

    findings = []

    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            raise ValueError(f"Statement {index} must be a JSON object.")

        effect = statement.get("Effect")
        if effect != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if not isinstance(actions, list) or not all(
            isinstance(action, str) for action in actions
        ):
            raise ValueError(
                f"Statement {index}: 'Action' must be a string or list of strings."
            )

        if not isinstance(resources, list) or not all(
            isinstance(resource, str) for resource in resources
        ):
            raise ValueError(
                f"Statement {index}: 'Resource' must be a string or list of strings."
            )

        action_wildcard = "*" in actions
        resource_wildcard = "*" in resources

        if action_wildcard and resource_wildcard:
            findings.append({
                "rule_id": "IAM-001",
                "title": "All actions allowed on all resources",
                "severity": "HIGH",
                "evidence": (
                    f"Statement {index} allows all actions on all resources."
                ),
                "remediation": (
                    "Apply least privilege by specifying only required actions "
                    "and resources."
                ),
                "soc2_reference": "CC6.1 - preliminary mapping; review applicability.",
            })

        elif action_wildcard:
            findings.append({
                "rule_id": "IAM-002",
                "title": "Wildcard actions on scoped resources",
                "severity": "HIGH",
                "evidence": (
                    f"Statement {index} allows all actions on these resources: "
                    f"{', '.join(resources)}."
                ),
                "remediation": (
                    "Replace wildcard actions with the specific permissions "
                    "required by the workload."
                ),
                "soc2_reference": "CC6.1 - preliminary mapping; review applicability.",
            })

        elif resource_wildcard:
            findings.append({
                "rule_id": "IAM-003",
                "title": "Wildcard resource scope",
                "severity": "MEDIUM",
                "evidence": (
                    f"Statement {index} allows actions {', '.join(actions)} "
                    "on all resources."
                ),
                "remediation": (
                    "Scope resources to the specific ARNs required, where the "
                    "AWS service supports resource-level permissions."
                ),
                "soc2_reference": "CC6.1 - preliminary mapping; review applicability.",
            })

        if statement.get("Condition") is None and statement.get("NotAction"):
            findings.append({
                "rule_id": "IAM-004",
                "title": "Allow statement uses NotAction",
                "severity": "MEDIUM",
                "evidence": (
                    f"Statement {index} uses NotAction in an Allow statement; "
                    "the effective permissions require careful review."
                ),
                "remediation": (
                    "Review the effective permission set and prefer explicit "
                    "Action entries where practical."
                ),
                "soc2_reference": "CC6.1 - preliminary mapping; review applicability.",
            })

    return findings


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    default_policy = project_root / "sample_data" / "iam_policy_wildcard.json"

    parser = argparse.ArgumentParser(
        description="Analyze a JSON IAM policy for selected risky patterns."
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

    try:
        with policy_path.open("r", encoding="utf-8-sig") as policy_file:
            policy = json.load(policy_file)

        findings = analyze_iam_policy(policy)

    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(f"Unable to analyze IAM policy: {error}")

    print(json.dumps(findings, indent=2))
    print(f"\nTotal findings: {len(findings)}")


if __name__ == "__main__":
    main()
