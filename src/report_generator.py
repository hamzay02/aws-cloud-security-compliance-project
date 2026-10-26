import json
from pathlib import Path

from src.iam_analyzer import analyze_iam_policy
from src.cloudtrail_analyzer import analyze_cloudtrail_events


def generate_security_report(
    policy: dict,
    events: list[dict],
) -> dict:
    """Combine IAM and CloudTrail findings into one report."""
    iam_findings = analyze_iam_policy(policy)
    cloudtrail_findings = analyze_cloudtrail_events(events)

    all_findings = iam_findings + cloudtrail_findings

    return {
        "project": "AWS Cloud Security & Compliance Project",
        "total_findings": len(all_findings),
        "severity_summary": {
            "HIGH": sum(
                finding["severity"] == "HIGH"
                for finding in all_findings
            ),
            "MEDIUM": sum(
                finding["severity"] == "MEDIUM"
                for finding in all_findings
            ),
            "LOW": sum(
                finding["severity"] == "LOW"
                for finding in all_findings
            ),
        },
        "findings": all_findings,
        "note": (
            "Findings are based on basic detection rules and simulated data. "
            "This report is not a formal security audit or SOC 2 attestation."
        ),
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    with (project_root / "sample_data" / "iam_policy_wildcard.json").open(
        "r", encoding="utf-8-sig"
    ) as policy_file:
        policy = json.load(policy_file)

    with (project_root / "sample_data" / "cloudtrail_events.json").open(
        "r", encoding="utf-8-sig"
    ) as events_file:
        events = json.load(events_file)

    report = generate_security_report(policy, events)

    reports_dir = project_root / "reports"
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / "security_report.json"
    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
