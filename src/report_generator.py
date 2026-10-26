
import json
from pathlib import Path

from src.iam_analyzer import analyze_iam_policy
from src.cloudtrail_analyzer import analyze_cloudtrail_events
from src.cloud_config_analyzer import analyze_cloud_config


def generate_security_report(
    policy: dict,
    events: list[dict],
    cloud_config: list[dict] | None = None,
) -> dict:
    """Combine IAM, CloudTrail, and optional cloud configuration findings."""
    iam_findings = analyze_iam_policy(policy)
    cloudtrail_findings = analyze_cloudtrail_events(events)

    cloud_config_findings = (
        analyze_cloud_config(cloud_config)
        if cloud_config is not None
        else []
    )

    all_findings = (
        iam_findings
        + cloudtrail_findings
        + cloud_config_findings
    )

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
    sample_data_dir = project_root / "sample_data"

    with (sample_data_dir / "iam_policy_wildcard.json").open(
        "r", encoding="utf-8-sig"
    ) as policy_file:
        policy = json.load(policy_file)

    with (sample_data_dir / "cloudtrail_events.json").open(
        "r", encoding="utf-8-sig"
    ) as events_file:
        events = json.load(events_file)

    with (sample_data_dir / "cloud_config.json").open(
        "r", encoding="utf-8-sig"
    ) as config_file:
        cloud_config = json.load(config_file)

    report = generate_security_report(policy, events, cloud_config)

    reports_dir = project_root / "reports"
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / "security_report.json"
    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
