
import json
from pathlib import Path

from src.cloudtrail_analyzer import analyze_cloudtrail_events
from src.cloud_config_analyzer import analyze_cloud_config
from src.iam_analyzer import analyze_iam_policy
from src.report_generator import generate_security_report
from src.soc2_mapper import map_findings_to_controls
from src.soc2_evidence_tracker import track_evidence
from src.soc2_assessment import build_assessment


def load_json(path: Path):
    with path.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def save_json(path: Path, data: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def generate_markdown_summary(security_report: dict) -> str:
    """Create a human-readable summary of security findings."""
    findings = security_report.get("findings", [])
    total = len(findings)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = {
        severity: sum(
            1 for finding in findings
            if finding.get("severity", "INFO").upper() == severity
        )
        for severity in severity_order
    }

    lines = [
        "# Security Findings Summary",
        "",
        "> This report is generated from simulated project data. "
        "It is not a formal security audit or SOC 2 attestation.",
        "",
        "## Overview",
        "",
        f"- **Total findings:** {total}",
        "",
        "## Findings by severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]

    for severity in severity_order:
        if counts[severity]:
            lines.append(f"| {severity} | {counts[severity]} |")

    if total == 0:
        lines.extend(["", "No findings were detected in the supplied sample data."])

    lines.extend(["", "## Finding details", ""])

    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "Unknown").upper()
        title = finding.get("title", "Untitled finding")
        rule_id = finding.get("rule_id", "N/A")
        evidence = finding.get("evidence", "No evidence details provided.")
        remediation = finding.get("remediation", "Manual review recommended.")

        lines.extend([
            f"### {index}. {title}",
            "",
            f"- **Rule:** {rule_id}",
            f"- **Severity:** {severity}",
            f"- **Evidence:** {evidence}",
            f"- **Recommended remediation:** {remediation}",
            "",
        ])

    lines.extend([
        "## Scope and limitations",
        "",
        "This summary reflects only the supplied sample inputs and implemented "
        "detection rules. Findings require human review; the absence of a "
        "finding does not establish that an environment is secure.",
        "",
    ])

    return "\n".join(lines)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    sample_dir = root / "sample_data"
    reports_dir = root / "reports"

    policy = load_json(sample_dir / "iam_policy_wildcard.json")
    events = load_json(sample_dir / "cloudtrail_events.json")
    cloud_config = load_json(sample_dir / "cloud_config.json")
    controls = load_json(sample_dir / "soc2_controls.json")
    evidence_records = load_json(sample_dir / "soc2_evidence.json")

    security_report = generate_security_report(policy, events, cloud_config)
    save_json(reports_dir / "security_report.json", security_report)

    markdown_summary = generate_markdown_summary(security_report)
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "security_summary.md").write_text(
        markdown_summary,
        encoding="utf-8",
    )

    mapped_controls = map_findings_to_controls(
        security_report["findings"],
        controls,
    )
    save_json(reports_dir / "soc2_mapping_report.json", mapped_controls)

    evidence_report = track_evidence(evidence_records)
    save_json(reports_dir / "soc2_evidence_report.json", evidence_report)

    assessment = build_assessment(mapped_controls, evidence_report)
    save_json(reports_dir / "soc2_assessment_report.json", assessment)

    print("Security and compliance-support workflow completed.")
    print(f"Security findings: {security_report['total_findings']}")
    print(f"Controls requiring review: {assessment['controls_requiring_review']}")
    print(f"Evidence records: {evidence_report['total_evidence_records']}")
    print(f"Markdown summary: {reports_dir / 'security_summary.md'}")
    print(f"Reports saved in: {reports_dir}")


if __name__ == "__main__":
    main()
