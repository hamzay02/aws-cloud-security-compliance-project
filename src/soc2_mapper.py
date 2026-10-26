import json
from pathlib import Path


def map_findings_to_controls(
    findings: list[dict],
    controls: list[dict],
) -> list[dict]:
    """Map security findings to relevant SOC 2 control references."""
    mapped_controls = []

    for control in controls:
        relevant_findings = [
            finding
            for finding in findings
            if finding.get("rule_id")
            in control.get("relevant_finding_rules", [])
        ]

        if not relevant_findings:
            continue

        mapped_controls.append({
            "control_id": control["control_id"],
            "control_name": control["control_name"],
            "description": control["description"],
            "related_findings": [
                {
                    "rule_id": finding["rule_id"],
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "evidence": finding["evidence"],
                    "remediation": finding["remediation"],
                }
                for finding in relevant_findings
            ],
            "assessment_note": control["assessment_note"],
            "assessment_status": "REVIEW_REQUIRED",
        })

    return mapped_controls


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    with (project_root / "reports" / "security_report.json").open(
        "r", encoding="utf-8-sig"
    ) as report_file:
        report = json.load(report_file)

    with (project_root / "sample_data" / "soc2_controls.json").open(
        "r", encoding="utf-8-sig"
    ) as controls_file:
        controls = json.load(controls_file)

    mapped_controls = map_findings_to_controls(
        report["findings"],
        controls,
    )

    output_path = project_root / "reports" / "soc2_mapping_report.json"
    output_path.parent.mkdir(exist_ok=True)

    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(mapped_controls, output_file, indent=2)

    print(json.dumps(mapped_controls, indent=2))
    print(f"\nSOC 2 mapping report saved to: {output_path}")


if __name__ == "__main__":
    main()
