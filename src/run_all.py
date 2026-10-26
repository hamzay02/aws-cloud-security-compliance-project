import json
from pathlib import Path

from src.cloudtrail_analyzer import analyze_cloudtrail_events
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


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    sample_dir = root / "sample_data"
    reports_dir = root / "reports"

    policy = load_json(sample_dir / "iam_policy_wildcard.json")
    events = load_json(sample_dir / "cloudtrail_events.json")
    controls = load_json(sample_dir / "soc2_controls.json")
    evidence_records = load_json(sample_dir / "soc2_evidence.json")

    security_report = generate_security_report(policy, events)
    save_json(reports_dir / "security_report.json", security_report)

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
    print(f"Reports saved in: {reports_dir}")


if __name__ == "__main__":
    main()
