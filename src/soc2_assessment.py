import json
from pathlib import Path


def build_assessment(
    mapped_controls: list[dict],
    evidence_report: dict,
) -> dict:
    """Combine preliminary control mappings and evidence records."""
    evidence_records = evidence_report["evidence_records"]
    assessments = []

    for control in mapped_controls:
        control_id = control["control_id"]

        related_evidence = [
            record
            for record in evidence_records
            if record["control_id"] == control_id
        ]

        assessments.append({
            "control_id": control_id,
            "control_name": control["control_name"],
            "assessment_status": "REVIEW_REQUIRED",
            "related_findings": control["related_findings"],
            "evidence_records": related_evidence,
            "evidence_count": len(related_evidence),
            "pending_evidence_reviews": sum(
                record["review_status"] == "PENDING_REVIEW"
                for record in related_evidence
            ),
            "assessment_note": (
                "Preliminary project mapping only. Review control design, "
                "operating effectiveness, and supporting evidence before "
                "drawing conclusions."
            ),
        })

    return {
        "report_name": "Preliminary SOC 2 Control Assessment",
        "total_controls_reviewed": len(assessments),
        "controls_requiring_review": sum(
            item["assessment_status"] == "REVIEW_REQUIRED"
            for item in assessments
        ),
        "controls": assessments,
        "disclaimer": (
            "This report uses simulated data and preliminary control mappings. "
            "It does not establish SOC 2 compliance or replace an independent audit."
        ),
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    with (project_root / "reports" / "soc2_mapping_report.json").open(
        "r", encoding="utf-8-sig"
    ) as file:
        mapped_controls = json.load(file)

    with (project_root / "reports" / "soc2_evidence_report.json").open(
        "r", encoding="utf-8-sig"
    ) as file:
        evidence_report = json.load(file)

    assessment = build_assessment(mapped_controls, evidence_report)

    output_path = project_root / "reports" / "soc2_assessment_report.json"
    output_path.parent.mkdir(exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(assessment, file, indent=2)

    print(json.dumps(assessment, indent=2))
    print(f"\nAssessment report saved to: {output_path}")


if __name__ == "__main__":
    main()
