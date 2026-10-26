import json
from pathlib import Path


REQUIRED_FIELDS = {
    "evidence_id",
    "control_id",
    "evidence_type",
    "source",
    "description",
    "collection_date",
    "review_status",
    "reviewer_notes",
}


def track_evidence(evidence_records: list[dict]) -> dict:
    """Validate evidence records and summarize their review statuses."""
    validated_records = []

    for index, record in enumerate(evidence_records, start=1):
        missing_fields = REQUIRED_FIELDS - record.keys()

        if missing_fields:
            raise ValueError(
                f"Evidence record {index} is missing required fields: "
                f"{', '.join(sorted(missing_fields))}"
            )

        validated_records.append(record)

    status_summary = {}
    for record in validated_records:
        status = record["review_status"]
        status_summary[status] = status_summary.get(status, 0) + 1

    return {
        "total_evidence_records": len(validated_records),
        "review_status_summary": status_summary,
        "evidence_records": validated_records,
        "note": (
            "Evidence records are illustrative. Their presence does not "
            "establish that a SOC 2 control is designed effectively or operating effectively."
        ),
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    evidence_path = project_root / "sample_data" / "soc2_evidence.json"

    with evidence_path.open("r", encoding="utf-8-sig") as evidence_file:
        evidence_records = json.load(evidence_file)

    report = track_evidence(evidence_records)

    output_path = project_root / "reports" / "soc2_evidence_report.json"
    output_path.parent.mkdir(exist_ok=True)

    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\nEvidence report saved to: {output_path}")


if __name__ == "__main__":
    main()
