
import json
from datetime import date
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

ALLOWED_REVIEW_STATUSES = {
    "PENDING_REVIEW",
    "IN_REVIEW",
    "REVIEWED",
    "REJECTED",
}

ALLOWED_REMEDIATION_STATUSES = {
    "NOT_STARTED",
    "IN_PROGRESS",
    "COMPLETED",
    "NOT_REQUIRED",
}


def track_evidence(evidence_records: list[dict]) -> dict:
    """Validate evidence records and summarize review and remediation status."""
    if not isinstance(evidence_records, list):
        raise ValueError("Evidence records must be a JSON list.")

    validated_records = []
    seen_ids = set()

    for index, record in enumerate(evidence_records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"Evidence record {index} must be a JSON object.")

        missing_fields = REQUIRED_FIELDS - record.keys()
        if missing_fields:
            raise ValueError(
                f"Evidence record {index} is missing required fields: "
                f"{', '.join(sorted(missing_fields))}"
            )

        for field in REQUIRED_FIELDS:
            if not isinstance(record[field], str) or not record[field].strip():
                raise ValueError(
                    f"Evidence record {index}: '{field}' must be a non-empty string."
                )

        evidence_id = record["evidence_id"]
        if evidence_id in seen_ids:
            raise ValueError(f"Duplicate evidence_id: {evidence_id}")
        seen_ids.add(evidence_id)

        try:
            date.fromisoformat(record["collection_date"])
        except ValueError as error:
            raise ValueError(
                f"Evidence record {index}: collection_date must use YYYY-MM-DD."
            ) from error

        review_status = record["review_status"]
        if review_status not in ALLOWED_REVIEW_STATUSES:
            raise ValueError(
                f"Evidence record {index}: invalid review_status "
                f"'{review_status}'."
            )

        normalized_record = dict(record)
        normalized_record.setdefault("remediation_status", "NOT_STARTED")
        normalized_record.setdefault("remediation_owner", "UNASSIGNED")
        normalized_record.setdefault("remediation_due_date", "")

        if normalized_record["remediation_status"] not in ALLOWED_REMEDIATION_STATUSES:
            raise ValueError(
                f"Evidence record {index}: invalid remediation_status "
                f"'{normalized_record['remediation_status']}'."
            )

        if not isinstance(normalized_record["remediation_owner"], str):
            raise ValueError(
                f"Evidence record {index}: remediation_owner must be a string."
            )

        due_date = normalized_record["remediation_due_date"]
        if not isinstance(due_date, str):
            raise ValueError(
                f"Evidence record {index}: remediation_due_date must be a string."
            )
        if due_date:
            try:
                date.fromisoformat(due_date)
            except ValueError as error:
                raise ValueError(
                    f"Evidence record {index}: remediation_due_date must use YYYY-MM-DD."
                ) from error

        validated_records.append(normalized_record)

    review_summary = {}
    remediation_summary = {}

    for record in validated_records:
        review_status = record["review_status"]
        review_summary[review_status] = review_summary.get(review_status, 0) + 1

        remediation_status = record["remediation_status"]
        remediation_summary[remediation_status] = (
            remediation_summary.get(remediation_status, 0) + 1
        )

    return {
        "total_evidence_records": len(validated_records),
        "review_status_summary": review_summary,
        "remediation_status_summary": remediation_summary,
        "evidence_records": validated_records,
        "note": (
            "Evidence records are illustrative. Their presence does not "
            "establish that a SOC 2 control is designed effectively or operating effectively."
        ),
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    evidence_path = project_root / "sample_data" / "soc2_evidence.json"

    try:
        with evidence_path.open("r", encoding="utf-8-sig") as evidence_file:
            evidence_records = json.load(evidence_file)

        report = track_evidence(evidence_records)

    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"Unable to track evidence: {error}") from error

    output_path = project_root / "reports" / "soc2_evidence_report.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\nEvidence report saved to: {output_path}")


if __name__ == "__main__":
    main()
