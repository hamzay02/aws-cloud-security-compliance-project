
import pytest

from src.soc2_evidence_tracker import track_evidence


def sample_evidence():
    return {
        "evidence_id": "EVD-001",
        "control_id": "CC6.1",
        "evidence_type": "IAM policy review",
        "source": "sample_data/iam_policy_wildcard.json",
        "description": "Simulated IAM policy review.",
        "collection_date": "2026-10-26",
        "review_status": "PENDING_REVIEW",
        "reviewer_notes": "Review the permissions.",
    }


def test_tracks_valid_evidence_record():
    result = track_evidence([sample_evidence()])

    assert result["total_evidence_records"] == 1
    assert result["review_status_summary"] == {"PENDING_REVIEW": 1}
    assert result["remediation_status_summary"] == {"NOT_STARTED": 1}

    record = result["evidence_records"][0]
    assert record["remediation_status"] == "NOT_STARTED"
    assert record["remediation_owner"] == "UNASSIGNED"
    assert record["remediation_due_date"] == ""


def test_rejects_evidence_missing_required_fields():
    evidence = sample_evidence()
    del evidence["control_id"]

    with pytest.raises(ValueError, match="control_id"):
        track_evidence([evidence])


def test_summarizes_multiple_review_statuses():
    pending = sample_evidence()
    reviewed = sample_evidence()
    reviewed["evidence_id"] = "EVD-002"
    reviewed["review_status"] = "REVIEWED"

    result = track_evidence([pending, reviewed])

    assert result["total_evidence_records"] == 2
    assert result["review_status_summary"] == {
        "PENDING_REVIEW": 1,
        "REVIEWED": 1,
    }


def test_accepts_empty_evidence_list():
    result = track_evidence([])

    assert result["total_evidence_records"] == 0
    assert result["review_status_summary"] == {}
    assert result["remediation_status_summary"] == {}


def test_rejects_duplicate_evidence_ids():
    first = sample_evidence()
    second = sample_evidence()

    with pytest.raises(ValueError, match="evidence_id"):
        track_evidence([first, second])


def test_rejects_invalid_review_status():
    evidence = sample_evidence()
    evidence["review_status"] = "APPROVED"

    with pytest.raises(ValueError, match="review_status"):
        track_evidence([evidence])


def test_rejects_invalid_collection_date():
    evidence = sample_evidence()
    evidence["collection_date"] = "not-a-date"

    with pytest.raises(ValueError, match="collection_date"):
        track_evidence([evidence])


def test_tracks_remediation_fields():
    evidence = sample_evidence()
    evidence["remediation_status"] = "IN_PROGRESS"
    evidence["remediation_owner"] = "Security Team"
    evidence["remediation_due_date"] = "2026-11-15"

    result = track_evidence([evidence])

    assert result["remediation_status_summary"] == {"IN_PROGRESS": 1}
    assert result["evidence_records"][0]["remediation_owner"] == "Security Team"
    assert result["evidence_records"][0]["remediation_due_date"] == "2026-11-15"


def test_rejects_invalid_remediation_status():
    evidence = sample_evidence()
    evidence["remediation_status"] = "STARTED"

    with pytest.raises(ValueError, match="remediation_status"):
        track_evidence([evidence])


def test_rejects_invalid_remediation_due_date():
    evidence = sample_evidence()
    evidence["remediation_due_date"] = "next Friday"

    with pytest.raises(ValueError, match="remediation_due_date"):
        track_evidence([evidence])
