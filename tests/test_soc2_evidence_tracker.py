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
