import pytest

from src.soc2_assessment import build_assessment


def sample_control():
    return {
        "control_id": "CC6.1",
        "control_name": "Logical and physical access controls",
        "related_findings": [
            {
                "rule_id": "IAM-001",
                "title": "Overly permissive IAM policy",
                "severity": "HIGH",
                "evidence": "All actions are allowed on all resources.",
                "remediation": "Apply least privilege.",
            }
        ],
        "assessment_note": "Preliminary mapping.",
        "assessment_status": "REVIEW_REQUIRED",
    }


def sample_evidence():
    return {
        "evidence_id": "EVD-001",
        "control_id": "CC6.1",
        "evidence_type": "IAM policy review",
        "source": "sample_data/iam_policy_wildcard.json",
        "description": "Simulated policy review.",
        "collection_date": "2026-10-26",
        "review_status": "PENDING_REVIEW",
        "reviewer_notes": "Review permissions.",
    }


def test_assessment_includes_related_evidence():
    result = build_assessment(
        [sample_control()],
        {"evidence_records": [sample_evidence()]},
    )

    control = result["controls"][0]
    assert result["total_controls_reviewed"] == 1
    assert control["evidence_count"] == 1
    assert control["pending_evidence_reviews"] == 1


def test_assessment_handles_control_without_evidence():
    result = build_assessment(
        [sample_control()],
        {"evidence_records": []},
    )

    control = result["controls"][0]
    assert control["evidence_count"] == 0
    assert control["pending_evidence_reviews"] == 0
    assert control["assessment_status"] == "REVIEW_REQUIRED"


def test_assessment_excludes_evidence_for_other_controls():
    unrelated = sample_evidence()
    unrelated["control_id"] = "CC7.2"

    result = build_assessment(
        [sample_control()],
        {"evidence_records": [unrelated]},
    )

    assert result["controls"][0]["evidence_count"] == 0


def test_assessment_includes_disclaimer():
    result = build_assessment(
        [sample_control()],
        {"evidence_records": []},
    )

    assert "does not establish SOC 2 compliance" in result["disclaimer"]
