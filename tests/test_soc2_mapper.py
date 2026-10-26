from src.soc2_mapper import map_findings_to_controls


def test_maps_iam_finding_to_access_control():
    findings = [
        {
            "rule_id": "IAM-001",
            "title": "Overly permissive IAM policy",
            "severity": "HIGH",
            "evidence": "All actions on all resources.",
            "remediation": "Apply least privilege.",
        }
    ]
    controls = [
        {
            "control_id": "CC6.1",
            "control_name": "Logical and physical access controls",
            "description": "Access control review.",
            "relevant_finding_rules": ["IAM-001", "CT-002"],
            "assessment_note": "Validate applicability.",
        }
    ]

    result = map_findings_to_controls(findings, controls)

    assert len(result) == 1
    assert result[0]["control_id"] == "CC6.1"
    assert result[0]["related_findings"][0]["rule_id"] == "IAM-001"
    assert result[0]["assessment_status"] == "REVIEW_REQUIRED"


def test_ignores_controls_without_matching_findings():
    findings = [
        {
            "rule_id": "CT-001",
            "title": "CloudTrail logging stopped",
            "severity": "HIGH",
            "evidence": "Logging was stopped.",
            "remediation": "Review and restore logging.",
        }
    ]
    controls = [
        {
            "control_id": "CC6.1",
            "control_name": "Access controls",
            "description": "Access control review.",
            "relevant_finding_rules": ["IAM-001"],
            "assessment_note": "Validate applicability.",
        }
    ]

    result = map_findings_to_controls(findings, controls)

    assert result == []


def test_maps_multiple_findings_to_one_control():
    findings = [
        {
            "rule_id": "IAM-001",
            "title": "Overly permissive IAM policy",
            "severity": "HIGH",
            "evidence": "All actions on all resources.",
            "remediation": "Apply least privilege.",
        },
        {
            "rule_id": "CT-002",
            "title": "IAM access key created",
            "severity": "MEDIUM",
            "evidence": "A key was created.",
            "remediation": "Verify authorization.",
        },
    ]
    controls = [
        {
            "control_id": "CC6.1",
            "control_name": "Access controls",
            "description": "Access control review.",
            "relevant_finding_rules": ["IAM-001", "CT-002"],
            "assessment_note": "Validate applicability.",
        }
    ]

    result = map_findings_to_controls(findings, controls)

    assert len(result) == 1
    assert len(result[0]["related_findings"]) == 2
