
import pytest

from src.iam_analyzer import analyze_iam_policy


def test_detects_wildcard_actions_and_resources():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ],
    }

    findings = analyze_iam_policy(policy)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-001"
    assert findings[0]["severity"] == "HIGH"


def test_does_not_flag_restricted_s3_policy():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }

    assert analyze_iam_policy(policy) == []


def test_does_not_flag_deny_statement():
    policy = {
        "Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*"}
        ],
    }

    assert analyze_iam_policy(policy) == []


def test_detects_risky_statement_among_multiple_statements():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
            },
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
        ],
    }

    findings = analyze_iam_policy(policy)

    assert len(findings) == 1
    assert "Statement 2" in findings[0]["evidence"]


def test_detects_wildcard_actions_on_specific_resource():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }

    findings = analyze_iam_policy(policy)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-002"
    assert findings[0]["severity"] == "HIGH"


def test_detects_wildcard_resource_scope():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }

    findings = analyze_iam_policy(policy)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-003"
    assert findings[0]["severity"] == "MEDIUM"


def test_flags_allow_statement_using_not_action():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": "iam:CreateAccessKey",
                "Resource": "*",
            }
        ]
    }

    findings = analyze_iam_policy(policy)

    assert any(f["rule_id"] == "IAM-004" for f in findings)


@pytest.mark.parametrize("policy", [None, [], "invalid", 123])
def test_rejects_non_object_policy(policy):
    with pytest.raises(ValueError):
        analyze_iam_policy(policy)


@pytest.mark.parametrize("statement", ["invalid", 123, None])
def test_rejects_invalid_statement_types(statement):
    with pytest.raises(ValueError):
        analyze_iam_policy({"Statement": [statement]})


def test_rejects_invalid_statement_container():
    with pytest.raises(ValueError):
        analyze_iam_policy({"Statement": "invalid"})


def test_rejects_invalid_action_type():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": 123, "Resource": "*"}
        ]
    }

    with pytest.raises(ValueError):
        analyze_iam_policy(policy)


def test_rejects_invalid_resource_type():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": 123,
            }
        ]
    }

    with pytest.raises(ValueError):
        analyze_iam_policy(policy)
