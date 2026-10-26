from src.iam_analyzer import analyze_iam_policy


def test_detects_wildcard_actions_and_resources():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
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

    findings = analyze_iam_policy(policy)

    assert findings == []


def test_does_not_flag_deny_statement():
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }

    findings = analyze_iam_policy(policy)

    assert findings == []


def test_detects_risky_statement_among_multiple_statements():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
            },
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
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
