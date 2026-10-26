from src.cloudtrail_analyzer import analyze_cloudtrail_events


def test_detects_cloudtrail_logging_stopped():
    events = [
        {
            "eventName": "StopLogging",
            "eventTime": "2026-10-25T14:35:00Z",
            "sourceIPAddress": "203.0.113.25",
            "userIdentity": {"userName": "sample-user"},
        }
    ]

    findings = analyze_cloudtrail_events(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CT-001"
    assert findings[0]["severity"] == "HIGH"


def test_detects_access_key_creation():
    events = [
        {
            "eventName": "CreateAccessKey",
            "eventTime": "2026-10-25T14:30:00Z",
            "sourceIPAddress": "203.0.113.25",
            "userIdentity": {"userName": "sample-user"},
        }
    ]

    findings = analyze_cloudtrail_events(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CT-002"
    assert findings[0]["severity"] == "MEDIUM"


def test_ignores_unmatched_event():
    events = [
        {
            "eventName": "DescribeInstances",
            "userIdentity": {"userName": "sample-user"},
        }
    ]

    findings = analyze_cloudtrail_events(events)

    assert findings == []


def test_detects_multiple_security_relevant_events():
    events = [
        {"eventName": "CreateAccessKey"},
        {"eventName": "StopLogging"},
    ]

    findings = analyze_cloudtrail_events(events)

    assert len(findings) == 2
    assert {finding["rule_id"] for finding in findings} == {
        "CT-001",
        "CT-002",
    }
