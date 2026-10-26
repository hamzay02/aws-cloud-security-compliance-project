
import pytest

from src.cloudtrail_analyzer import analyze_cloudtrail_events


def test_detects_cloudtrail_logging_stopped():
    events = [{"eventName": "StopLogging"}]

    findings = analyze_cloudtrail_events(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CT-001"
    assert findings[0]["severity"] == "HIGH"


def test_detects_access_key_creation():
    events = [{"eventName": "CreateAccessKey"}]

    findings = analyze_cloudtrail_events(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CT-002"


def test_ignores_unmatched_event():
    assert analyze_cloudtrail_events(
        [{"eventName": "DescribeInstances"}]
    ) == []


def test_detects_multiple_security_relevant_events():
    events = [
        {"eventName": "StopLogging"},
        {"eventName": "CreateAccessKey"},
    ]

    findings = analyze_cloudtrail_events(events)

    assert len(findings) == 2
    assert {f["rule_id"] for f in findings} == {"CT-001", "CT-002"}


def test_detects_failed_console_login():
    events = [
        {
            "eventName": "ConsoleLogin",
            "additionalEventData": {"LoginTo": "Failure"},
            "sourceIPAddress": "192.0.2.10",
        }
    ]

    findings = analyze_cloudtrail_events(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CT-003"
    assert findings[0]["severity"] == "MEDIUM"


def test_ignores_successful_console_login():
    events = [
        {
            "eventName": "ConsoleLogin",
            "additionalEventData": {"LoginTo": "Success"},
        }
    ]

    assert analyze_cloudtrail_events(events) == []


def test_detects_security_group_ingress_change():
    events = [{"eventName": "AuthorizeSecurityGroupIngress"}]

    findings = analyze_cloudtrail_events(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CT-004"


@pytest.mark.parametrize("events", [None, {}, "invalid", 123])
def test_rejects_non_list_events(events):
    with pytest.raises(ValueError):
        analyze_cloudtrail_events(events)


@pytest.mark.parametrize("event", [None, [], "invalid", 123])
def test_rejects_non_object_event(event):
    with pytest.raises(ValueError):
        analyze_cloudtrail_events([event])
