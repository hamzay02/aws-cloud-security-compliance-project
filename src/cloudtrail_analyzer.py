
import argparse
import json
from pathlib import Path
from typing import Any


RULES = {
    "StopLogging": {
        "rule_id": "CT-001",
        "title": "CloudTrail logging stopped",
        "severity": "HIGH",
        "remediation": (
            "Verify whether the change was authorized and restore "
            "CloudTrail logging if it was stopped unexpectedly."
        ),
    },
    "CreateAccessKey": {
        "rule_id": "CT-002",
        "title": "IAM access key created",
        "severity": "MEDIUM",
        "remediation": (
            "Verify that the access key creation was authorized. "
            "Follow organizational procedures for key storage and rotation."
        ),
    },
    "ConsoleLogin": {
        "rule_id": "CT-003",
        "title": "Console login failure recorded",
        "severity": "MEDIUM",
        "remediation": (
            "Review the login result, source IP, and identity context. "
            "Investigate repeated failures and verify whether the activity "
            "was expected."
        ),
    },
    "AuthorizeSecurityGroupIngress": {
        "rule_id": "CT-004",
        "title": "Security group ingress rule changed",
        "severity": "MEDIUM",
        "remediation": (
            "Review the security group change and confirm that exposed ports "
            "and source ranges are required and appropriately restricted."
        ),
    },
}


def analyze_cloudtrail_events(events: list[dict]) -> list[dict]:
    """Identify selected security-relevant CloudTrail event patterns."""
    if not isinstance(events, list):
        raise ValueError("CloudTrail events must be a JSON list.")

    findings = []

    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(f"CloudTrail event {index} must be a JSON object.")

        event_name = event.get("eventName")
        if not isinstance(event_name, str):
            continue

        rule = RULES.get(event_name)
        if rule is None:
            continue

                # ConsoleLogin is flagged only when CloudTrail records a failed login.
        if event_name == "ConsoleLogin":
            response = event.get("responseElements", {})
            if not isinstance(response, dict):
                response = {}

            additional = event.get("additionalEventData", {})
            if not isinstance(additional, dict):
                additional = {}

            login_result = (
                additional.get("LoginTo")
                or response.get("ConsoleLogin")
            )

            if login_result in ("Success", "成功"):
                continue

            if login_result not in ("Failure", "Failed") and not event.get("errorCode"):
                continue

        identity = event.get("userIdentity", {})
        if not isinstance(identity, dict):
            identity = {}

        username = identity.get("userName", "unknown user")
        event_time = event.get("eventTime", "unknown time")
        source_ip = event.get("sourceIPAddress", "unknown IP")

        findings.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "evidence": (
                f"Event '{event_name}' was recorded at {event_time} "
                f"for user '{username}' from IP {source_ip}."
            ),
            "remediation": rule["remediation"],
        })

    return findings


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    default_events = project_root / "sample_data" / "cloudtrail_events.json"

    parser = argparse.ArgumentParser(
        description="Analyze sample CloudTrail events for selected security risks."
    )
    parser.add_argument(
        "--events",
        default=str(default_events),
        help="Path to a JSON file containing a list of CloudTrail events.",
    )
    args = parser.parse_args()

    events_path = Path(args.events)
    if not events_path.is_absolute():
        events_path = project_root / events_path

    try:
        with events_path.open("r", encoding="utf-8-sig") as events_file:
            events: Any = json.load(events_file)

        findings = analyze_cloudtrail_events(events)

    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(f"Unable to analyze CloudTrail events: {error}")

    print(json.dumps(findings, indent=2))
    print(f"\nTotal findings: {len(findings)}")


if __name__ == "__main__":
    main()
