import argparse
import json
from pathlib import Path


def analyze_cloudtrail_events(events: list[dict]) -> list[dict]:
    """Identify selected security-relevant CloudTrail events."""
    findings = []

    rules = {
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
    }

    for event in events:
        event_name = event.get("eventName")
        rule = rules.get(event_name)

        if rule is None:
            continue

        identity = event.get("userIdentity", {})
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

    with events_path.open("r", encoding="utf-8-sig") as events_file:
        events = json.load(events_file)

    findings = analyze_cloudtrail_events(events)

    print(json.dumps(findings, indent=2))
    print(f"\nTotal findings: {len(findings)}")


if __name__ == "__main__":
    main()
