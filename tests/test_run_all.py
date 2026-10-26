
import json

import pytest

from src.run_all import (
    generate_markdown_summary,
    load_json,
    save_json,
)


def test_load_json_reads_sample_file(tmp_path):
    sample_file = tmp_path / "sample.json"
    sample_file.write_text('{"status": "ok"}', encoding="utf-8")

    result = load_json(sample_file)

    assert result == {"status": "ok"}


def test_load_json_rejects_invalid_json(tmp_path):
    sample_file = tmp_path / "invalid.json"
    sample_file.write_text("{invalid json}", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        load_json(sample_file)


def test_load_json_raises_for_missing_file(tmp_path):
    missing_file = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        load_json(missing_file)


def test_save_json_writes_report(tmp_path):
    report_path = tmp_path / "reports" / "test_report.json"
    report = {"total_findings": 3, "status": "complete"}

    save_json(report_path, report)

    assert report_path.exists()
    assert load_json(report_path) == report


def test_save_json_creates_missing_directories(tmp_path):
    report_path = tmp_path / "new" / "nested" / "report.json"

    save_json(report_path, {"controls": 2})

    assert report_path.exists()
    assert load_json(report_path) == {"controls": 2}


def test_markdown_summary_includes_totals_and_severity():
    report = {
        "findings": [
            {
                "rule_id": "CFG-001",
                "title": "Public storage bucket",
                "severity": "HIGH",
                "evidence": "Public access is enabled.",
                "remediation": "Disable public access.",
            },
            {
                "rule_id": "CT-002",
                "title": "Access key created",
                "severity": "MEDIUM",
                "evidence": "An access key was created.",
                "remediation": "Verify authorization.",
            },
        ]
    }

    summary = generate_markdown_summary(report)

    assert "**Total findings:** 2" in summary
    assert "| HIGH | 1 |" in summary
    assert "| MEDIUM | 1 |" in summary
    assert "CFG-001" in summary
    assert "Public storage bucket" in summary
    assert "Disable public access." in summary


def test_markdown_summary_handles_no_findings():
    summary = generate_markdown_summary({"findings": []})

    assert "**Total findings:** 0" in summary
    assert "No findings were detected" in summary
    assert "Scope and limitations" in summary
