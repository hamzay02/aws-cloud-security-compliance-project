from src.run_all import load_json, save_json


def test_load_json_reads_sample_file(tmp_path):
    sample_file = tmp_path / "sample.json"
    sample_file.write_text('{"status": "ok"}', encoding="utf-8")

    result = load_json(sample_file)

    assert result == {"status": "ok"}


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
