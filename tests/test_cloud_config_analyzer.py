
import pytest

from src.cloud_config_analyzer import analyze_cloud_config


def test_detects_public_bucket_missing_encryption_and_open_ssh():
    resources = [
        {
            "resource_id": "public-bucket",
            "resource_type": "storage_bucket",
            "public_access": True,
            "encryption_enabled": False,
        },
        {
            "resource_id": "admin-security-group",
            "resource_type": "security_group",
            "ingress_rules": [
                {"port": 22, "source_cidr": "0.0.0.0/0"},
                {"port": 443, "source_cidr": "0.0.0.0/0"},
            ],
        },
    ]

    findings = analyze_cloud_config(resources)

    assert {finding["rule_id"] for finding in findings} == {
        "CFG-001",
        "CFG-002",
        "CFG-003",
    }
    assert all(finding["severity"] == "HIGH" for finding in findings)


def test_ignores_secure_storage_and_https_ingress():
    resources = [
        {
            "resource_id": "private-bucket",
            "resource_type": "storage_bucket",
            "public_access": False,
            "encryption_enabled": True,
        },
        {
            "resource_id": "web-security-group",
            "resource_type": "security_group",
            "ingress_rules": [
                {"port": 443, "source_cidr": "0.0.0.0/0"},
            ],
        },
    ]

    assert analyze_cloud_config(resources) == []


@pytest.mark.parametrize("resources", [None, {}, "invalid", 123])
def test_rejects_non_list_configuration(resources):
    with pytest.raises(ValueError):
        analyze_cloud_config(resources)


def test_rejects_non_object_resource():
    with pytest.raises(ValueError, match="must be a JSON object"):
        analyze_cloud_config(["invalid"])


def test_rejects_missing_resource_id():
    with pytest.raises(ValueError, match="resource_id"):
        analyze_cloud_config([
            {
                "resource_type": "storage_bucket",
                "public_access": False,
                "encryption_enabled": True,
            }
        ])


def test_rejects_invalid_storage_boolean():
    with pytest.raises(ValueError, match="public_access"):
        analyze_cloud_config([
            {
                "resource_id": "bucket-1",
                "resource_type": "storage_bucket",
                "public_access": "yes",
                "encryption_enabled": True,
            }
        ])


def test_rejects_invalid_ingress_rules():
    with pytest.raises(ValueError, match="ingress_rules"):
        analyze_cloud_config([
            {
                "resource_id": "sg-1",
                "resource_type": "security_group",
                "ingress_rules": "invalid",
            }
        ])


def test_rejects_invalid_port():
    with pytest.raises(ValueError, match="integer port"):
        analyze_cloud_config([
            {
                "resource_id": "sg-1",
                "resource_type": "security_group",
                "ingress_rules": [
                    {"port": "22", "source_cidr": "0.0.0.0/0"},
                ],
            }
        ])
