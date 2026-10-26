
def analyze_cloud_config(resources: list[dict]) -> list[dict]:
    """Check simulated cloud resources for selected configuration risks."""
    if not isinstance(resources, list):
        raise ValueError("Cloud configuration must be a JSON list.")

    findings = []

    for index, resource in enumerate(resources, start=1):
        if not isinstance(resource, dict):
            raise ValueError(
                f"Cloud resource {index} must be a JSON object."
            )

        resource_id = resource.get("resource_id")
        resource_type = resource.get("resource_type")

        if not isinstance(resource_id, str) or not resource_id.strip():
            raise ValueError(
                f"Cloud resource {index} requires a non-empty resource_id."
            )

        if not isinstance(resource_type, str):
            raise ValueError(
                f"Cloud resource {index} requires a resource_type string."
            )

        def add_finding(rule_id, title, severity, evidence, remediation):
            findings.append({
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "evidence": f"Resource '{resource_id}': {evidence}",
                "remediation": remediation,
            })

        if resource_type == "storage_bucket":
            public_access = resource.get("public_access")
            encryption_enabled = resource.get("encryption_enabled")

            if not isinstance(public_access, bool):
                raise ValueError(
                    f"Resource '{resource_id}': public_access must be true or false."
                )

            if not isinstance(encryption_enabled, bool):
                raise ValueError(
                    f"Resource '{resource_id}': encryption_enabled must be true or false."
                )

            if public_access:
                add_finding(
                    "CFG-001",
                    "Storage bucket allows public access",
                    "HIGH",
                    "public_access is enabled.",
                    "Disable public access unless explicitly required and approved. "
                    "Review bucket policies and public access settings.",
                )

            if not encryption_enabled:
                add_finding(
                    "CFG-003",
                    "Storage encryption is not enabled",
                    "HIGH",
                    "encryption_enabled is false.",
                    "Enable appropriate encryption at rest and verify the "
                    "organization's encryption requirements.",
                )

        elif resource_type == "security_group":
            rules = resource.get("ingress_rules")
            if not isinstance(rules, list):
                raise ValueError(
                    f"Resource '{resource_id}': ingress_rules must be a list."
                )

            for rule_index, rule in enumerate(rules, start=1):
                if not isinstance(rule, dict):
                    raise ValueError(
                        f"Resource '{resource_id}': ingress rule {rule_index} "
                        "must be a JSON object."
                    )

                source = rule.get("source_cidr")
                port = rule.get("port")

                if not isinstance(source, str):
                    raise ValueError(
                        f"Resource '{resource_id}': ingress rule {rule_index} "
                        "requires a source_cidr string."
                    )

                if isinstance(port, bool) or not isinstance(port, int):
                    raise ValueError(
                        f"Resource '{resource_id}': ingress rule {rule_index} "
                        "requires an integer port."
                    )

                if not 1 <= port <= 65535:
                    raise ValueError(
                        f"Resource '{resource_id}': ingress rule {rule_index} "
                        "port must be between 1 and 65535."
                    )

                if source == "0.0.0.0/0" and port in {
                    22, 3389, 3306, 5432, 1433, 27017
                }:
                    add_finding(
                        "CFG-002",
                        "Sensitive port open to the internet",
                        "HIGH",
                        f"Port {port} allows ingress from 0.0.0.0/0.",
                        "Restrict the source CIDR to trusted addresses or "
                        "approved networks and verify that the port is required.",
                    )

    return findings
