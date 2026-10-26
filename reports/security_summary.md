# Security Findings Summary

> This report is generated from simulated project data. It is not a formal security audit or SOC 2 attestation.

## Overview

- **Total findings:** 6

## Findings by severity

| Severity | Count |
|---|---:|
| HIGH | 5 |
| MEDIUM | 1 |

## Finding details

### 1. All actions allowed on all resources

- **Rule:** IAM-001
- **Severity:** HIGH
- **Evidence:** Statement 1 allows all actions on all resources.
- **Recommended remediation:** Apply least privilege by specifying only required actions and resources.

### 2. IAM access key created

- **Rule:** CT-002
- **Severity:** MEDIUM
- **Evidence:** Event 'CreateAccessKey' was recorded at 2026-10-25T14:30:00Z for user 'sample-user' from IP 203.0.113.25.
- **Recommended remediation:** Verify that the access key creation was authorized. Follow organizational procedures for key storage and rotation.

### 3. CloudTrail logging stopped

- **Rule:** CT-001
- **Severity:** HIGH
- **Evidence:** Event 'StopLogging' was recorded at 2026-10-25T14:35:00Z for user 'sample-user' from IP 203.0.113.25.
- **Recommended remediation:** Verify whether the change was authorized and restore CloudTrail logging if it was stopped unexpectedly.

### 4. Storage bucket allows public access

- **Rule:** CFG-001
- **Severity:** HIGH
- **Evidence:** Resource 'sample-public-bucket': public_access is enabled.
- **Recommended remediation:** Disable public access unless explicitly required and approved. Review bucket policies and public access settings.

### 5. Storage encryption is not enabled

- **Rule:** CFG-003
- **Severity:** HIGH
- **Evidence:** Resource 'sample-public-bucket': encryption_enabled is false.
- **Recommended remediation:** Enable appropriate encryption at rest and verify the organization's encryption requirements.

### 6. Sensitive port open to the internet

- **Rule:** CFG-002
- **Severity:** HIGH
- **Evidence:** Resource 'sample-admin-security-group': Port 22 allows ingress from 0.0.0.0/0.
- **Recommended remediation:** Restrict the source CIDR to trusted addresses or approved networks and verify that the port is required.

## Scope and limitations

This summary reflects only the supplied sample inputs and implemented detection rules. Findings require human review; the absence of a finding does not establish that an environment is secure.
