\# Project Architecture



\## Project Structure



```text

aws-cloud-security-compliance-project/

|-- .github/

|   |-- workflows/

|   |   |-- tests.yml

|-- reports/

|   |-- security\_report.json

|   |-- security\_summary.md

|   |-- soc2\_assessment\_report.json

|   |-- soc2\_evidence\_report.json

|   |-- soc2\_mapping\_report.json

|-- sample\_data/

|   |-- cloud\_config.json

|   |-- cloudtrail\_events.json

|   |-- iam\_policy\_restricted.json

|   |-- iam\_policy\_wildcard.json

|   |-- soc2\_controls.json

|   |-- soc2\_evidence.json

|-- src/

|   |-- cloud\_config\_analyzer.py

|   |-- cloudtrail\_analyzer.py

|   |-- iam\_analyzer.py

|   |-- report\_generator.py

|   |-- run\_all.py

|   |-- soc2\_assessment.py

|   |-- soc2\_evidence\_tracker.py

|   |-- soc2\_mapper.py

|-- tests/

|-- .gitignore

|-- README.md

|-- requirements.txt

```



\## Folder and File Overview



\### `.github/workflows/`

Contains the GitHub Actions workflow (`tests.yml`) that automatically runs the test suite when changes are pushed or pull requests are opened.



\### `reports/`

Stores the generated security and compliance-support reports.



\- `security\_report.json` — Combined security findings in JSON format.

\- `security\_summary.md` — Human-readable summary of security findings.

\- `soc2\_assessment\_report.json` — Summary of control assessments and related evidence.

\- `soc2\_evidence\_report.json` — Evidence records and their review or remediation status.

\- `soc2\_mapping\_report.json` — Maps selected security findings to preliminary SOC 2 control references.



\### `sample\_data/`

Contains simulated JSON data used to test the project without connecting to a live AWS account.



\- `cloud\_config.json` — Sample cloud resource configuration.

\- `cloudtrail\_events.json` — Simulated AWS CloudTrail events.

\- `iam\_policy\_restricted.json` — Example IAM policy with restricted permissions.

\- `iam\_policy\_wildcard.json` — Example IAM policy containing wildcard permissions.

\- `soc2\_controls.json` — Sample SOC 2 control references.

\- `soc2\_evidence.json` — Sample evidence records for tracking and review.



\### `src/`

Contains the Python source code that performs the analysis and generates reports.



\- `cloud\_config\_analyzer.py` — Checks selected cloud configuration risks.

\- `cloudtrail\_analyzer.py` — Identifies selected security-relevant CloudTrail events.

\- `iam\_analyzer.py` — Detects selected risky IAM policy patterns.

\- `report\_generator.py` — Combines security findings and generates reports.

\- `run\_all.py` — Runs the complete analysis and reporting workflow.

\- `soc2\_assessment.py` — Produces the SOC 2 assessment report.

\- `soc2\_evidence\_tracker.py` — Validates and tracks evidence and remediation status.

\- `soc2\_mapper.py` — Maps selected findings to SOC 2 control references.



\### `tests/`

Contains automated pytest tests that verify detection rules, input validation, evidence tracking, and report generation.



\### Root Files



\- `.gitignore` — Excludes files that should not be tracked by Git, such as virtual environments and Python cache files.

\- `README.md` — Explains the project, setup instructions, usage, and limitations.

\- `requirements.txt` — Lists the Python dependencies needed to run the project.



\## How It Works



The project loads simulated JSON data, analyzes it for selected security risks, generates security reports, maps findings to preliminary SOC 2 controls, and tracks supporting evidence and remediation status. Pytest checks the functionality, while GitHub Actions automates test execution.



\*\*Important:\*\* This project runs locally with simulated data. It does not connect to AWS, inspect live cloud resources, or certify SOC 2 compliance.
