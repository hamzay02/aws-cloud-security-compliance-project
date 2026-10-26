\# AWS Cloud Security \& Compliance Automation



A Python-based portfolio project that analyzes sample AWS security data, identifies potential risks, maps findings to preliminary SOC 2 control references, and organizes supporting evidence for review.



\## Project Overview



This project demonstrates practical skills in cloud security analysis, compliance-support workflows, evidence documentation, and automated testing. It uses simulated data and runs locally without requiring deployment to AWS.



\## Features



\- \*\*IAM Policy Analysis:\*\* Detects selected overly permissive IAM policy patterns, including wildcard actions and resources.

\- \*\*CloudTrail Event Analysis:\*\* Flags selected security-relevant events, including stopped logging and IAM access key creation.

\- \*\*Security Reporting:\*\* Combines findings into a JSON report with severity summaries and remediation guidance.

\- \*\*SOC 2 Control Mapping:\*\* Links selected findings to preliminary control references, including CC6.1 and CC7.2.

\- \*\*Evidence Tracking:\*\* Records evidence sources, collection dates, review statuses, and reviewer notes.

\- \*\*Assessment Reporting:\*\* Combines control mappings, findings, and related evidence into a review report.

\- \*\*Automated Testing:\*\* Uses pytest to test detection rules, evidence validation, report generation, and supporting functions.

\- \*\*Local Execution:\*\* Uses simulated input data and does not require paid AWS resources.



\## Technologies



\- Python

\- pytest

\- JSON

\- Git and GitHub Actions (CI workflow planned or implemented, depending on repository status)



\## Project Structure



```text

aws-cloud-security-compliance-project/

├── .github/

│   └── workflows/

├── docs/

├── reports/

├── sample\_data/

├── src/

│   ├── iam\_analyzer.py

│   ├── cloudtrail\_analyzer.py

│   ├── report\_generator.py

│   ├── soc2\_mapper.py

│   ├── soc2\_evidence\_tracker.py

│   ├── soc2\_assessment.py

│   └── run\_all.py

├── tests/

├── .gitignore

└── README.md

```



\## Getting Started



\### 1. Set up the environment



Create and activate a Python virtual environment:



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

```



Install pytest:



python -m pip install -r requirements.txt



\### 2. Run the workflow



From the project root, run:



```powershell

python -m src.run\_all

```



The workflow reads the sample data and generates JSON reports in the `reports/` directory.



\### 3. Run the tests



```powershell

python -m pytest -v

```



\## Sample Outputs



The current simulated dataset produces:



\- 3 security findings

\- 2 controls requiring review

\- 2 evidence records pending review



These counts describe the sample dataset, not a real AWS environment.



\## Limitations



\- Detection rules are intentionally basic and do not replace a full AWS IAM policy evaluation or a comprehensive security assessment.

\- Sample CloudTrail events and IAM policies are simulated, not collected from a live AWS account.

\- SOC 2 control mappings are preliminary examples and must be validated against applicable criteria and organizational control design.

\- Evidence records and generated reports do not establish SOC 2 compliance, control effectiveness, or completion of a formal audit.



\## Future Improvements



\- Expand detection rules and validation for malformed or unexpected input.

\- Add tests for invalid JSON and unsupported input structures.

\- Improve evidence review workflows and remediation tracking.

\- Add a GitHub Actions CI workflow to run tests automatically on pushes and pull requests.

\- Add Markdown summaries for easier report review.



\## Disclaimer



This is an educational portfolio project using simulated data. It is not an official compliance tool and does not provide a SOC 2 attestation.



