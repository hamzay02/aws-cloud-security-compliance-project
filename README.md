\# AWS Cloud Security \& Compliance Automation



A Python-based portfolio project that analyzes simulated AWS security data, identifies potential risks, maps findings to preliminary SOC 2 control references, and tracks supporting evidence for review.



\## Project Overview



This project demonstrates practical skills in Python, cloud security analysis, compliance-support workflows, evidence documentation, and automated testing. It runs locally using simulated data and does not require deploying resources to AWS.



\## Features



\- \*\*IAM Policy Analysis:\*\* Detects selected overly permissive IAM policy patterns, including wildcard actions and resources.

\- \*\*CloudTrail Event Analysis:\*\* Flags selected security-relevant events, including stopped logging and IAM access key creation.

\- \*\*Security Reporting:\*\* Generates JSON reports containing findings, severity summaries, and remediation guidance.

\- \*\*SOC 2 Control Mapping:\*\* Maps selected security findings to preliminary SOC 2 control references, including CC6.1 and CC7.2.

\- \*\*Evidence Tracking:\*\* Records evidence sources, collection dates, review statuses, and reviewer notes.

\- \*\*Assessment Reporting:\*\* Combines control mappings and evidence records into an assessment report for review.

\- \*\*Automated Testing:\*\* Uses pytest to validate detection rules, evidence tracking, report generation, and workflow functionality.

\- \*\*Continuous Integration:\*\* Uses GitHub Actions to run automated tests on pushes and pull requests.

\- \*\*Cost-Conscious Execution:\*\* Uses simulated input data and runs locally without requiring paid AWS resources.



\## Technologies



\- Python

\- pytest

\- JSON

\- Git and GitHub

\- GitHub Actions



\## Project Structure



```text

aws-cloud-security-compliance-project/

├── .github/

│   └── workflows/

│       └── tests.yml

├── reports/

│   ├── security\_report.json

│   ├── soc2\_assessment\_report.json

│   ├── soc2\_evidence\_report.json

│   └── soc2\_mapping\_report.json

├── sample\_data/

│   ├── cloudtrail\_events.json

│   ├── iam\_policy\_restricted.json

│   ├── iam\_policy\_wildcard.json

│   ├── soc2\_controls.json

│   └── soc2\_evidence.json

├── src/

│   ├── cloudtrail\_analyzer.py

│   ├── iam\_analyzer.py

│   ├── report\_generator.py

│   ├── run\_all.py

│   ├── soc2\_assessment.py

│   ├── soc2\_evidence\_tracker.py

│   └── soc2\_mapper.py

├── tests/

├── .gitignore

├── README.md

└── requirements.txt

```



\## Getting Started



\### 1. Set Up the Environment



Install Python and Git, then clone the repository:



```powershell

git clone https://github.com/hamzay02/aws-cloud-security-compliance-project.git

cd aws-cloud-security-compliance-project

```



Create and activate a virtual environment in PowerShell:



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

```



Install the project dependency:



```powershell

python -m pip install -r requirements.txt

```



\### 2. Run the Workflow



From the project root, run:



```powershell

python -m src.run\_all

```



The workflow analyzes the sample data and generates JSON reports in the `reports/` directory.



\### 3. Run the Tests



```powershell

python -m pytest -v

```



The project has 23 local automated tests. GitHub Actions is configured to run the test suite automatically when changes are pushed or pull requests are opened.



\## Sample Results



The included simulated dataset currently produces:



\- \*\*3 security findings\*\*

\- \*\*2 controls requiring review\*\*

\- \*\*2 evidence records pending review\*\*



These results describe the sample dataset only. They do not represent findings from a live AWS environment.



\## Limitations



\- Detection rules cover selected patterns and do not replace comprehensive AWS IAM policy evaluation or a full security assessment.

\- CloudTrail events and IAM policies are simulated rather than collected from a live AWS account.

\- SOC 2 control mappings are preliminary examples and require validation against applicable criteria and organizational control design.

\- Evidence records and generated reports do not establish SOC 2 compliance, control effectiveness, or completion of a formal audit.



\## Future Improvements



\- Expand detection rules and validation for malformed or unexpected input.

\- Add tests for invalid JSON and unsupported input structures.

\- Improve evidence review workflows and remediation tracking.

\- Add Markdown summaries to make security findings easier to review.



\## Disclaimer



This is an educational portfolio project that uses simulated data. It is not an official compliance tool, does not constitute a formal security audit, and does not provide a SOC 2 attestation.



