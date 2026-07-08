Overview

Explain what the tool does and why it exists.

Features
CSV & JSON log parsing
Rule-based threat detection
Severity classification
MITRE ATT&CK mapping
Risk scoring
Interactive Streamlit dashboard
HTML report generation
PDF report generation
Architecture

Include the architecture diagram image.

Screenshots

Embed all screenshots.

Installation
git clone https://github.com/Ajf45/SOC_Alert_Analyzer.git

cd SOC_Alert_Analyzer

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

streamlit run app.py
Sample Logs

Mention the included sample log files in the logs/ directory.

Technologies
Python
Streamlit
Pandas
Plotly
Jinja2
WeasyPrint
HTML
CSS
Future Enhancements

Examples:

Windows Event Log (.evtx) support
Sigma rule integration
VirusTotal IP enrichment
GeoIP mapping
Email notifications
User authentication
Incident history with SQLite