# 🔍 IP Reputation Checker

A powerful command-line tool to check IP address reputation using **AbuseIPDB** and **VirusTotal** APIs. Get comprehensive threat intelligence data about any IP address with a single command.

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)

## ✨ Features

- 🔎 **Multi-Source Intelligence**: Queries both AbuseIPDB and VirusTotal APIs
- 📊 **Comprehensive Results**: Displays confidence scores, detection rates, ISP information, and more
- 🎯 **Risk Assessment**: Calculates overall risk level (SAFE/LOW/MEDIUM/HIGH/CRITICAL)
- 💾 **Auto-Save**: Saves results to JSON files for later analysis
- 🎨 **Colored Output**: Easy-to-read terminal output with color coding
- ⚙️ **Configurable**: Simple environment variable configuration
- 🚀 **Lightweight**: Minimal dependencies, runs on any Python 3.6+ environment

## 📋 Prerequisites

- Python 3.6 or higher
- API keys from [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/JuttSahib1999/ip-reputation-checker.git
cd ip-reputation-checker


Create a Virtual Environment (Recommended)
bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate


Install Dependencies
bash
pip install -r requirements.txt


Configure API Keys
Create a .env file in the project root:

bash
# .env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
🔑 How to get API keys:

AbuseIPDB: Sign up at abuseipdb.com and get your API key from the dashboard

VirusTotal: Register at virustotal.com and get your API key from your account

🎮 Usage
Command Line Mode
bash
python ip_checker.py 8.8.8.8
Interactive Mode
bash
python ip_checker.py
# Then enter the IP when prompted
Example Output
text
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     IP REPUTATION CHECKER TOOL                               ║
║     Version: 1.0.0                                           ║
║     Created by: Abdul Muqeet Tabraiz                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

[+] Checking IP: 8.8.8.8

[*] Querying AbuseIPDB...
[*] Querying VirusTotal...

============================================================
IP REPUTATION CHECK RESULTS
============================================================

Target IP: 8.8.8.8
Scan Time: 2024-01-15 14:30:25

────────────────────────────────────────────────────────────
ABUSEIPDB RESULTS
────────────────────────────────────────────────────────────
Confidence Score: 0%
Country: US
ISP: Google LLC
Domain: google.com
Usage Type: Search Engine
Total Reports: 0
Last Reported: Never

────────────────────────────────────────────────────────────
VIRUSTOTAL RESULTS
────────────────────────────────────────────────────────────
Detection Rate: 0.0%
Malicious Votes: 0/92
Country: US
Network: 8.8.8.0/24
AS Owner: Google LLC
Reputation Score: 0
Last Analysis: 2024-01-15 12:00:00

============================================================
OVERALL RISK ASSESSMENT
============================================================
Risk Level: SAFE
AbuseIPDB Score: 0%
VirusTotal Detection: 0.0%
============================================================

[✓] Results saved to: results/ip_check_8.8.8.8_20240115_143025.json
📁 Project Structure
text
ip-reputation-checker/
├── ip_checker.py          # Main application
├── requirements.txt       # Python dependencies
├── .env                   # API keys (create this)
├── results/               # JSON results directory
├── README.md             # This file
└── LICENSE               # MIT License
🛠️ Technologies Used
Python 3 - Core programming language

Requests - HTTP client for API calls

python-dotenv - Environment variable management

Colorama - Cross-platform colored terminal output

📝 API Rate Limits
AbuseIPDB: 1000 requests per day (free tier)

VirusTotal: 4 requests per minute (public API)

💡 Tip: The tool includes a 1-second delay between API calls to respect rate limits.

🎯 Use Cases
Security Analysts: Quickly assess IP reputation during threat hunting

System Administrators: Investigate suspicious connections

Penetration Testers: Reconnaissance and threat intelligence gathering

SOC Teams: Enrich security alerts with IP reputation data

Network Engineers: Verify IP addresses before whitelisting/blacklisting

🤝 Contributing
Contributions are welcome! Here's how you can help:

Fork the repository

Create a feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

Development Setup
bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/


📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

👤 Author
Abdul Muqeet Tabraiz

GitHub: @JuttSahib1999

LinkedIn: Abdul Muqeet Tabraiz


🙏 Acknowledgments
AbuseIPDB for their threat intelligence API

VirusTotal for their comprehensive malware detection

All open-source contributors who make tools like this possible

📊 Roadmap
Add more threat intelligence providers (IPInfo, Shodan, GreyNoise)

Implement batch IP checking from file

Add CSV/Excel export functionality

Create web interface using Flask/FastAPI

Add email report generation

Implement caching mechanism to reduce API calls

Add proxy support

Create Docker container

⭐ Star History
https://api.star-history.com/svg?repos=JuttSahib1999/ip-reputation-checker&type=Date

❤️ Support
If you find this tool useful, please give it a ⭐ on GitHub!

For questions, suggestions, or support, please open an issue on GitHub.

⚠️ Disclaimer
This tool is for educational and professional security assessment purposes only. Always ensure you have proper authorization before scanning IP addresses. The author is not responsible for any misuse of this tool.

Made with ❤️ by Abdul Muqeet Tabraiz
