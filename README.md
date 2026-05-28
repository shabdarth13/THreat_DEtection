🛡 Threat Detection System

An AI-powered cybersecurity platform that combines phishing email detection, IP threat intelligence, website/domain reputation analysis, and website security posture assessment into a single intelligent dashboard.

Developed to provide real-time cyber threat analysis using Machine Learning, NLP, VirusTotal, Shodan, and security configuration analysis.

🚀 Features
📧 AI-Powered Phishing Detection
Detects phishing emails using a fine-tuned DistilBERT NLP model
Analyzes suspicious email text
Returns:
Prediction
Confidence score
Security verdict
🌐 IP Threat Intelligence

Performs real-time intelligence gathering on IP addresses using:

VirusTotal
Malicious detections
Suspicious detections
Reputation score
Harmless detections
Shodan
Exposed services
ASN information
Domains hosted
Geolocation
Redirects
Internet exposure analysis
🔗 Website / Domain Intelligence

Analyzes websites using multiple security layers:

Domain Reputation Analysis
VirusTotal domain intelligence
Reputation scoring
Malicious/suspicious detections
URL Reputation Analysis
URL-level scanning
Redirect analysis
Threat indicators
Website Security Posture Analysis

Checks:

HTTPS usage
Missing security headers
Server exposure
Redirect behavior
HTTP response configuration

Security headers checked:

Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
🧠 Weighted Risk Scoring Engine

The platform generates a normalized 0–100 cyber risk score using:

Malicious detections
Suspicious detections
Reputation score
Exposed services
Domain intelligence
URL intelligence
Missing security headers
HTTPS configuration
Server exposure

Risk Levels:

🟢 Low Risk
🟡 Medium Risk
🔴 High Risk
🖥 Interactive Dashboard

Modern cyber-themed dashboard featuring:

Email phishing scanner
IP intelligence scanner
Website/domain scanner
Risk visualization
Security posture breakdown
Threat analysis cards
Recommendations & action plans


🛠 Technologies Used
Frontend
HTML5
CSS3
JavaScript
Backend
Python
Flask
Flask-CORS
Machine Learning / NLP
PyTorch
HuggingFace Transformers
DistilBERT
Threat Intelligence APIs
VirusTotal API
Shodan API
Additional Libraries
requests
python-dotenv
socket
urllib


📂 Project Structure
THREAT-DETECTION/
│
├── app/
│   ├── app.py
│   │
│   ├── phishing/
│   │   └── detector.py
│   │
│   ├── threat_intel/
│   │   └── feeds.py
│   │
│   ├── models/
│   │   └── bert_spam_classifier/
│   │
│   ├── templates/
│   │   ├── index.html
│   │   ├── dashboard.html
│   │   ├── about.html
│   │   ├── features.html
│   │   ├── contact.html
│   │   └── start.html
│   │
│   ├── .env
│   └── requirements.txt
│
├── data/
│   └── CEAS_08.csv
│
└── README.md
⚙ Installation
1. Clone Repository
git clone https://github.com/your-username/threat-detection.git
cd threat-detection
2. Create Virtual Environment
Windows
python -m venv venv
venv\Scripts\activate
Linux / Mac
python3 -m venv venv
source venv/bin/activate
3. Install Dependencies
pip install -r requirements.txt
🔑 Environment Variables

Create .env inside app/

VT_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key
PHISHING_MODEL_DIR=models\bert_spam_classifier
🧠 Train Phishing Model

Run:

python app/models/train_spam_model.py

This trains and saves the DistilBERT phishing model.

▶ Run Application
cd app
python app.py

Server starts on:

http://127.0.0.1:5000
🔍 Example Use Cases
Email Scan

Input:

Your account has been suspended.
Click here immediately to verify credentials.

Output:

Prediction: Phishing
Confidence: 98%
IP Threat Scan

Input:

8.8.8.8

Checks:

VirusTotal reputation
Shodan exposure
Threat score
Infrastructure analysis
Website Scan

Input:

http://demo.testfire.net

Checks:

Domain reputation
URL intelligence
HTTPS usage
Security headers
Server exposure
Website risk score
🧪 Risk Score Logic

Example weighted scoring:

Risk Score =
(Malicious × Weight)
+ (Suspicious × Weight)
+ Reputation Penalty
+ Missing Header Penalty
+ Exposure Penalty
🔐 Security Concepts Implemented
Threat Intelligence
NLP-based phishing detection
Website hardening analysis
Security header inspection
Domain reputation analysis
Infrastructure reputation analysis
Weighted cyber risk scoring
📈 Future Improvements
Real-time ransomware detection
PDF and attachment malware scanning
Dark web breach intelligence
SIEM integration
Threat feed aggregation
Live traffic monitoring
CVE vulnerability mapping
AI chatbot assistant
Database logging & analytics
Cloud deployment (AWS/GCP)
👨‍💻 Team
CODE FORENSICS
Shabdarth
Shivani Negi
Deepak Tripathi
Piyusha
📜 License

This project is developed for educational and cybersecurity research purposes.

⭐ Final Overview

The Threat Detection System is a multi-layer AI cybersecurity platform capable of:

✅ Detecting phishing emails using NLP
✅ Performing IP threat intelligence analysis
✅ Analyzing websites/domains for cyber threats
✅ Evaluating website security posture
✅ Generating weighted cyber risk scores
✅ Providing actionable security recommendation