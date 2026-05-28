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