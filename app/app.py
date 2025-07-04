import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from phishing.detector import PhishingDetector
from threat_intel.feeds import ThreatIntel

app = Flask(__name__, template_folder='templates')
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize core components
phishing_detector = PhishingDetector()
threat_intel = ThreatIntel()


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about_html():
    return render_template('about.html')

@app.route('/contact')
def contact_html():
    return render_template('contact.html')

@app.route('/dashboard')
def dashboard_html():
    return render_template('dashboard.html')

@app.route('/start')
def start_html():
    return render_template('start.html')

@app.route('/features')
def features_html():
    return render_template('features.html')

# API routes
@app.route("/api/phishing", methods=["POST"])
def detect_phishing():
    data = request.get_json()
    email_text = data.get("text")

    if not email_text:
        return jsonify({"error": "Missing 'text' in request"}), 400

    try:
        result = phishing_detector.detect(email_text)
        return jsonify({
            "message": "Phishing scan completed",
            "result": result
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/threat-intel/<ip_address>", methods=["GET"])
def threat_lookup_get(ip_address):
    try:
        result = threat_intel.get_threat_report(ip_address)

        human_friendly = {
            "IP Address": ip_address,
            "Location": f"{result['shodan'].get('city', 'Unknown')}, {result['shodan'].get('country', 'Unknown')}",
            "ASN": result['shodan'].get("asn", "N/A"),
            "Domains": ", ".join(result['shodan'].get("domains", [])) or "None",
            "Services Found": ", ".join(result['shodan'].get("services", [])) or "None",
            "Redirects": result['shodan'].get("redirects_to") or "None",
            "VirusTotal": {
                "Reputation Score": result["virustotal"].get("reputation", "N/A"),
                "Harmless": result["virustotal"].get("harmless", 0),
                "Malicious": result["virustotal"].get("malicious", 0),
                "Suspicious": result["virustotal"].get("suspicious", 0),
                "Undetected": result["virustotal"].get("undetected", 0)
            }
        }

        return jsonify({
            "message": "Threat intelligence retrieved successfully",
            "report": human_friendly
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
if __name__ == '__main__':
    app.run(debug=True)
