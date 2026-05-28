import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from phishing.detector import PhishingDetector
from threat_intel.feeds import ThreatIntel


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

CORS(app, resources={r"/api/*": {"origins": "*"}})


try:
    phishing_detector = PhishingDetector()
    print("Phishing detector loaded successfully.")
except Exception as e:
    phishing_detector = None
    print("Failed to load phishing detector:", e)


try:
    threat_intel = ThreatIntel()
    print("Threat intelligence module loaded successfully.")
except Exception as e:
    threat_intel = None
    print("Failed to load threat intelligence module:", e)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about_html():
    return render_template("about.html")


@app.route("/contact")
def contact_html():
    return render_template("contact.html")


@app.route("/dashboard")
def dashboard_html():
    return render_template("dashboard.html")


@app.route("/start")
def start_html():
    return render_template("start.html")


@app.route("/features")
def features_html():
    return render_template("features.html")


@app.route("/api/phishing", methods=["POST"])
def detect_phishing():
    if phishing_detector is None:
        return jsonify({
            "error": "Phishing model is not loaded. Train the model first."
        }), 500

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    email_text = data.get("text", "").strip()

    if not email_text:
        return jsonify({"error": "Missing or empty 'text' field"}), 400

    try:
        result = phishing_detector.detect(email_text)

        return jsonify({
            "message": "Phishing scan completed",
            "result": result
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def clamp_score(score):
    return max(0, min(100, round(score)))


def classify_risk(score):
    if score >= 70:
        return "High Risk"
    elif score >= 35:
        return "Medium Risk"
    else:
        return "Low Risk"


def build_verdict_and_recommendation(risk_level, target_type):
    if risk_level == "High Risk":
        return (
            f"This {target_type} has strong malicious or insecure indicators.",
            f"Block or avoid this {target_type}, and investigate related logs immediately."
        )

    if risk_level == "Medium Risk":
        return (
            f"This {target_type} has suspicious or weak security indicators.",
            f"Use caution, monitor activity, and allow only if the source is trusted."
        )

    return (
        f"No strong malicious indicators were detected for this {target_type}.",
        "No immediate action required, but normal monitoring is recommended."
    )


def calculate_ip_risk(vt_data, shodan_data):
    malicious = vt_data.get("malicious", 0) or 0
    suspicious = vt_data.get("suspicious", 0) or 0
    reputation = vt_data.get("reputation", 0) or 0

    services = shodan_data.get("services", [])
    domains = shodan_data.get("domains", [])

    if not isinstance(services, list):
        services = []

    if not isinstance(domains, list):
        domains = []

    score = 0

    score += malicious * 18
    score += suspicious * 10

    if isinstance(reputation, int) and reputation < 0:
        score += min(abs(reputation) * 2, 30)

    score += min(len(services) * 3, 20)
    score += min(len(domains) * 1.5, 10)

    if shodan_data.get("error"):
        score += 5

    score = clamp_score(score)

    return score, classify_risk(score)


def calculate_website_risk(domain_data, url_data, ip_report, security_headers):
    score = 0

    domain_malicious = domain_data.get("malicious", 0) or 0
    domain_suspicious = domain_data.get("suspicious", 0) or 0
    domain_reputation = domain_data.get("reputation", 0) or 0

    url_malicious = url_data.get("malicious", 0) or 0
    url_suspicious = url_data.get("suspicious", 0) or 0

    ip_vt = ip_report.get("virustotal", {})
    ip_shodan = ip_report.get("shodan", {})

    ip_malicious = ip_vt.get("malicious", 0) or 0
    ip_suspicious = ip_vt.get("suspicious", 0) or 0
    ip_reputation = ip_vt.get("reputation", 0) or 0

    services = ip_shodan.get("services", [])
    if not isinstance(services, list):
        services = []

    missing_headers = security_headers.get("missing_headers", [])
    if not isinstance(missing_headers, list):
        missing_headers = []

    score += domain_malicious * 20
    score += domain_suspicious * 12

    if isinstance(domain_reputation, int) and domain_reputation < 0:
        score += min(abs(domain_reputation) * 2, 25)

    score += url_malicious * 22
    score += url_suspicious * 12

    score += ip_malicious * 12
    score += ip_suspicious * 7

    if isinstance(ip_reputation, int) and ip_reputation < 0:
        score += min(abs(ip_reputation), 20)

    score += min(len(services) * 2, 15)

    if not security_headers.get("https_used"):
        score += 18

    score += min(len(missing_headers) * 5, 30)

    status_code = security_headers.get("status_code")

    if status_code and status_code >= 500:
        score += 10

    server = str(security_headers.get("server", "")).lower()

    if server and server != "unknown":
        score += 3

    if security_headers.get("error"):
        score += 5

    if domain_data.get("error"):
        score += 5

    if url_data.get("error"):
        score += 5

    score = clamp_score(score)

    return score, classify_risk(score)


def build_ip_report(ip_address, result):
    shodan_data = result.get("shodan", {})
    vt_data = result.get("virustotal", {})

    harmless = vt_data.get("harmless", 0) or 0
    malicious = vt_data.get("malicious", 0) or 0
    suspicious = vt_data.get("suspicious", 0) or 0
    undetected = vt_data.get("undetected", 0) or 0
    reputation = vt_data.get("reputation", 0) or 0

    services = shodan_data.get("services", [])
    domains = shodan_data.get("domains", [])

    if not isinstance(services, list):
        services = []

    if not isinstance(domains, list):
        domains = []

    risk_score, risk_level = calculate_ip_risk(vt_data, shodan_data)
    verdict, recommendation = build_verdict_and_recommendation(risk_level, "IP address")

    return {
        "ip": ip_address,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "verdict": verdict,
        "recommendation": recommendation,

        "risk_breakdown": {
            "malicious_weight": malicious * 18,
            "suspicious_weight": suspicious * 10,
            "negative_reputation_used": reputation if isinstance(reputation, int) and reputation < 0 else 0,
            "exposed_services": len(services),
            "linked_domains": len(domains)
        },

        "virustotal": {
            "reputation": reputation,
            "harmless": harmless,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "error": vt_data.get("error")
        },

        "shodan": {
            "asn": shodan_data.get("asn", "N/A"),
            "city": shodan_data.get("city", "Unknown"),
            "country": shodan_data.get("country", "Unknown"),
            "location": f"{shodan_data.get('city', 'Unknown')}, {shodan_data.get('country', 'Unknown')}",
            "services": services,
            "domains": domains,
            "redirects_to": shodan_data.get("redirects_to") or "None",
            "error": shodan_data.get("error")
        },

        "action_plan": [
            "Check firewall logs for recent connections from this IP.",
            "Review failed login attempts related to this IP.",
            "Block the IP if malicious or suspicious activity is confirmed.",
            "Continue monitoring using VirusTotal and Shodan intelligence."
        ],

        "errors": {
            "virustotal": vt_data.get("error"),
            "shodan": shodan_data.get("error")
        }
    }


@app.route("/api/threat-intel/<ip_address>", methods=["GET"])
def threat_lookup_get(ip_address):
    if threat_intel is None:
        return jsonify({"error": "Threat intelligence module is not loaded."}), 500

    try:
        ip_address = ip_address.strip().rstrip(".")
        result = threat_intel.get_threat_report(ip_address)
        report = build_ip_report(ip_address, result)

        return jsonify(report), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/site-intel", methods=["POST"])
def site_lookup_post():
    if threat_intel is None:
        return jsonify({"error": "Threat intelligence module is not loaded."}), 500

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    website = data.get("website", "").strip()

    if not website:
        return jsonify({"error": "Missing website/domain field"}), 400

    try:
        raw_report = threat_intel.get_website_report(website)

        domain_data = raw_report.get("domain_report", {}).get("virustotal_domain", {})
        url_data = raw_report.get("url_report", {}).get("virustotal_url", {})
        ip_raw = raw_report.get("ip_report", {})
        security_headers = raw_report.get("security_headers", {})

        ip_report = build_ip_report(
            raw_report.get("resolved_ip"),
            ip_raw
        )

        risk_score, risk_level = calculate_website_risk(
            domain_data,
            url_data,
            ip_report,
            security_headers
        )

        verdict, recommendation = build_verdict_and_recommendation(
            risk_level,
            "website/domain"
        )

        final_report = {
            "website": raw_report.get("input"),
            "normalized_url": raw_report.get("normalized_url"),
            "domain": raw_report.get("domain"),
            "resolved_ip": raw_report.get("resolved_ip"),

            "risk_level": risk_level,
            "risk_score": risk_score,
            "verdict": verdict,
            "recommendation": recommendation,

            "risk_breakdown": {
                "domain_malicious": domain_data.get("malicious", 0),
                "domain_suspicious": domain_data.get("suspicious", 0),
                "url_malicious": url_data.get("malicious", 0),
                "url_suspicious": url_data.get("suspicious", 0),
                "resolved_ip_score": ip_report.get("risk_score"),
                "resolved_ip_level": ip_report.get("risk_level"),
                "missing_security_headers": len(security_headers.get("missing_headers", [])),
                "https_used": security_headers.get("https_used")
            },

            "domain_analysis": {
                "reputation": domain_data.get("reputation", 0),
                "registrar": domain_data.get("registrar", "Unknown"),
                "harmless": domain_data.get("harmless", 0),
                "malicious": domain_data.get("malicious", 0),
                "suspicious": domain_data.get("suspicious", 0),
                "undetected": domain_data.get("undetected", 0),
                "categories": domain_data.get("categories", {}),
                "error": domain_data.get("error")
            },

            "url_analysis": {
                "title": url_data.get("title", "N/A"),
                "final_url": url_data.get("last_final_url", raw_report.get("normalized_url")),
                "harmless": url_data.get("harmless", 0),
                "malicious": url_data.get("malicious", 0),
                "suspicious": url_data.get("suspicious", 0),
                "undetected": url_data.get("undetected", 0),
                "error": url_data.get("error")
            },

            "security_posture": {
                "https_used": security_headers.get("https_used"),
                "status_code": security_headers.get("status_code"),
                "final_url": security_headers.get("final_url"),
                "server": security_headers.get("server"),
                "redirected": security_headers.get("redirected"),
                "missing_headers": security_headers.get("missing_headers", []),
                "present_headers": security_headers.get("present_headers", []),
                "error": security_headers.get("error")
            },

            "ip_analysis": ip_report,

            "action_plan": [
                "Check whether this domain appears in browser history, proxy logs, or firewall logs.",
                "Avoid submitting credentials or downloading files from this website.",
                "Block the domain if malicious, suspicious, or insecure indicators are confirmed.",
                "Monitor DNS requests and outbound connections related to this domain.",
                "Review missing security headers and HTTPS configuration."
            ],

            "errors": {
                "domain": domain_data.get("error"),
                "url": url_data.get("error"),
                "security_headers": security_headers.get("error"),
                "ip": ip_report.get("errors")
            }
        }

        return jsonify(final_report), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )