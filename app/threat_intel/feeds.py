import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class ThreatIntel:
    def __init__(self):
        self.VT_API_KEY = os.getenv("VT_API_KEY")
        self.SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

    def get_threat_report(self, ip_address):
        result = {"ip": ip_address}

        # ------------------ VirusTotal ------------------
        try:
            if not self.VT_API_KEY:
                raise ValueError("VirusTotal API key not found in environment.")

            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            vt_headers = {"x-apikey": self.VT_API_KEY}
            vt_response = requests.get(vt_url, headers=vt_headers)
            vt_response.raise_for_status()
            vt_data = vt_response.json().get("data", {}).get("attributes", {})

            result["virustotal"] = {
                "reputation": vt_data.get("reputation"),
                "harmless": vt_data.get("last_analysis_stats", {}).get("harmless"),
                "malicious": vt_data.get("last_analysis_stats", {}).get("malicious"),
                "suspicious": vt_data.get("last_analysis_stats", {}).get("suspicious"),
                "undetected": vt_data.get("last_analysis_stats", {}).get("undetected"),
            }
        except Exception as e:
            result["virustotal"] = {"error": f"VirusTotal error: {str(e)}"}

        # ------------------ Shodan ------------------
        try:
            if not self.SHODAN_API_KEY:
                raise ValueError("Shodan API key not found in environment.")

            shodan_url = f"https://api.shodan.io/shodan/host/{ip_address}?key={self.SHODAN_API_KEY}"
            shodan_response = requests.get(shodan_url)
            shodan_response.raise_for_status()
            shodan_data = shodan_response.json()

            modules = list({entry.get("module") for entry in shodan_data.get("data", []) if "module" in entry})
            domains = list({domain for entry in shodan_data.get("data", []) for domain in entry.get("domains", [])})
            redirects = None

            for entry in shodan_data.get("data", []):
                if "http" in entry.get("module", "") and "Location:" in entry.get("data", ""):
                    for line in entry["data"].splitlines():
                        if line.startswith("Location:"):
                            redirects = line.split("Location:")[1].strip()
                            break

            result["shodan"] = {
                "asn": shodan_data.get("asn"),
                "city": shodan_data.get("city"),
                "country": shodan_data.get("country_name"),
                "services": modules,
                "domains": domains,
                "redirects_to": redirects
            }
        except Exception as e:
            result["shodan"] = {"error": f"Shodan error: {str(e)}"}

        return result
