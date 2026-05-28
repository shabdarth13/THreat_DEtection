import os
import socket
import base64
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", ".env"))
load_dotenv(ENV_PATH)


class ThreatIntel:
    def __init__(self):
        self.VT_API_KEY = os.getenv("VT_API_KEY")
        self.SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

    def clean_ip(self, ip_address):
        return ip_address.strip().rstrip(".")

    def normalize_website(self, website):
        website = website.strip()

        if not website.startswith(("http://", "https://")):
            website = "https://" + website

        parsed = urlparse(website)
        domain = parsed.netloc.lower()

        if domain.startswith("www."):
            domain = domain[4:]

        if not domain:
            raise ValueError("Invalid website/domain entered.")

        return website, domain

    def resolve_domain_to_ip(self, domain):
        try:
            return socket.gethostbyname(domain)
        except Exception:
            raise ValueError(f"Could not resolve domain to IP: {domain}")

    def get_security_headers_report(self, website_url):
        required_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        result = {
            "url": website_url,
            "https_used": website_url.startswith("https://"),
            "status_code": None,
            "final_url": website_url,
            "missing_headers": [],
            "present_headers": [],
            "server": "Unknown",
            "redirected": False,
            "error": None
        }

        try:
            response = requests.get(
                website_url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "ThreatDetectionScanner/1.0"}
            )

            result["status_code"] = response.status_code
            result["final_url"] = response.url
            result["redirected"] = response.url != website_url
            result["server"] = response.headers.get("Server", "Unknown")

            for header in required_headers:
                if header in response.headers:
                    result["present_headers"].append(header)
                else:
                    result["missing_headers"].append(header)

        except Exception as e:
            result["error"] = str(e)

        return result

    def get_threat_report(self, ip_address):
        ip_address = self.clean_ip(ip_address)
        result = {"ip": ip_address}

        try:
            if not self.VT_API_KEY:
                raise ValueError("VirusTotal API key not found in .env file.")

            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                headers={"x-apikey": self.VT_API_KEY},
                timeout=10
            )

            response.raise_for_status()

            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})

            result["virustotal"] = {
                "reputation": data.get("reputation", 0),
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0)
            }

        except Exception as e:
            result["virustotal"] = {
                "error": f"VirusTotal error: {str(e)}"
            }

        try:
            if not self.SHODAN_API_KEY:
                raise ValueError("Shodan API key not found in .env file.")

            response = requests.get(
                "https://api.shodan.io/shodan/host/" + ip_address,
                params={"key": self.SHODAN_API_KEY},
                timeout=10
            )

            response.raise_for_status()
            data = response.json()

            services = []
            domains = []
            redirects = None

            for entry in data.get("data", []):
                module = entry.get("module")

                if module:
                    services.append(module)

                for domain in entry.get("domains", []):
                    domains.append(domain)

                raw_data = entry.get("data", "")

                if module and "http" in module and "Location:" in raw_data:
                    for line in raw_data.splitlines():
                        if line.startswith("Location:"):
                            redirects = line.split("Location:", 1)[1].strip()
                            break

            result["shodan"] = {
                "asn": data.get("asn", "N/A"),
                "city": data.get("city", "Unknown"),
                "country": data.get("country_name", "Unknown"),
                "services": list(set(services)),
                "domains": list(set(domains)),
                "redirects_to": redirects
            }

        except Exception as e:
            result["shodan"] = {
                "error": f"Shodan error: {str(e)}"
            }

        return result

    def get_domain_report(self, domain):
        result = {"domain": domain}

        try:
            if not self.VT_API_KEY:
                raise ValueError("VirusTotal API key not found in .env file.")

            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self.VT_API_KEY},
                timeout=10
            )

            response.raise_for_status()

            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})

            result["virustotal_domain"] = {
                "reputation": data.get("reputation", 0),
                "registrar": data.get("registrar", "Unknown"),
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "categories": data.get("categories", {})
            }

        except Exception as e:
            result["virustotal_domain"] = {
                "error": f"VirusTotal domain error: {str(e)}"
            }

        return result

    def get_url_report(self, website_url):
        result = {"url": website_url}

        try:
            if not self.VT_API_KEY:
                raise ValueError("VirusTotal API key not found in .env file.")

            url_id = base64.urlsafe_b64encode(
                website_url.encode()
            ).decode().strip("=")

            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": self.VT_API_KEY},
                timeout=10
            )

            response.raise_for_status()

            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})

            result["virustotal_url"] = {
                "title": data.get("title", "N/A"),
                "last_final_url": data.get("last_final_url", website_url),
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0)
            }

        except Exception as e:
            result["virustotal_url"] = {
                "error": f"VirusTotal URL error: {str(e)}"
            }

        return result

    def get_website_report(self, website):
        normalized_url, domain = self.normalize_website(website)
        resolved_ip = self.resolve_domain_to_ip(domain)

        return {
            "input": website,
            "normalized_url": normalized_url,
            "domain": domain,
            "resolved_ip": resolved_ip,
            "domain_report": self.get_domain_report(domain),
            "url_report": self.get_url_report(normalized_url),
            "ip_report": self.get_threat_report(resolved_ip),
            "security_headers": self.get_security_headers_report(normalized_url)
        }