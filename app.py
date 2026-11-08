import base64
import ipaddress
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # Small JSON requests only.

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
RISKY_TLDS = (".zip", ".mov", ".top", ".xyz", ".click", ".gq", ".tk")
WORDS = {"login", "verify", "update", "password", "account", "billing", "confirm", "wallet", "signin", "urgent", "suspend"}
BRANDS = {"paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook", "instagram", "whatsapp"}


def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a URL to scan.")
    if len(raw) > 2048 or any(ord(c) < 32 for c in raw):
        raise ValueError("The URL is too long or contains invalid characters.")
    candidate = raw if "://" in raw else "https://" + raw
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname
        # Accessing .port can raise ValueError for malformed ports.
        _ = parsed.port
        if parsed.scheme not in ("http", "https") or not host or parsed.username or parsed.password:
            raise ValueError
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        if host == "localhost" or len(host) > 253 or " " in host:
            raise ValueError
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
        if len(host.split(".")) < 2 and not is_ip:
            raise ValueError
    except Exception:
        raise ValueError("Enter a valid public website URL, such as example.com.")
    # Keep the submitted URL as entered (except adding the default scheme) for accurate reputation checks.
    normalized = candidate
    return raw, normalized, parsed, host, is_ip


def google_safe_browsing_check(url):
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured", "provider": "Google Safe Browsing"}
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "phishguard-feather", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(endpoint, params={"key": api_key}, json=payload, timeout=5)
        if response.status_code == 200:
            matches = response.json().get("matches", [])
            if matches:
                types = sorted({m.get("threatType", "unsafe URL") for m in matches})
                return {"status": "threat", "provider": "Google Safe Browsing", "details": types}
            return {"status": "clear", "provider": "Google Safe Browsing"}
        app.logger.warning("Safe Browsing API returned HTTP %s", response.status_code)
        return {"status": "unavailable", "provider": "Google Safe Browsing"}
    except requests.RequestException:
        return {"status": "unavailable", "provider": "Google Safe Browsing"}


def virustotal_check(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured", "provider": "VirusTotal"}
    # Look up an existing report only. We do not submit new URLs for scanning.
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key, "accept": "application/json"},
            timeout=5,
        )
        if response.status_code == 404:
            return {"status": "no_report", "provider": "VirusTotal"}
        if response.status_code != 200:
            app.logger.warning("VirusTotal API returned HTTP %s", response.status_code)
            return {"status": "unavailable", "provider": "VirusTotal"}
        attrs = response.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        if malicious > 0:
            return {"status": "threat", "provider": "VirusTotal", "malicious": malicious, "suspicious": suspicious, "total": malicious + suspicious + harmless + undetected}
        if suspicious > 0:
            return {"status": "suspicious", "provider": "VirusTotal", "malicious": malicious, "suspicious": suspicious, "total": malicious + suspicious + harmless + undetected}
        return {"status": "clear", "provider": "VirusTotal", "malicious": malicious, "suspicious": suspicious, "total": malicious + suspicious + harmless + undetected}
    except (requests.RequestException, ValueError, TypeError):
        return {"status": "unavailable", "provider": "VirusTotal"}


def analyze(raw):
    try:
        original, normalized, parsed, host, is_ip = normalize_url(raw)
    except ValueError as exc:
        return {"error": str(exc)}

    score, findings = 0, []

    def flag(points, title, detail):
        nonlocal score
        score += points
        findings.append({"title": title, "detail": detail, "source": "URL pattern"})

    if parsed.scheme != "https":
        flag(12, "No HTTPS encryption", "This URL uses HTTP. Data sent to the site may not be encrypted.")
    if is_ip:
        flag(25, "IP address hostname", "The link uses an IP address instead of a conventional domain.")
    if "@" in parsed.netloc:
        flag(25, "Misleading @ symbol", "The @ character can disguise the actual destination in a URL.")
    if len(original) > 100:
        flag(8, "Unusually long URL", "Long links can make the destination harder to inspect.")
    if len(host.split(".")) >= 5:
        flag(8, "Many subdomain levels", "The hostname contains several subdomain levels.")
    if host in SHORTENERS:
        flag(18, "URL shortener", "The final destination is hidden until the shortened link is expanded.")
    if any(host.endswith(tld) for tld in RISKY_TLDS):
        flag(10, "Uncommon top-level domain", "This domain ending is sometimes abused; this alone is not proof of phishing.")
    if host.count("-") >= 3:
        flag(8, "Multiple hyphens", "Several hyphens can appear in deceptive domain names.")
    text = (host + " " + parsed.path + " " + parsed.query).lower()
    hits = sorted(word for word in WORDS if word in text)
    if hits:
        flag(min(15, 4 + 2 * len(hits)), "Sensitive-action wording", "Found terms often used in account or credential lures: " + ", ".join(hits) + ".")
    brands = sorted(brand for brand in BRANDS if brand in host)
    if brands and not any(host == b + ".com" or host.endswith("." + b + ".com") for b in brands):
        flag(12, "Possible brand impersonation", "Brand-related wording appears in a hostname that is not an obvious primary brand domain: " + ", ".join(brands) + ".")

    # Reputation checks use API services only; the submitted destination website is never opened by this app.
    safe_browsing = google_safe_browsing_check(normalized)
    virustotal = virustotal_check(normalized)
    threat_intel = [safe_browsing, virustotal]

    if safe_browsing["status"] == "threat":
        score = max(score, 95)
        findings.append({"title": "Listed by Google Safe Browsing", "detail": "Google Safe Browsing matched this URL to threat category/categories: " + ", ".join(safe_browsing.get("details", [])) + ". Avoid opening it or entering information.", "source": "Threat intelligence"})
    if virustotal["status"] == "threat":
        score = max(score, 85)
        findings.append({"title": "Malicious detections in VirusTotal report", "detail": f"The latest available report has {virustotal.get('malicious', 0)} malicious detection(s) out of {virustotal.get('total', 0)} engines. Treat this as a strong warning, not a standalone proof.", "source": "Threat intelligence"})
    elif virustotal["status"] == "suspicious":
        score = max(score, 60)
        findings.append({"title": "Suspicious detections in VirusTotal report", "detail": f"The latest available report has {virustotal.get('suspicious', 0)} suspicious detection(s). Review the evidence carefully.", "source": "Threat intelligence"})

    score = min(score, 100)
    intel_configured = any(x["status"] not in ("not_configured",) for x in threat_intel)
    intel_hit = any(x["status"] in ("threat", "suspicious") for x in threat_intel)
    intel_unavailable = any(x["status"] == "unavailable" for x in threat_intel)

    if safe_browsing["status"] == "threat":
        level, label, color = "high", "Known threat detected", "danger"
        summary = "Google Safe Browsing reports this URL as unsafe. Avoid visiting it or providing personal information."
    elif virustotal["status"] == "threat":
        level, label, color = "high", "High risk — malicious reports", "danger"
        summary = "VirusTotal reports malicious detections for this URL. Avoid visiting it unless you have a trusted, verified reason."
    elif virustotal["status"] == "suspicious":
        level, label, color = "high", "Suspicious reputation signals", "danger"
        summary = "Some VirusTotal engines flag this URL as suspicious. Detection results can be imperfect; treat the link cautiously."
    elif score >= 45:
        level, label, color = "high", "High risk indicators", "danger"
        summary = "Several URL patterns commonly associated with deceptive links were detected."
    elif score >= 20:
        level, label, color = "medium", "Some risk indicators", "warning"
        summary = "One or more patterns deserve caution. Verify the destination independently."
    elif not intel_configured:
        level, label, color = "unknown", "Preliminary URL assessment", "warning"
        summary = "No strong URL-pattern warnings were detected, but live threat-intelligence checks are not configured. This is not a safety verdict."
    elif intel_unavailable:
        level, label, color = "unknown", "Threat check incomplete", "warning"
        summary = "No strong URL-pattern warnings were detected, but one or more reputation checks could not complete. Do not assume the site is safe."
    elif not intel_hit:
        level, label, color = "low", "No known threats detected", "success"
        summary = "Configured reputation checks did not find a known threat and few URL-pattern warnings were detected. This does not guarantee safety."
    else:
        level, label, color = "low", "No known threats detected", "success"
        summary = "No known threat was returned by the configured checks. This does not guarantee safety."

    intel_summary = []
    for item in threat_intel:
        status = item["status"]
        if status == "clear":
            message = "No match in the available report/list"
        elif status == "threat":
            message = "Threat match found"
        elif status == "suspicious":
            message = "Suspicious detections found"
        elif status == "no_report":
            message = "No existing report found"
        elif status == "not_configured":
            message = "Not configured (API key missing)"
        else:
            message = "Check unavailable"
        intel_summary.append({"provider": item["provider"], "status": status, "message": message})

    configured_names = [x["provider"] for x in threat_intel if x["status"] != "not_configured"]
    method = "URL heuristics + " + (", ".join(configured_names) if configured_names else "optional threat-intelligence checks not configured")
    disclaimer = "Preliminary assessment only. Reputation checks depend on configured API keys and available provider data. No destination website is opened or crawled, and no trained ML model is used. A low score does not guarantee safety."

    return {
        "url": original, "host": host, "score": score, "level": level, "label": label,
        "color": color, "summary": summary, "findings": findings,
        "threat_intelligence": intel_summary,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "disclaimer": disclaimer,
    }


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or {}
    result = analyze(data.get("url", ""))
    return jsonify(result), 400 if "error" in result else 200


@app.get("/health")
def health():
    return jsonify({"status": "ok", "engine": "phishguard-feather-v1"})


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nAllow: /\n", 200, {
        "Content-Type": "text/plain"
    }

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
