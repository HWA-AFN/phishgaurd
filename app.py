from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import ipaddress
from datetime import datetime, timezone

app = Flask(__name__)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
RISKY_TLDS = (".zip", ".mov", ".top", ".xyz", ".click", ".gq", ".tk")
WORDS = {"login", "verify", "update", "password", "account", "billing", "confirm", "wallet", "signin", "urgent", "suspend"}
BRANDS = {"paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook", "instagram", "whatsapp"}

def analyze(raw):
    raw = (raw or "").strip()
    if not raw:
        return {"error": "Enter a URL to scan."}
    if len(raw) > 2048 or any(ord(c) < 32 for c in raw):
        return {"error": "The URL is too long or contains invalid characters."}
    try:
        parsed = urlparse(raw if "://" in raw else "https://" + raw)
        host = parsed.hostname
        if parsed.scheme not in ("http", "https") or not host:
            raise ValueError()
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        if host == "localhost" or len(host) > 253 or " " in host:
            raise ValueError()
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
        if len(host.split(".")) < 2 and not is_ip:
            raise ValueError()
    except Exception:
        return {"error": "Enter a valid public website URL, such as example.com."}

    score, findings = 0, []
    def flag(points, title, detail):
        nonlocal score
        score += points
        findings.append({"title": title, "detail": detail})

    if parsed.scheme != "https":
        flag(12, "No HTTPS encryption", "This URL uses HTTP. Data sent to the site may not be encrypted.")
    if is_ip:
        flag(25, "IP address hostname", "The link uses an IP address instead of a conventional domain.")
    if "@" in parsed.netloc:
        flag(25, "Misleading @ symbol", "The @ character can disguise the actual destination in a URL.")
    if len(raw) > 100:
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
        flag(min(15, 4 + 2 * len(hits)), "Sensitive-action wording",
             "Found terms often used in account or credential lures: " + ", ".join(hits) + ".")
    brands = sorted(brand for brand in BRANDS if brand in host)
    if brands and not any(host == b + ".com" or host.endswith("." + b + ".com") for b in brands):
        flag(12, "Possible brand impersonation",
             "Brand-related wording appears in a hostname that is not an obvious primary brand domain: " + ", ".join(brands) + ".")

    score = min(score, 100)
    if score >= 45:
        level, label, color = "high", "High risk indicators", "danger"
        summary = "Several URL patterns commonly associated with deceptive links were detected."
    elif score >= 20:
        level, label, color = "medium", "Some risk indicators", "warning"
        summary = "One or more patterns deserve caution. Verify the destination independently."
    else:
        level, label, color = "low", "Fewer risk indicators", "success"
        summary = "Few configured warning patterns were detected. This does not establish that the site is safe."

    return {
        "url": raw, "host": host, "score": score, "level": level, "label": label,
        "color": color, "summary": summary, "findings": findings,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "method": "Local heuristic analysis",
        "disclaimer": "Preliminary URL-pattern assessment only. No website visit, malware scan, live reputation check, or trained ML model is used. A low score does not guarantee safety."
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
    return jsonify({"status": "ok", "engine": "local-heuristic-v1"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
