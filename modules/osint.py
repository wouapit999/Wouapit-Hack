"""OSINT Intelligence module — email breaches, social footprinting, metadata extraction."""
import re, os, hashlib, json
from datetime import datetime

try:
    import requests as req
    REQ_OK = True
except ImportError:
    REQ_OK = False


# ── HIBP email breach check ──────────────────────────────────────────────────
def email_breach_check(email: str, api_key: str = "") -> dict:
    result = {"email": email, "timestamp": datetime.utcnow().isoformat(),
              "breaches": [], "pastes": []}
    if not REQ_OK:
        return {"error": "requests not installed"}
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"error": "Invalid email format"}
    headers = {"User-Agent": "Wouapit-Hack-Security-Tool",
               "hibp-api-key": api_key} if api_key else {"User-Agent": "Wouapit-Hack-Security-Tool"}
    try:
        r = req.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            for breach in r.json():
                result["breaches"].append({
                    "name":          breach.get("Name"),
                    "domain":        breach.get("Domain"),
                    "breach_date":   breach.get("BreachDate"),
                    "pwn_count":     breach.get("PwnCount"),
                    "data_classes":  breach.get("DataClasses",[]),
                    "is_verified":   breach.get("IsVerified"),
                    "is_sensitive":  breach.get("IsSensitive"),
                    "description":   re.sub(r"<[^>]+>","", breach.get("Description",""))[:300],
                })
        elif r.status_code == 404:
            result["status"] = "not_found"
            result["message"] = "Good news — this email was not found in any known breach."
        elif r.status_code == 401:
            result["error"] = "HIBP API key required. Get one at https://haveibeenpwned.com/API/Key"
        elif r.status_code == 429:
            result["error"] = "Rate limited by HIBP. Please wait before retrying."
        else:
            result["error"] = f"HIBP API returned HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    result["breach_count"] = len(result["breaches"])
    return result


# ── Password hash check (HIBP Pwned Passwords) ──────────────────────────────
def password_pwned_check(password: str) -> dict:
    result = {"timestamp": datetime.utcnow().isoformat()}
    sha1    = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix  = sha1[:5]
    suffix  = sha1[5:]
    if not REQ_OK:
        return {"error": "requests not installed"}
    try:
        r = req.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                    headers={"Add-Padding": "true"}, timeout=8)
        if r.status_code == 200:
            for line in r.text.splitlines():
                if ":" in line:
                    h, count = line.split(":", 1)
                    if h.upper() == suffix:
                        result["pwned"] = True
                        result["count"] = int(count.strip())
                        result["message"] = f"This password appears {result['count']:,} times in data breaches!"
                        return result
            result["pwned"]   = False
            result["count"]   = 0
            result["message"] = "Password not found in known breaches (use it cautiously)."
    except Exception as e:
        result["error"] = str(e)
    return result


# ── GitHub footprinting ──────────────────────────────────────────────────────
def github_footprint(username: str) -> dict:
    result = {"username": username, "timestamp": datetime.utcnow().isoformat()}
    if not REQ_OK:
        return {"error": "requests not installed"}
    try:
        headers = {"Accept": "application/vnd.github+json",
                   "User-Agent": "Wouapit-Hack"}
        r = req.get(f"https://api.github.com/users/{username}", headers=headers, timeout=10)
        if r.status_code == 200:
            u = r.json()
            result["profile"] = {
                "name":        u.get("name"),
                "bio":         u.get("bio"),
                "company":     u.get("company"),
                "location":    u.get("location"),
                "email":       u.get("email"),
                "blog":        u.get("blog"),
                "twitter":     u.get("twitter_username"),
                "followers":   u.get("followers"),
                "following":   u.get("following"),
                "public_repos":u.get("public_repos"),
                "public_gists":u.get("public_gists"),
                "created_at":  u.get("created_at"),
                "updated_at":  u.get("updated_at"),
                "avatar_url":  u.get("avatar_url"),
                "html_url":    u.get("html_url"),
            }
        elif r.status_code == 404:
            result["error"] = "User not found"
            return result
        # Fetch repos
        repos_r = req.get(f"https://api.github.com/users/{username}/repos",
                          headers=headers, params={"per_page": 30, "sort": "updated"}, timeout=10)
        if repos_r.status_code == 200:
            repos = repos_r.json()
            result["repos"] = [{
                "name":         r2.get("name"),
                "description":  r2.get("description","")[:100],
                "language":     r2.get("language"),
                "stars":        r2.get("stargazers_count"),
                "forks":        r2.get("forks_count"),
                "updated_at":   r2.get("updated_at"),
                "topics":       r2.get("topics",[]),
                "url":          r2.get("html_url"),
                "is_fork":      r2.get("fork"),
            } for r2 in repos[:15]]
            result["languages"] = list({r2.get("language") for r2 in repos if r2.get("language")})
        # Secret scanning hints in repo names/descriptions
        secrets_keywords = ["api-key","secret","token","password","credential","config","env","dotenv"]
        result["security_hints"] = []
        for repo in result.get("repos",[]):
            name = (repo.get("name","") + " " + (repo.get("description") or "")).lower()
            found = [k for k in secrets_keywords if k in name]
            if found:
                result["security_hints"].append({
                    "repo": repo.get("name"), "keywords": found,
                    "url":  repo.get("url"),
                    "note": "Repository name/description contains sensitive keywords"
                })
    except Exception as e:
        result["error"] = str(e)
    return result


# ── DNS + WHOIS history ──────────────────────────────────────────────────────
def dns_history(domain: str) -> dict:
    result = {"domain": domain, "timestamp": datetime.utcnow().isoformat()}
    if not REQ_OK:
        return {"error": "requests not installed"}
    try:
        # SecurityTrails-style public endpoint (no key needed for basic)
        r = req.get(
            f"https://api.hackertarget.com/dnslookup/?q={domain}",
            timeout=10,
        )
        result["current_dns"] = r.text[:2000] if r.status_code == 200 else "Unavailable"
        # Reverse IP lookup
        r2 = req.get(f"https://api.hackertarget.com/reverseiplookup/?q={domain}", timeout=10)
        result["reverse_ip_domains"] = r2.text[:1000].splitlines() if r2.status_code == 200 else []
        # Zone transfer attempt
        r3 = req.get(f"https://api.hackertarget.com/zonetransfer/?q={domain}", timeout=10)
        result["zone_transfer"] = r3.text[:2000] if r3.status_code == 200 else "Blocked"
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Metadata extractor ───────────────────────────────────────────────────────
def extract_metadata(file_bytes: bytes, filename: str) -> dict:
    result = {"filename": filename, "timestamp": datetime.utcnow().isoformat(),
              "metadata": {}, "security_findings": []}
    ext = os.path.splitext(filename)[1].lower()

    # Hash
    result["hashes"] = {
        "md5":    hashlib.md5(file_bytes).hexdigest(),
        "sha1":   hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }
    result["size_bytes"] = len(file_bytes)

    if ext in (".jpg", ".jpeg", ".png", ".tiff", ".gif"):
        _extract_image_meta(file_bytes, result)
    elif ext == ".pdf":
        _extract_pdf_meta(file_bytes, result)
    elif ext in (".docx", ".xlsx", ".pptx"):
        _extract_office_meta(file_bytes, result)
    else:
        result["metadata"]["note"] = f"No specific extractor for {ext}"

    return result


def _extract_image_meta(data: bytes, result: dict):
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        import io
        img = Image.open(io.BytesIO(data))
        result["metadata"]["format"] = img.format
        result["metadata"]["mode"]   = img.mode
        result["metadata"]["size"]   = f"{img.width}x{img.height}"
        exif_data = img._getexif() if hasattr(img, "_getexif") else None
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, str(tag_id))
                result["metadata"][tag] = str(value)[:200]
            # GPS check
            gps_info = exif_data.get(34853)
            if gps_info:
                result["security_findings"].append({
                    "type": "GPS Location Embedded",
                    "severity": "HIGH",
                    "detail": "Image contains GPS coordinates — reveals physical location",
                    "remediation": "Strip EXIF data before publishing: exiftool -all= image.jpg",
                })
            # Author/device info
            for tag in ["Make","Model","Software","Artist","Copyright","XPAuthor"]:
                if tag in result["metadata"]:
                    result["security_findings"].append({
                        "type": f"Device/Author Info: {tag}",
                        "severity": "LOW",
                        "detail": f"{tag}: {result['metadata'][tag]}",
                        "remediation": "Remove identifying metadata before publishing.",
                    })
    except Exception as e:
        result["metadata"]["exif_error"] = str(e)


def _extract_pdf_meta(data: bytes, result: dict):
    try:
        text = data.decode("latin-1", errors="ignore")
        patterns = {
            "Author":   r"/Author\s*\(([^)]+)\)",
            "Creator":  r"/Creator\s*\(([^)]+)\)",
            "Producer": r"/Producer\s*\(([^)]+)\)",
            "Title":    r"/Title\s*\(([^)]+)\)",
            "Subject":  r"/Subject\s*\(([^)]+)\)",
            "Keywords": r"/Keywords\s*\(([^)]+)\)",
            "CreationDate": r"/CreationDate\s*\(([^)]+)\)",
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, text)
            if m:
                result["metadata"][key] = m.group(1).strip()
                if key in ("Author","Creator","Producer"):
                    result["security_findings"].append({
                        "type": f"PDF Metadata Exposed: {key}",
                        "severity": "LOW",
                        "detail": f"{key}: {m.group(1).strip()}",
                        "remediation": "Sanitise PDF metadata before distribution.",
                    })
        # Check for embedded URLs
        urls = re.findall(r"https?://[^\s)\]>\"']+", text)[:20]
        if urls:
            result["metadata"]["embedded_urls"] = urls
        # Check for JavaScript
        if "/JavaScript" in text or "/JS " in text:
            result["security_findings"].append({
                "type": "PDF Contains JavaScript",
                "severity": "HIGH",
                "detail": "Embedded JavaScript can execute when PDF is opened",
                "remediation": "Investigate and remove JavaScript from PDF.",
            })
    except Exception as e:
        result["metadata"]["pdf_error"] = str(e)


def _extract_office_meta(data: bytes, result: dict):
    try:
        import zipfile, io
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        result["metadata"]["files_in_archive"] = names[:20]
        # Core properties
        if "docProps/core.xml" in names:
            xml_text = z.read("docProps/core.xml").decode("utf-8", errors="ignore")
            for tag in ["dc:creator","cp:lastModifiedBy","cp:revision","dcterms:created","dcterms:modified"]:
                m = re.search(f"<{tag}>([^<]+)</{tag}>", xml_text)
                if m:
                    key = tag.split(":")[-1]
                    result["metadata"][key] = m.group(1)
                    if key in ("creator","lastModifiedBy"):
                        result["security_findings"].append({
                            "type": f"Author Info Exposed: {key}",
                            "severity": "LOW",
                            "detail": f"{key}: {m.group(1)}",
                            "remediation": "Remove metadata via File → Info → Inspect Document.",
                        })
        # App properties
        if "docProps/app.xml" in names:
            xml_text = z.read("docProps/app.xml").decode("utf-8", errors="ignore")
            for tag in ["Application","Company","Manager"]:
                m = re.search(f"<{tag}>([^<]+)</{tag}>", xml_text)
                if m:
                    result["metadata"][tag] = m.group(1)
                    if tag in ("Company","Manager"):
                        result["security_findings"].append({
                            "type": f"Corporate Info Exposed: {tag}",
                            "severity": "LOW",
                            "detail": f"{tag}: {m.group(1)}",
                        })
        # Macro check
        macro_files = [n for n in names if n.endswith(".bin") or "vba" in n.lower() or "macro" in n.lower()]
        if macro_files:
            result["security_findings"].append({
                "type": "Office Document Contains Macros",
                "severity": "HIGH",
                "detail": f"Macro-related files: {macro_files}",
                "remediation": "Inspect macros for malicious code before opening.",
            })
    except Exception as e:
        result["metadata"]["office_error"] = str(e)


# ── Dark web exposure (simulated via known breach indicators) ─────────────────
def dark_web_exposure(query: str) -> dict:
    result = {"query": query, "timestamp": datetime.utcnow().isoformat(),
              "indicators": [], "sources": []}
    if not REQ_OK:
        return {"error": "requests not installed"}
    # Dehashed API (public endpoints)
    try:
        r = req.get(
            "https://api.dehashed.com/search",
            params={"query": query, "size": 10},
            headers={"Accept": "application/json"},
            timeout=8,
        )
        if r.status_code == 200:
            data = r.json()
            for entry in (data.get("entries") or [])[:10]:
                result["indicators"].append({
                    "email":    entry.get("email",""),
                    "username": entry.get("username",""),
                    "source":   entry.get("database_name",""),
                    "hashed_pw":entry.get("hashed_password","") != "",
                    "ip":       entry.get("ip_address",""),
                })
        elif r.status_code == 401:
            result["note"] = "Dehashed requires API key. Using public threat data only."
    except Exception:
        pass
    # BreachDirectory
    try:
        r2 = req.get(
            f"https://breachdirectory.p.rapidapi.com/",
            params={"func": "auto", "term": query},
            headers={"X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"},
            timeout=8,
        )
        if r2.status_code == 200:
            data2 = r2.json()
            result["sources"].append({"name": "BreachDirectory", "found": data2.get("found",False)})
    except Exception:
        pass
    result["disclaimer"] = "Dark web data is for threat awareness only. Results depend on available public breach databases."
    return result
