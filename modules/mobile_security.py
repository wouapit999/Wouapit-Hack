"""Mobile Security module — APK/IPA static analysis, manifest, secrets."""
import zipfile, re, io, hashlib, os
from datetime import datetime

DANGEROUS_PERMS = {
    "SEND_SMS":           ("Can send SMS messages (financial fraud risk)", "HIGH"),
    "RECEIVE_SMS":        ("Can intercept SMS (2FA bypass risk)",          "HIGH"),
    "READ_CONTACTS":      ("Can read all contacts",                        "MEDIUM"),
    "READ_CALL_LOG":      ("Can read call history",                        "MEDIUM"),
    "RECORD_AUDIO":       ("Can record audio/calls",                       "HIGH"),
    "CAMERA":             ("Can access camera",                            "MEDIUM"),
    "ACCESS_FINE_LOCATION":("Precise GPS tracking",                        "HIGH"),
    "READ_EXTERNAL_STORAGE":("Can read device storage",                    "MEDIUM"),
    "WRITE_EXTERNAL_STORAGE":("Can write/modify storage",                  "MEDIUM"),
    "RECEIVE_BOOT_COMPLETED":("Autostart on device boot (persistence)",    "HIGH"),
    "INTERNET":           ("Network access (data exfiltration risk)",      "LOW"),
    "SYSTEM_ALERT_WINDOW":("Can draw over other apps (clickjacking)",      "HIGH"),
    "REQUEST_INSTALL_PACKAGES":("Can silently install apps",               "CRITICAL"),
    "BIND_ACCESSIBILITY_SERVICE":("Can spy on screen content",             "CRITICAL"),
    "READ_SMS":           ("Can read all SMS messages",                    "HIGH"),
    "PROCESS_OUTGOING_CALLS":("Can intercept outgoing calls",              "HIGH"),
    "CHANGE_NETWORK_STATE":("Can modify network settings",                 "MEDIUM"),
    "USE_BIOMETRIC":      ("Can use fingerprint/face auth",                "LOW"),
    "MANAGE_EXTERNAL_STORAGE":("Full storage access (Android 11+)",       "HIGH"),
    "PACKAGE_USAGE_STATS":("Can see which apps user runs",                 "HIGH"),
}

SECRET_PATTERNS = [
    (r"(?i)api[_\-]?key\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})",        "API Key"),
    (r"(?i)secret\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})",               "Secret"),
    (r"(?i)password\s*[=:]\s*['\"]?([^\s'\"]{8,})",                     "Password"),
    (r"(?i)token\s*[=:]\s*['\"]?([A-Za-z0-9\-_\.]{20,})",              "Token"),
    (r"AIza[0-9A-Za-z\-_]{35}",                                          "Google API Key"),
    (r"AKIA[0-9A-Z]{16}",                                                 "AWS Access Key"),
    (r"(?i)firebase[_\-]?url\s*=\s*https://[a-z0-9\-]+\.firebaseio\.com","Firebase URL"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",                         "Private Key"),
    (r"(?i)jdbc:[a-z]+://[^\s\"']+",                                      "JDBC Connection String"),
    (r"mongodb(?:\+srv)?://[^\s\"']+",                                    "MongoDB URL"),
    (r"(?i)stripe[_\-]?(?:secret|live)[_\-]?key\s*[=:]\s*(sk_live_[A-Za-z0-9]+)", "Stripe Key"),
]


def analyze_apk(apk_bytes: bytes, filename: str = "app.apk") -> dict:
    result = {
        "filename":    filename,
        "timestamp":   datetime.utcnow().isoformat(),
        "hashes":      {},
        "permissions": [],
        "dangerous_permissions": [],
        "components":  {"activities":[],"services":[],"receivers":[],"providers":[]},
        "hardcoded_secrets": [],
        "urls":        [],
        "ips":         [],
        "interesting_strings": [],
        "native_libs": [],
        "vulnerabilities": [],
        "risk_score":  0,
    }
    result["hashes"] = {
        "md5":    hashlib.md5(apk_bytes).hexdigest(),
        "sha1":   hashlib.sha1(apk_bytes).hexdigest(),
        "sha256": hashlib.sha256(apk_bytes).hexdigest(),
        "size":   len(apk_bytes),
    }
    try:
        z = zipfile.ZipFile(io.BytesIO(apk_bytes))
        files = z.namelist()
        result["file_count"] = len(files)
        result["files_sample"] = [f for f in files if not f.startswith("res/")][:30]

        # Manifest analysis
        if "AndroidManifest.xml" in files:
            manifest_raw = z.read("AndroidManifest.xml")
            _parse_android_manifest(manifest_raw, result)

        # Dex files
        dex_files = [f for f in files if f.endswith(".dex")]
        result["dex_files"] = dex_files
        # Strings from dex
        all_strings = []
        for dex in dex_files[:3]:
            try:
                dex_data = z.read(dex)
                extracted = _extract_dex_strings(dex_data)
                all_strings.extend(extracted)
            except Exception:
                pass

        # Also scan smali / assets / raw
        for fname in files:
            if any(fname.endswith(ext) for ext in (".smali",".xml",".json",".txt",".properties")):
                try:
                    content = z.read(fname).decode("utf-8", errors="ignore")
                    all_strings.append(content)
                except Exception:
                    pass

        combined = "\n".join(all_strings)
        # URLs
        result["urls"] = list(set(re.findall(r"https?://[^\s\"'<>]{4,100}", combined)))[:30]
        # IPs
        result["ips"]  = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", combined)))[:20]
        # Hardcoded secrets
        for pattern, label in SECRET_PATTERNS:
            matches = re.findall(pattern, combined)
            for m in matches[:3]:
                val = m if isinstance(m, str) else m[0] if m else ""
                if val and len(val) > 6:
                    result["hardcoded_secrets"].append({
                        "type":  label,
                        "value": val[:50] + ("…" if len(val) > 50 else ""),
                        "severity": "CRITICAL",
                    })

        # Native libraries
        result["native_libs"] = [f for f in files if f.endswith(".so")]
        # Check for debug build
        if any("debug" in f.lower() or "test" in f.lower() for f in files):
            result["vulnerabilities"].append({
                "type": "Debug/Test Build Detected",
                "severity": "MEDIUM",
                "description": "Debug build artifacts found in APK",
                "remediation": "Never release debug builds to production.",
            })
        # Check for HTTP (not HTTPS) usage
        http_only = [u for u in result["urls"] if u.startswith("http://")]
        if http_only:
            result["vulnerabilities"].append({
                "type": "Insecure HTTP URLs",
                "severity": "HIGH",
                "urls": http_only[:5],
                "description": "App uses unencrypted HTTP connections",
                "remediation": "Use HTTPS for all network communications.",
            })
        # Secrets findings
        if result["hardcoded_secrets"]:
            result["vulnerabilities"].append({
                "type": "Hardcoded Secrets",
                "severity": "CRITICAL",
                "count": len(result["hardcoded_secrets"]),
                "description": "API keys, passwords or tokens found hardcoded in APK",
                "remediation": "Move secrets to a secure backend. Never hardcode credentials.",
            })
    except zipfile.BadZipFile:
        result["error"] = "Not a valid ZIP/APK file"
    except Exception as e:
        result["error"] = str(e)

    # Risk score
    sev_w = {"CRITICAL":15,"HIGH":8,"MEDIUM":3,"LOW":1}
    score = sum(sev_w.get(v.get("severity","LOW"),1) for v in result["vulnerabilities"])
    score += sum(sev_w.get(p.get("severity","LOW"),1) for p in result["dangerous_permissions"])
    score += len(result["hardcoded_secrets"]) * 15
    result["risk_score"] = min(100, score)
    result["verdict"] = (
        "HIGH RISK" if result["risk_score"] >= 60 else
        "MEDIUM RISK" if result["risk_score"] >= 30 else
        "LOW RISK"
    )
    return result


def _parse_android_manifest(data: bytes, result: dict):
    """Parse AndroidManifest.xml — binary XML or text."""
    # Try text decode first
    text = ""
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = data.decode("latin-1", errors="ignore")
    # Permission extraction (works on both text and partially decoded binary)
    perms = re.findall(r'android\.permission\.([A-Z_]+)', text)
    for p in set(perms):
        entry = {"permission": f"android.permission.{p}"}
        if p in DANGEROUS_PERMS:
            desc, sev = DANGEROUS_PERMS[p]
            entry.update({"description": desc, "severity": sev})
            result["dangerous_permissions"].append(entry)
        else:
            result["permissions"].append(f"android.permission.{p}")
    # Package name
    pkg = re.search(r'package="([^"]+)"', text)
    if pkg:
        result["package_name"] = pkg.group(1)
    # Min SDK
    sdk = re.search(r'minSdkVersion="(\d+)"', text)
    if sdk:
        v = int(sdk.group(1))
        result["min_sdk"] = v
        if v < 21:
            result["vulnerabilities"] = result.get("vulnerabilities",[])
            result["vulnerabilities"].append({
                "type": f"Low minSdkVersion ({v} = Android {_sdk_to_ver(v)})",
                "severity": "MEDIUM",
                "description": "App supports very old Android versions with known vulnerabilities",
                "remediation": "Set minSdkVersion to at least 24 (Android 7.0)",
            })
    # Backup allowed
    if 'allowBackup="true"' in text or 'android:allowBackup="true"' in text:
        result.setdefault("vulnerabilities",[]).append({
            "type": "Backup Allowed (android:allowBackup=true)",
            "severity": "MEDIUM",
            "description": "App data can be backed up and extracted via ADB",
            "remediation": "Set android:allowBackup=false if not needed.",
        })
    # Debuggable
    if 'debuggable="true"' in text or 'android:debuggable="true"' in text:
        result.setdefault("vulnerabilities",[]).append({
            "type": "Debuggable Build (android:debuggable=true)",
            "severity": "HIGH",
            "description": "App can be debugged via ADB — exposes internals to attackers",
            "remediation": "Set android:debuggable=false in release builds.",
        })
    # Network Security Config (absence)
    if "networkSecurityConfig" not in text:
        result.setdefault("vulnerabilities",[]).append({
            "type": "No Network Security Config",
            "severity": "MEDIUM",
            "description": "Missing network_security_config.xml — may allow cleartext/custom CA traffic",
            "remediation": "Add networkSecurityConfig with cleartextTrafficPermitted=false",
        })
    # Exported components
    exported = re.findall(r'(?:Activity|Service|Receiver|Provider)[^>]*android:exported="true"[^>]*/?>',
                          text, re.IGNORECASE)
    if len(exported) > 3:
        result.setdefault("vulnerabilities",[]).append({
            "type": f"{len(exported)} Exported Components",
            "severity": "MEDIUM",
            "description": "Multiple exported components may be accessible by other apps",
            "remediation": "Set android:exported=false for components not meant to be public",
        })


def _extract_dex_strings(dex_data: bytes) -> list:
    strings = []
    for m in re.finditer(rb"[ -~]{6,}", dex_data):
        s = m.group(0).decode("ascii", errors="ignore")
        strings.append(s)
    return strings[:500]


def _sdk_to_ver(sdk: int) -> str:
    m = {16:"4.1",17:"4.2",18:"4.3",19:"4.4",21:"5.0",22:"5.1",
         23:"6.0",24:"7.0",25:"7.1",26:"8.0",27:"8.1",28:"9",
         29:"10",30:"11",31:"12",32:"12L",33:"13",34:"14"}
    return m.get(sdk, str(sdk))


def analyze_ipa(ipa_bytes: bytes, filename: str = "app.ipa") -> dict:
    result = {
        "filename":   filename,
        "timestamp":  datetime.utcnow().isoformat(),
        "hashes":     {},
        "info_plist": {},
        "urls":       [],
        "hardcoded_secrets": [],
        "vulnerabilities": [],
        "risk_score": 0,
    }
    result["hashes"] = {
        "md5":    hashlib.md5(ipa_bytes).hexdigest(),
        "sha256": hashlib.sha256(ipa_bytes).hexdigest(),
        "size":   len(ipa_bytes),
    }
    try:
        z = zipfile.ZipFile(io.BytesIO(ipa_bytes))
        files = z.namelist()
        result["file_count"] = len(files)
        # Info.plist
        plist_files = [f for f in files if f.endswith("Info.plist")]
        all_text = []
        for pf in plist_files[:1]:
            try:
                content = z.read(pf).decode("utf-8", errors="ignore")
                all_text.append(content)
                # Extract key values
                keys   = re.findall(r"<key>([^<]+)</key>", content)
                values = re.findall(r"<(?:string|integer|true|false)>([^<]*)</(?:string|integer)>", content)
                for k, v in zip(keys, values):
                    result["info_plist"][k] = v
            except Exception:
                pass
        # Scan binary
        bin_files = [f for f in files if not f.endswith((".png",".jpg",".nib",".car"))]
        for bf in bin_files[:5]:
            try:
                content = z.read(bf).decode("utf-8", errors="ignore")
                all_text.append(content)
            except Exception:
                pass
        combined = "\n".join(all_text)
        result["urls"] = list(set(re.findall(r"https?://[^\s\"'<>]{4,100}", combined)))[:20]
        for pattern, label in SECRET_PATTERNS:
            matches = re.findall(pattern, combined)
            for m in matches[:2]:
                val = m if isinstance(m, str) else ""
                if val and len(val) > 6:
                    result["hardcoded_secrets"].append({"type": label, "value": val[:50]+"…", "severity":"CRITICAL"})
        # ATS check
        plist = result["info_plist"]
        if plist.get("NSAllowsArbitraryLoads") == "true" or "NSAllowsArbitraryLoads" not in str(combined):
            result["vulnerabilities"].append({
                "type": "App Transport Security Disabled or Missing",
                "severity": "HIGH",
                "description": "NSAllowsArbitraryLoads may allow HTTP connections",
                "remediation": "Set NSAllowsArbitraryLoads to false in Info.plist",
            })
        if result["hardcoded_secrets"]:
            result["vulnerabilities"].append({
                "type": "Hardcoded Secrets",
                "severity": "CRITICAL",
                "count": len(result["hardcoded_secrets"]),
                "remediation": "Move secrets to Keychain or secure backend",
            })
        http_only = [u for u in result["urls"] if u.startswith("http://")]
        if http_only:
            result["vulnerabilities"].append({
                "type": "Insecure HTTP URLs",
                "severity": "HIGH",
                "urls": http_only[:5],
                "remediation": "Use HTTPS for all network communications",
            })
    except zipfile.BadZipFile:
        result["error"] = "Not a valid ZIP/IPA file"
    except Exception as e:
        result["error"] = str(e)
    sev_w = {"CRITICAL":15,"HIGH":8,"MEDIUM":3,"LOW":1}
    result["risk_score"] = min(100,
        sum(sev_w.get(v.get("severity","LOW"),1) for v in result["vulnerabilities"]) +
        len(result["hardcoded_secrets"]) * 15)
    result["verdict"] = (
        "HIGH RISK" if result["risk_score"] >= 60 else
        "MEDIUM RISK" if result["risk_score"] >= 30 else
        "LOW RISK"
    )
    return result
