"""
Smart Metering Penetration Testing — DLMS/COSEM, Wireless M-Bus, ANSI C12,
HES/MDMS scanning, meter firmware analysis, SDR playbook, IEC 62443 compliance.

For authorised security testing of AMI/smart-grid infrastructure only.
"""
import re, struct, binascii, hashlib, os
from datetime import datetime

try:
    import requests as req
    REQ_OK = True
except ImportError:
    REQ_OK = False


# ═══════════════════════════════════════════════════════════════════════════
# DLMS / COSEM (IEC 62056) — dominant AMI protocol in Europe & most global
# ═══════════════════════════════════════════════════════════════════════════

DLMS_TAGS = {
    0x60: "AARQ (Application Association Request)",
    0x61: "AARE (Application Association Response)",
    0x62: "RLRQ (Release Request)",
    0x63: "RLRE (Release Response)",
    0xC0: "GET-Request",
    0xC1: "SET-Request",
    0xC2: "EVENT-NOTIFICATION",
    0xC3: "ACTION-Request",
    0xC4: "GET-Response",
    0xC5: "SET-Response",
    0xC7: "ACTION-Response",
    0xD8: "EXCEPTION-Response",
    0xDB: "GENERAL-GLOBAL-CIPHERING",
    0xDD: "GENERAL-CIPHERING",
    0xC8: "GLO-GET-Request",
    0xC9: "GLO-SET-Request",
    0xCB: "GLO-ACTION-Request",
    0xCC: "GLO-GET-Response",
    0xCD: "GLO-SET-Response",
    0xCF: "GLO-ACTION-Response",
}

DLMS_AUTH_LEVELS = {
    0: ("Lowest / None",       "CRITICAL", "No authentication — anyone can read/write meter"),
    1: ("Low (LLS)",           "HIGH",     "Cleartext password — sniffable, replayable"),
    2: ("High (HLS)",          "MEDIUM",   "Legacy challenge-response, MD5/SHA-1 based"),
    3: ("High MD5 (HLS3)",     "HIGH",     "MD5 broken since 2004 — collision + preimage attacks"),
    4: ("High SHA-1 (HLS4)",   "MEDIUM",   "SHA-1 deprecated; acceptable for now, plan migration"),
    5: ("High GMAC (HLS5)",    "LOW",      "GMAC authentication — current best practice"),
    6: ("High SHA-256 (HLS6)", "LOW",      "SHA-256 based — recommended"),
    7: ("High ECDSA (HLS7)",   "LOW",      "Elliptic-curve — strongest, IEC 62056-6-1:2019"),
}

# Well-known OBIS codes (Object Identification System) — standardised meter data
OBIS_CODES = {
    "1.0.1.8.0.255":  "Active energy import (total kWh)",
    "1.0.1.8.1.255":  "Active energy import tariff 1",
    "1.0.1.8.2.255":  "Active energy import tariff 2",
    "1.0.2.8.0.255":  "Active energy export (total kWh)",
    "1.0.32.7.0.255": "Instantaneous voltage L1",
    "1.0.31.7.0.255": "Instantaneous current L1",
    "0.0.42.0.0.255": "COSEM logical device name",
    "0.0.96.1.0.255": "Meter serial number",
    "0.0.1.0.0.255":  "Clock",
    "0.0.99.98.0.255":"Standard event log",
    "0.0.99.98.1.255":"Fraud event log — tampering, magnetic, reverse-flow",
    "0.0.40.0.0.255": "Current association object",
    "0.0.43.0.0.255": "Security setup — auth/encryption keys live here!",
    "0.0.43.0.1.255": "Security setup — master key",
    "1.0.94.34.104.255": "Manufacturer software version",
}


def analyze_dlms_apdu(hex_string: str) -> dict:
    """Parse a DLMS/COSEM APDU (hex-encoded). Detects auth level, cipher, and
    common weaknesses. Accepts HDLC-wrapped frames (0x7E flags) or raw APDU."""
    result = {"input_hex": hex_string, "timestamp": datetime.utcnow().isoformat(),
              "findings": [], "info": []}
    try:
        clean = re.sub(r"[^0-9a-fA-F]", "", hex_string)
        data  = binascii.unhexlify(clean)
    except Exception as e:
        return {"error": f"Invalid hex: {e}"}
    if len(data) < 1:
        return {"error": "Empty APDU"}

    if data[0] == 0x7E and data[-1] == 0x7E:
        result["info"].append("HDLC-wrapped APDU (IEC 62056-46). Extracting inner frame.")
        inner = data[1:-1]
        if len(inner) > 5:
            idx = inner.find(b"\xe6\xe6\x00")
            data = inner[idx + 3:] if idx >= 0 else inner

    tag = data[0]
    result["apdu_tag"]  = f"0x{tag:02X}"
    result["apdu_type"] = DLMS_TAGS.get(tag, f"Unknown (0x{tag:02X})")

    if tag in (0x60, 0x61):
        _parse_aarq_aare(data, result)
    elif tag in (0xDB, 0xDD) or (tag >= 0xC8 and tag <= 0xCF):
        result["findings"].append({
            "type":     "Ciphered APDU",
            "severity": "INFO",
            "description": f"APDU is encrypted (tag {result['apdu_tag']}). Content needs session key.",
            "note":     "If Suite 0 AES-GCM-128 with default AK-EK, offline attacks possible.",
        })
    elif tag == 0xC0:
        _parse_get_request(data, result)
    elif tag == 0xC1:
        result["operation"] = "SET (write to meter object) — sensitive"
        if len(data) >= 12:
            class_id = struct.unpack(">H", data[4:6])[0]
            obis     = ".".join(str(b) for b in data[6:12])
            result["class_id"] = class_id
            result["obis"]     = obis
            result["obis_meaning"] = OBIS_CODES.get(obis, "Unknown OBIS")
            if obis.startswith("0.0.43."):
                result["findings"].append({
                    "type":     "Write to Security Setup Object",
                    "severity": "CRITICAL",
                    "description": f"OBIS {obis} is Security Setup — SET means key/policy modification.",
                })

    # Weak-cipher / default-key heuristics
    if b"\x00" * 16 in data:
        result["findings"].append({
            "type":     "16 null bytes in payload",
            "severity": "MEDIUM",
            "description": "Possible null AES key or padding — commonly seen with default configs.",
        })
    if b"\x11" * 16 in data:
        result["findings"].append({
            "type":     "IEC test-vector key detected",
            "severity": "CRITICAL",
            "description": "16 bytes of 0x11 — well-known IEC 62056 test key. Never use in production.",
        })
    return result


def _parse_aarq_aare(data: bytes, result: dict):
    tag  = data[0]
    result["assoc_kind"] = "AARQ" if tag == 0x60 else "AARE"
    i = 2 + (data[1] & 0x7F if len(data) > 1 and data[1] & 0x80 else 0)

    while i < len(data) - 2:
        t = data[i]
        if t == 0x8B and i + 1 < len(data):
            length = data[i+1]
            oid    = data[i+2:i+2+length]
            mech   = oid[-1] if oid else 0
            auth   = DLMS_AUTH_LEVELS.get(mech, ("Unknown", "MEDIUM", "Undocumented mechanism"))
            result["auth_level"] = mech
            result["auth_name"]  = auth[0]
            result["findings"].append({
                "type":     f"Authentication level: {auth[0]}",
                "severity": auth[1],
                "description": auth[2],
                "remediation": "Upgrade to HLS6/HLS7 (SHA-256 or ECDSA). Rotate keys."
                              if auth[1] in ("CRITICAL","HIGH","MEDIUM") else "Maintain current level."
            })
            i += 2 + length
            continue
        if t == 0xAC:
            length   = data[i+1]
            auth_val = data[i+2:i+2+length]
            result["auth_value_hex"] = binascii.hexlify(auth_val).decode()
            try:
                as_ascii = auth_val.decode("ascii", errors="ignore")
                if as_ascii.strip("\x00 ") in ("00000000","12345678","password","admin","1234",""):
                    result["findings"].append({
                        "type":     f"Weak LLS password: '{as_ascii}'",
                        "severity": "CRITICAL",
                        "description": "Trivial cleartext password — default or shipped by manufacturer.",
                    })
            except Exception:
                pass
            i += 2 + length
            continue
        i += 1


def _parse_get_request(data: bytes, result: dict):
    result["operation"] = "GET (read meter object)"
    if len(data) >= 12 and data[1] == 0x01:
        result["invoke_id"]    = data[2]
        result["class_id"]     = struct.unpack(">H", data[3:5])[0]
        obis                   = ".".join(str(b) for b in data[5:11])
        result["obis"]         = obis
        result["attribute_id"] = data[11]
        result["obis_meaning"] = OBIS_CODES.get(obis, "Unknown OBIS")
        if obis.startswith("0.0.43."):
            result["findings"].append({
                "type":     "Read on Security Setup Object",
                "severity": "HIGH",
                "description": f"OBIS {obis} exposes key material. Ensure client is authenticated at HLS.",
            })


# ═══════════════════════════════════════════════════════════════════════════
# WIRELESS M-BUS (EN 13757-4) — European short-range (868 / 169 MHz)
# ═══════════════════════════════════════════════════════════════════════════

WMBUS_MANUFACTURERS = {
    "KAM":"Kamstrup",   "ITR":"Itron",       "LGZ":"Landis+Gyr",
    "ELS":"Elster",     "SEN":"Sensus",      "AMT":"Aichi",
    "ABB":"ABB",        "SIE":"Siemens",     "SCH":"Schneider",
    "EMH":"EMH Metering","DAN":"Danfoss",    "SON":"Sontex",
    "TCH":"Techem",     "EFE":"Engelmann",   "QDS":"Qundis",
    "HYD":"Hydrometer", "APA":"Apator",      "DVG":"Diehl",
    "ZRM":"Zenner",     "MAD":"Maddalena",   "BMT":"BMeters",
    "EDM":"EDMI",       "AID":"Aidon",       "SGM":"Sagemcom",
}

WMBUS_CI_FIELD = {
    0x5A: "TPL header short — no encryption",
    0x5B: "TPL header short — mode 5 (AES-CBC-IV)",
    0x60: "TPL header long — no encryption",
    0x61: "TPL header long — mode 5 (AES-CBC-IV)",
    0x64: "TPL header long — mode 7 (AES-CBC-IV variable key)",
    0x65: "TPL header long — mode 9 (AES-CMAC)",
    0x66: "TPL header long — mode 8 (AES-GCM)",
    0x67: "TPL header long — mode 13 (AES-CBC-CGM)",
    0x72: "Long transport layer",
    0x7A: "Short transport layer",
    0x8A: "AFL frame (Authentication and Fragmentation)",
}

WMBUS_DEVICE_TYPES = {
    0x02:"Electricity meter", 0x03:"Gas meter",       0x04:"Heat meter (outlet)",
    0x06:"Warm water meter",  0x07:"Water meter",     0x08:"Heat cost allocator",
    0x0A:"Cooling meter",     0x15:"Hot water",       0x16:"Cold water",
    0x17:"Dual water",        0x1A:"Smoke detector",  0x1F:"Radio converter (meter)",
    0x25:"Communication controller", 0x37:"Radio converter (meter)",
}


def parse_wmbus_telegram(hex_string: str) -> dict:
    """Parse a Wireless M-Bus telegram (EN 13757-4).
    Format: L | C | M(2) | A(6: ID+Version+Type) | CI | payload"""
    result = {"timestamp": datetime.utcnow().isoformat(), "findings": []}
    try:
        clean = re.sub(r"[^0-9a-fA-F]", "", hex_string)
        data  = binascii.unhexlify(clean)
    except Exception as e:
        return {"error": f"Invalid hex: {e}"}
    if len(data) < 10:
        return {"error": "Frame too short (min 10 bytes)"}

    result["length"]    = data[0]
    result["c_field"]   = f"0x{data[1]:02X}"
    result["direction"] = "meter → concentrator" if (data[1] & 0x40) else "concentrator → meter"

    m_bytes = int.from_bytes(data[2:4], "little")
    ch1 = chr(((m_bytes >> 10) & 0x1F) + 64)
    ch2 = chr(((m_bytes >>  5) & 0x1F) + 64)
    ch3 = chr(( m_bytes        & 0x1F) + 64)
    manufacturer_code = ch1 + ch2 + ch3
    result["manufacturer_code"] = manufacturer_code
    result["manufacturer"]      = WMBUS_MANUFACTURERS.get(manufacturer_code, "Unknown")

    result["meter_id"]         = binascii.hexlify(data[4:8][::-1]).decode().upper()
    result["version"]          = data[8]
    result["device_type"]      = data[9]
    result["device_type_name"] = WMBUS_DEVICE_TYPES.get(data[9], f"Unknown (0x{data[9]:02X})")

    if len(data) >= 11:
        ci = data[10]
        result["ci_field"]   = f"0x{ci:02X}"
        result["ci_meaning"] = WMBUS_CI_FIELD.get(ci, f"Unknown CI (0x{ci:02X})")

        if ci in (0x5A, 0x60):
            result["findings"].append({
                "type":     "Wireless M-Bus telegram is UNENCRYPTED",
                "severity": "HIGH",
                "description": "CI field indicates no encryption. All meter readings broadcast in the "
                               "clear on 868 MHz — anyone with RTL-SDR (~$25) can decode.",
                "remediation": "Configure meter for AES-128 mode 5 or higher. Rotate keys quarterly.",
            })
        elif ci in (0x5B, 0x61):
            result["findings"].append({
                "type":     "Wireless M-Bus mode 5 (AES-CBC with IV)",
                "severity": "MEDIUM",
                "description": "Mode 5 = AES-CBC-128. Vulnerable if manufacturer reuses default keys.",
                "remediation": "Ensure per-meter unique keys. Verify manufacturer key-derivation.",
            })
        elif ci in (0x65, 0x66):
            result["findings"].append({
                "type":     f"Wireless M-Bus AEAD mode ({result['ci_meaning']})",
                "severity": "LOW",
                "description": "Authenticated encryption — current best practice.",
            })
    return result


# ═══════════════════════════════════════════════════════════════════════════
# ANSI C12.19 / C12.22 — North American AMI protocol
# ═══════════════════════════════════════════════════════════════════════════

C12_TABLES = {
    0:"General Configuration", 1:"General Manufacturer Identification",
    5:"Device Identification", 6:"Utility Information",
    7:"Procedure Response",    8:"Procedure Initiate",
    23:"Register Data",        25:"Actual Event Log",
    28:"Actual Load Profile",  42:"Actual Communication",
    46:"Password / Key",       50:"State Table",
    52:"Current Time and Date",63:"Load Profile Data Set 1",
}

C12_SERVICES = {
    0x20:"Identification Request", 0x21:"Logon Request",
    0x22:"Security Request (password/session key)", 0x23:"Logoff Request",
    0x24:"Negotiate", 0x30:"Read Full Table",
    0x31:"Read Partial Table (index)", 0x38:"Write Full Table",
    0x39:"Write Partial Table (index)", 0x50:"Acknowledgement", 0x60:"Terminate",
}


def analyze_c12_packet(hex_string: str) -> dict:
    """Analyse an ANSI C12.22 packet."""
    result = {"timestamp": datetime.utcnow().isoformat(), "findings": []}
    try:
        clean = re.sub(r"[^0-9a-fA-F]", "", hex_string)
        data  = binascii.unhexlify(clean)
    except Exception as e:
        return {"error": f"Invalid hex: {e}"}
    if len(data) < 3:
        return {"error": "Packet too short"}

    svc = data[0]
    result["service"]      = f"0x{svc:02X}"
    result["service_name"] = C12_SERVICES.get(svc, f"Unknown (0x{svc:02X})")

    if svc in (0x30, 0x31, 0x32, 0x33, 0x34) and len(data) >= 3:
        table_id = int.from_bytes(data[1:3], "big")
        result["table_id"]   = table_id
        result["table_name"] = C12_TABLES.get(table_id, f"Table {table_id}")
        if table_id == 46:
            result["findings"].append({
                "type":     "Read on Table 46 (Password/Key)",
                "severity": "CRITICAL",
                "description": "Attempt to read the password/security key table — indicator of credential extraction.",
            })
        if table_id in (7, 8):
            result["findings"].append({
                "type":     "Procedure Table access",
                "severity": "MEDIUM",
                "description": f"Table {table_id} triggers meter procedures (disconnect, firmware update).",
            })

    if svc == 0x22:
        result["findings"].append({
            "type":     "Security Request (0x22)",
            "severity": "HIGH",
            "description": "Password/session-key transmission. If unencrypted, credentials recoverable via sniffing.",
            "remediation": "Enforce C12.22 EAX authentication + AES-128 encryption.",
        })
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Smart meter CVE lookup — real NVD API
# ═══════════════════════════════════════════════════════════════════════════

METER_VENDORS = [
    "Itron","Landis+Gyr","Sensus","Elster","Kamstrup","Aidon","Sagemcom","EDMI",
    "Circutor","Iskra","Ziv","Aclara","Honeywell","Schneider Electric","Siemens",
    "GE Digital Energy","ABB","Diehl","Techem","Qundis","Zenner","Apator","Hydrometer",
    "Chint","Hexing","SGCC","Wasion","Holley Metering","Camtel Metering","MTN Grid",
]


def smart_meter_cve_lookup(vendor: str, keyword: str = "") -> dict:
    """Query NVD for smart-meter CVEs by vendor and optional keyword."""
    result = {"vendor": vendor, "keyword": keyword,
              "timestamp": datetime.utcnow().isoformat(), "cves": []}
    if not REQ_OK:
        return {"error": "requests not installed"}
    query = " ".join(filter(None, [vendor, keyword, "smart meter"])).strip()
    try:
        r = req.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query, "resultsPerPage": 30},
            timeout=15,
        )
        if r.status_code != 200:
            return {"error": f"NVD API returned HTTP {r.status_code}"}
        data = r.json()
        for item in data.get("vulnerabilities", []):
            cve  = item.get("cve", {})
            desc = next((d.get("value","") for d in cve.get("descriptions",[])
                         if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score, severity = "", ""
            for k, v in metrics.items():
                if v:
                    cvss = v[0].get("cvssData", {})
                    score    = cvss.get("baseScore", "")
                    severity = cvss.get("baseSeverity", "")
                    break
            result["cves"].append({
                "id":          cve.get("id", ""),
                "description": desc[:400],
                "cvss":        score,
                "severity":    severity,
                "published":   cve.get("published", "")[:10],
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve.get('id','')}",
            })
    except Exception as e:
        result["error"] = str(e)
    result["count"] = len(result["cves"])
    return result


# ═══════════════════════════════════════════════════════════════════════════
# HES / MDMS endpoint scanner
# ═══════════════════════════════════════════════════════════════════════════

HES_KNOWN_PATHS = [
    "/AIMS", "/aims/index.html", "/AMR", "/Command_Center", "/CommandCenter",
    "/openway", "/OpenWay", "/OpenWayRiva", "/riva", "/CollectionEngine",
    "/RegionalNet", "/flexnet", "/FlexNet", "/rmc", "/RMC",
    "/SagemAMR", "/Siconia", "/COOX", "/gateway",
    "/EziView", "/EDMI", "/READy", "/Kem", "/METER-Manager",
    "/aidon", "/gateway/aidon",
    "/mdms", "/MDMS", "/oracle/mdms", "/mdm", "/api/meter", "/api/reading",
    "/dr", "/dr/api", "/loadcontrol", "/hes", "/HES",
    "/system/tools", "/diagnostics", "/status", "/admin",
]


def hes_endpoint_scan(target_url: str) -> dict:
    """Probe common HES / MDMS admin paths on a target."""
    result = {"target": target_url, "timestamp": datetime.utcnow().isoformat(),
              "responsive": [], "authenticated": [], "unreachable": [], "findings": []}
    if not REQ_OK:
        return {"error": "requests not installed"}
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    target_url = target_url.rstrip("/")

    for path in HES_KNOWN_PATHS:
        url = target_url + path
        try:
            r = req.get(url, timeout=6, verify=False, allow_redirects=False)
            entry = {"path": path, "status": r.status_code,
                     "size": len(r.content), "server": r.headers.get("Server","")}
            if r.status_code == 200:
                entry["risk"] = "HIGH — accessible without auth"
                result["responsive"].append(entry)
                result["findings"].append({
                    "type":     f"HES/MDMS path exposed: {path}",
                    "severity": "HIGH",
                    "description": f"HTTP 200 on {path} — probable Head-End admin console.",
                    "remediation": "Restrict HES to VPN / management VLAN. Enable mTLS on all API endpoints.",
                })
            elif r.status_code in (401, 403):
                entry["risk"] = "MEDIUM — auth prompt / forbidden (endpoint exists)"
                result["authenticated"].append(entry)
            elif r.status_code in (301, 302):
                entry["risk"] = "MEDIUM — redirect"
                result["authenticated"].append(entry)
        except Exception:
            result["unreachable"].append(path)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Meter firmware analysis
# ═══════════════════════════════════════════════════════════════════════════

METER_FIRMWARE_INDICATORS = {
    "DLMS":            [b"COSEM", b"dlms", b"OBIS"],
    "ANSI C12":        [b"C12.19", b"C12.22", b"C1218", b"C1219"],
    "Wireless M-Bus":  [b"wmbus", b"WM-BUS", b"Kamstrup"],
    "Modbus":          [b"Modbus"],
    "Zigbee SEP":      [b"Smart Energy Profile", b"SEP 2.0"],
    "LoRaWAN":         [b"LoRaWAN", b"DevEUI", b"AppKey"],
    "MQTT":            [b"MQTT", b"CONNECT"],
    "DNP3":            [b"DNP3"],
}

METER_WEAK_CRYPTO_PATTERNS = [
    (b"DES-",         "DES encryption — broken since 1998"),
    (b"MD5",          "MD5 — cryptographically broken"),
    (b"SHA1",         "SHA-1 — deprecated, collisions possible"),
    (b"RC4",          "RC4 stream cipher — banned by IETF"),
    (b"AES-ECB",      "AES-ECB mode — no diffusion, vulnerable"),
    (b"\x00" * 16,    "Sixteen zero bytes — possible null cryptographic key"),
]


def analyze_meter_firmware(data: bytes, filename: str = "firmware.bin") -> dict:
    """Static analysis of a smart meter firmware image."""
    result = {
        "filename":  filename,
        "timestamp": datetime.utcnow().isoformat(),
        "size":      len(data),
        "sha256":    hashlib.sha256(data).hexdigest(),
        "md5":       hashlib.md5(data).hexdigest(),
        "protocols": [],
        "findings":  [],
    }
    for proto, patterns in METER_FIRMWARE_INDICATORS.items():
        if any(p in data for p in patterns):
            result["protocols"].append(proto)

    for pattern, desc in METER_WEAK_CRYPTO_PATTERNS:
        count = data.count(pattern)
        if count > 0:
            severity = "CRITICAL" if pattern == b"\x00" * 16 else "HIGH"
            result["findings"].append({
                "type":     f"Weak crypto indicator: {desc}",
                "severity": severity,
                "occurrences": count,
            })

    for m in re.finditer(
        rb"(?:password|passwd|passphrase|secret|apikey|key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-!@#\$%\^&\*]{4,40})",
        data, re.IGNORECASE
    ):
        result["findings"].append({
            "type":     "Hardcoded credential pattern",
            "severity": "CRITICAL",
            "sample":   m.group(0).decode("latin-1", errors="ignore")[:80],
        })

    for kw in [b"JTAG", b"UART", b"debug=1", b"factory_reset", b"telnet", b"root:"]:
        if kw in data:
            result["findings"].append({
                "type":     f"Debug/backdoor keyword: {kw.decode(errors='ignore')}",
                "severity": "MEDIUM",
                "description": "Firmware contains debug hooks that should be stripped for production.",
            })

    urls = re.findall(rb"https?://[^\s\"'<>]{4,120}", data)
    result["embedded_urls"] = list({u.decode("ascii", errors="ignore") for u in urls[:30]})
    ips = re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", data)
    result["embedded_ips"]  = list({i.decode() for i in ips[:20]})

    result["risk_score"] = min(100, sum(
        {"CRITICAL":25,"HIGH":10,"MEDIUM":4,"LOW":1}.get(f["severity"],1)
        for f in result["findings"]))
    result["verdict"] = ("HIGH RISK" if result["risk_score"] >= 60 else
                         "MEDIUM RISK" if result["risk_score"] >= 30 else
                         "LOW RISK")
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Key material analysis
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_METER_KEYS = {
    "00000000000000000000000000000000": "All-zero AES key — factory default on many DLMS meters",
    "0102030405060708090A0B0C0D0E0F10": "Sequential test key — IEC 62056 documentation",
    "0123456789ABCDEF0123456789ABCDEF": "Common example key from Kamstrup docs",
    "11111111111111111111111111111111": "IEC test vector",
    "2B7E151628AED2A6ABF7158809CF4F3C": "FIPS 197 AES example key (NEVER use in production)",
    "000102030405060708090A0B0C0D0E0F": "NIST test key",
}


def analyze_meter_key(key_hex: str) -> dict:
    result = {"key_hex": key_hex, "timestamp": datetime.utcnow().isoformat(), "findings": []}
    clean = re.sub(r"[^0-9a-fA-F]", "", key_hex).upper()
    if len(clean) not in (32, 48, 64):
        return {"error": f"Invalid length ({len(clean)} hex chars). Expected 32/48/64."}
    result["length_bits"] = len(clean) * 4

    if clean in DEFAULT_METER_KEYS:
        result["findings"].append({
            "type":     "KNOWN DEFAULT KEY",
            "severity": "CRITICAL",
            "match":    DEFAULT_METER_KEYS[clean],
            "remediation": "IMMEDIATELY rotate. This key is public and useless as protection.",
        })
    unique_bytes = len(set(clean[i:i+2] for i in range(0, len(clean), 2)))
    result["byte_diversity"] = f"{unique_bytes}/16 unique bytes"
    if unique_bytes < 8:
        result["findings"].append({
            "type":     "Low key entropy",
            "severity": "HIGH",
            "description": f"Only {unique_bytes} distinct byte values — brute-forceable much faster.",
        })
    if len(set([clean[i:i+8] for i in range(0, len(clean), 8)])) == 1:
        result["findings"].append({
            "type":     "Repeating 32-bit block",
            "severity": "CRITICAL",
            "description": "Same 4-byte block repeats across the entire key.",
        })
    try:
        decoded = binascii.unhexlify(clean).decode("ascii")
        if all(32 <= ord(c) < 127 for c in decoded):
            result["findings"].append({
                "type":     "Key is ASCII-encoded",
                "severity": "HIGH",
                "ascii":    decoded,
                "description": "Key derived from a plaintext string — likely low-entropy password.",
            })
    except Exception:
        pass
    if not result["findings"]:
        result["verdict"] = "No obvious weaknesses detected"
    return result


# ═══════════════════════════════════════════════════════════════════════════
# SDR + AMI attack playbook
# ═══════════════════════════════════════════════════════════════════════════

def sdr_playbook(protocol: str = "wmbus") -> dict:
    protocol = protocol.lower()
    phases = {
        "1. Reconnaissance": {
            "wmbus": [
                "# European = 868 MHz S/T-mode, US = 900 MHz, China = 470 MHz",
                "rtl_power -f 868.9M:869.7M:1k -g 40 -i 60 wmbus.csv",
                "# Or visual: gqrx tuned to 868.95 MHz — look for short bursts every 2-16 sec",
            ],
            "dlms": [
                "nmap -sV -p 4059 <target-range>    # DLMS/COSEM over TCP",
                "# DLMS over serial: connect optical probe to /dev/ttyUSB0 @ 9600 8E1",
            ],
            "c12": [
                "nmap -sV -p 1153,1155 <target-range>    # ANSI C12.22",
            ],
        }.get(protocol, ["nmap -sV --top-ports 1000 <target>"]),

        "2. Capture / Sniff": {
            "wmbus": [
                "# wmbusmeters — supports RTL-SDR & Amber USB",
                "wmbusmeters --logtelegrams stdout auto:t1",
                "# rtl_wmbus (github.com/xaelsouth/rtl-wmbus):",
                "rtl_sdr -f 868.95M -s 1.6M -g 40 - | ./build/rtl_wmbus -s",
            ],
            "dlms": [
                "sudo tcpdump -i eth0 -w dlms.pcap 'port 4059'",
                "picocom -b 9600 -d 8 -y e /dev/ttyUSB0 | tee dlms.log",
            ],
            "c12": [
                "sudo tcpdump -i eth0 -w c12.pcap 'port 1153 or port 1155'",
            ],
        }.get(protocol, ["sudo tcpdump -i eth0 -w traffic.pcap"]),

        "3. Analyse": {
            "wmbus": [
                "# Decrypt with meter key:",
                "wmbusmeters --logtelegrams=stdout meter1 auto ID KEY",
                "# Or paste hex into Wouapit-Hack /smart-metering → wM-Bus Parser tab",
            ],
            "dlms": [
                "# Paste APDU hex into /smart-metering → DLMS Parser tab",
                "# Live client: gurux.dlms (GXDLMSDirector on Windows, pip install gurux-dlms)",
            ],
            "c12": [
                "# Paste into /smart-metering → ANSI C12 Parser tab, or pip install metertools",
            ],
        }.get(protocol, ["# Upload to /smart-metering module tabs for parsing"]),

        "4. Exploitation (authorised only)": [
            "# Try LLS default passwords: 00000000, 12345678, admin, vendor defaults",
            "# Read Security Setup Object (OBIS 0.0.43.0.0.255) / C12.19 Table 46",
            "# Attempt firmware download via manufacturer OTA endpoint",
            "# Replay captured billing telegram with modified consumption",
        ],

        "5. Physical attacks": [
            "# Verify seal integrity (holographic seals, mm-wave scanning)",
            "# Optical probe: IEC 62056-21 IR interface (top of meter)",
            "# JTAG: locate test pads, use OpenOCD + Bus Pirate / JLink",
            "# UART: 3.3V TTL on debug header (baud 115200)",
            "# SPI flash dump: flashrom + CH341A programmer",
            "# Magnetic sensor bypass: mu-metal shielding",
            "# Current bypass: shunt CT — classic residential fraud",
        ],
    }
    return {
        "protocol":  protocol,
        "timestamp": datetime.utcnow().isoformat(),
        "hardware_options": [
            "RTL-SDR v3 (~$30) — RX only, 500 kHz–1.75 GHz",
            "HackRF One (~$300) — TX+RX, 1 MHz–6 GHz",
            "LimeSDR Mini (~$180) — 10 MHz–3.5 GHz",
            "USRP B200 mini (~$800) — professional-grade",
            "Optical probe (~$40) — IEC 62056-21 IR interface",
            "USB-to-serial (~$5) — for RS-485/RS-232 head-end",
        ],
        "phases": phases,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Physical audit checklist
# ═══════════════════════════════════════════════════════════════════════════

def physical_audit_checklist() -> dict:
    return {
        "title": "Smart Meter Physical Security Audit",
        "timestamp": datetime.utcnow().isoformat(),
        "categories": {
            "Tamper seals & enclosure": [
                {"check": "Holographic tamper seals intact and unique per meter", "severity": "HIGH"},
                {"check": "No visible drilling, cracking, or reflow marks", "severity": "MEDIUM"},
                {"check": "Meter cover screws show tamper-evident markings", "severity": "MEDIUM"},
                {"check": "Terminal cover sealed separately from meter cover", "severity": "HIGH"},
                {"check": "Anti-drill fill / potting compound over PCB", "severity": "MEDIUM"},
            ],
            "Optical / IR port (IEC 62056-21)": [
                {"check": "Optical port disabled or requires physical key/token", "severity": "HIGH"},
                {"check": "Authentication uses HLS (not LLS)", "severity": "CRITICAL"},
                {"check": "Password read/write via optical port logged to fraud log", "severity": "MEDIUM"},
                {"check": "Optical port timeout after 3 failed logon attempts", "severity": "MEDIUM"},
            ],
            "Debug / JTAG / UART": [
                {"check": "JTAG / SWD debug port disabled or fused-off in production", "severity": "CRITICAL"},
                {"check": "UART test pads disabled or authenticated", "severity": "HIGH"},
                {"check": "Boot ROM verifies signature of application firmware", "severity": "CRITICAL"},
                {"check": "SPI flash contents encrypted with per-device key", "severity": "HIGH"},
            ],
            "Anti-tampering sensors": [
                {"check": "Magnetic tampering detection (Hall-effect sensor)", "severity": "HIGH"},
                {"check": "Cover-open switch triggers fraud log entry", "severity": "HIGH"},
                {"check": "Reverse-current detection (energy theft)", "severity": "HIGH"},
                {"check": "Neutral-missing / current bypass detection", "severity": "MEDIUM"},
            ],
            "Communication interfaces": [
                {"check": "Wireless M-Bus AES-128 GCM enabled (mode 7 or 13)", "severity": "HIGH"},
                {"check": "Cellular NB-IoT/LTE-M SIM PIN + APN authentication", "severity": "MEDIUM"},
                {"check": "PLC (G3-PLC/PRIME) TDMA slot authentication", "severity": "MEDIUM"},
                {"check": "Zigbee HAN uses SEP 2.0 with per-device certificates", "severity": "MEDIUM"},
            ],
            "Firmware & software": [
                {"check": "Signed firmware upgrades only (no downgrade attack)", "severity": "CRITICAL"},
                {"check": "Secure boot chain verified (BootROM → bootloader → app)", "severity": "CRITICAL"},
                {"check": "Firmware version < 24 months old", "severity": "MEDIUM"},
                {"check": "No known CVEs for this firmware version", "severity": "HIGH"},
            ],
            "Key management": [
                {"check": "Per-meter unique keys (no fleet-wide default)", "severity": "CRITICAL"},
                {"check": "Keys stored in secure element / TPM, not plain flash", "severity": "HIGH"},
                {"check": "Key rotation policy documented and executed quarterly", "severity": "MEDIUM"},
                {"check": "Head-End key management server hardened + air-gapped", "severity": "HIGH"},
            ],
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
# Compliance mapping
# ═══════════════════════════════════════════════════════════════════════════

def compliance_mapping() -> dict:
    return {
        "title": "Smart Metering Compliance Frameworks",
        "timestamp": datetime.utcnow().isoformat(),
        "frameworks": {
            "IEC 62443-3-3 (ISA-99 SL 1-4)": [
                "SR 1.1 — Human user identification and authentication",
                "SR 1.2 — Software process and device identification",
                "SR 1.5 — Authenticator management",
                "SR 2.1 — Authorization enforcement",
                "SR 3.1 — Communication integrity",
                "SR 4.1 — Information confidentiality",
                "SR 5.1 — Network segmentation",
                "SR 7.6 — Network and security configuration settings",
            ],
            "IEC 62351 (Power system security)": [
                "Part 3 — TLS for network protocols",
                "Part 5 — IEC 60870-5 / DNP3 authentication",
                "Part 7 — Network management (SNMPv3)",
                "Part 8 — Role-based access control",
                "Part 9 — Key management",
            ],
            "NIST SP 800-82r3 (ICS Security)": [
                "PR.AC — Identity Management and Access Control",
                "PR.DS — Data Security (encryption at rest & transit)",
                "PR.IP — Information Protection Processes",
                "DE.CM — Continuous Monitoring",
                "RS.RP — Response Planning (incident response)",
            ],
            "NISTIR 7628 r1 (Smart Grid Cybersecurity)": [
                "SG.AC — Access Control (30+ requirements specific to AMI)",
                "SG.SC — System and Communications Protection",
                "SG.SI — System and Information Integrity",
                "SG.CM — Configuration Management",
            ],
            "ENISA — Smart Grid Threat Landscape": [
                "TA-01 — Insider threats (utility staff with meter access)",
                "TA-02 — Third-party supply chain (manufacturer keys)",
                "TA-06 — Physical attacks on infrastructure",
                "TA-08 — Nation-state actors targeting grid",
            ],
            "ISO/IEC 27019 (Energy utility ISMS)": [
                "Adds 33 sector-specific controls to ISO/IEC 27001",
                "Covers: physical protection of substations, process control safety, key management",
            ],
        },
    }
