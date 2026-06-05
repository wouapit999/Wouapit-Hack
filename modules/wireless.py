"""Wireless Security — WiFi scanner simulation, WPA analysis, handshake tools."""
import re, hashlib, itertools
from datetime import datetime

# ── WiFi scan simulation ──────────────────────────────────────────────────────
SAMPLE_APS = [
    {"ssid":"Corporate-WiFi",   "bssid":"AA:BB:CC:11:22:33","channel":6,  "signal":-45,
     "encryption":"WPA2-Enterprise","cipher":"CCMP","auth":"MGT","vendor":"Cisco"},
    {"ssid":"Guest-Network",    "bssid":"AA:BB:CC:44:55:66","channel":11, "signal":-60,
     "encryption":"WPA2-Personal","cipher":"CCMP","auth":"PSK","vendor":"Ubiquiti"},
    {"ssid":"NETGEAR-Setup",    "bssid":"CC:DD:EE:77:88:99","channel":1,  "signal":-72,
     "encryption":"WPA2-Personal","cipher":"TKIP","auth":"PSK","vendor":"NETGEAR"},
    {"ssid":"OpenNet",          "bssid":"11:22:33:44:55:66","channel":6,  "signal":-80,
     "encryption":"OPEN",         "cipher":"NONE","auth":"NONE","vendor":"Unknown"},
    {"ssid":"",                 "bssid":"FF:EE:DD:CC:BB:AA","channel":36, "signal":-55,
     "encryption":"WPA2-Personal","cipher":"CCMP","auth":"PSK","vendor":"Apple",
     "hidden":True},
    {"ssid":"TP-Link_3F4A",     "bssid":"22:33:44:55:66:77","channel":9,  "signal":-65,
     "encryption":"WPA2-Personal","cipher":"CCMP","auth":"PSK","vendor":"TP-Link",
     "default_ssid":True},
]

def wifi_scan_simulation(interface: str = "wlan0") -> dict:
    result = {
        "interface":  interface,
        "timestamp":  datetime.utcnow().isoformat(),
        "access_points": [],
        "findings":   [],
        "note":       "Simulation mode — real WiFi scanning requires hardware access and root privileges",
    }
    for ap in SAMPLE_APS:
        ap_entry = {**ap, "risk": _assess_ap_risk(ap)}
        result["access_points"].append(ap_entry)
        # Generate findings
        if ap.get("encryption") == "OPEN":
            result["findings"].append({
                "ssid":        ap["ssid"] or "(hidden)",
                "bssid":       ap["bssid"],
                "type":        "Open Network — No Encryption",
                "severity":    "CRITICAL",
                "description": "Network transmits data in cleartext. Any nearby device can capture traffic.",
                "remediation": "Enable WPA2-Enterprise or WPA3. Never use open networks for sensitive data.",
            })
        if ap.get("encryption","").startswith("WPA2") and "TKIP" in ap.get("cipher",""):
            result["findings"].append({
                "ssid":        ap["ssid"],
                "type":        "WPA2 with TKIP — Weak Cipher",
                "severity":    "HIGH",
                "description": "TKIP is deprecated and vulnerable to attacks (KRACK, etc.)",
                "remediation": "Switch to CCMP/AES cipher suite.",
            })
        if ap.get("default_ssid"):
            result["findings"].append({
                "ssid":        ap["ssid"],
                "type":        "Default SSID Detected",
                "severity":    "MEDIUM",
                "description": "Default SSID reveals vendor/model — facilitates targeted attacks",
                "remediation": "Change SSID to a non-identifying name.",
            })
        if ap.get("hidden"):
            result["findings"].append({
                "ssid":        "(hidden)",
                "bssid":       ap["bssid"],
                "type":        "Hidden SSID Detected",
                "severity":    "LOW",
                "description": "Hidden SSIDs provide no real security — easily discovered with passive scanning",
                "remediation": "Hidden SSIDs are not a security control. Use proper authentication.",
            })
    result["total_aps"]       = len(result["access_points"])
    result["open_networks"]   = sum(1 for a in result["access_points"] if a["encryption"]=="OPEN")
    result["wpa3_networks"]   = sum(1 for a in result["access_points"] if "WPA3" in a["encryption"])
    result["hidden_networks"] = sum(1 for a in result["access_points"] if a.get("hidden"))
    return result


def _assess_ap_risk(ap: dict) -> str:
    enc = ap.get("encryption","")
    if enc == "OPEN":           return "CRITICAL"
    if "TKIP" in ap.get("cipher",""): return "HIGH"
    if "WEP" in enc:            return "CRITICAL"
    if "WPA2-Personal" in enc:  return "MEDIUM"
    if "WPA2-Enterprise" in enc:return "LOW"
    if "WPA3" in enc:           return "LOW"
    return "MEDIUM"


# ── WPA handshake analysis ────────────────────────────────────────────────────
def analyze_handshake_file(data: bytes, filename: str) -> dict:
    result = {
        "filename":  filename,
        "timestamp": datetime.utcnow().isoformat(),
        "valid":     False,
        "networks":  [],
        "info":      {},
    }
    # Check for PCAP magic
    if len(data) < 24:
        result["error"] = "File too small"
        return result
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        result["valid"]  = True
        result["format"] = "PCAP (little-endian)"
    elif magic == b"\xa1\xb2\xc3\xd4":
        result["valid"]  = True
        result["format"] = "PCAP (big-endian)"
    elif magic in (b"\x0a\x0d\x0d\x0a",):
        result["valid"]  = True
        result["format"] = "PCAPNG"
    elif magic[:2] == b"PK":
        result["valid"]  = True
        result["format"] = "Hashcat .hc22000 / ZIP"
    else:
        result["error"]  = "Unknown file format. Expected .cap, .pcap, .pcapng, or .hc22000"
        return result
    result["size"] = len(data)
    result["info"] = {
        "capture_tools": "Use: aircrack-ng, hashcat, or cowpatty to crack",
        "hashcat_mode":  "22000 (WPA-PMKID+EAPOL)",
        "aircrack_cmd":  f"aircrack-ng -w /path/to/wordlist {filename}",
        "hashcat_cmd":   f"hashcat -a 0 -m 22000 {filename} /path/to/wordlist.txt",
        "hcxtools_cmd":  f"hcxpcapngtool -o output.hc22000 {filename}",
    }
    result["recommendations"] = [
        "Use strong, random WPA2 passphrase (20+ chars)",
        "Prefer WPA3 which is resistant to offline dictionary attacks",
        "Use WPA2-Enterprise with certificate-based auth",
        "Monitor for deauthentication attacks (handshake capture precursor)",
    ]
    return result


# ── Mini wordlist cracker ─────────────────────────────────────────────────────
def crack_wpa_hash(pmkid_or_hash: str, ssid: str = "", wordlist_text: str = "") -> dict:
    result = {
        "hash":        pmkid_or_hash,
        "ssid":        ssid,
        "cracked":     False,
        "timestamp":   datetime.utcnow().isoformat(),
    }
    passwords = []
    if wordlist_text:
        passwords = [p.strip() for p in wordlist_text.splitlines() if p.strip()][:500]
    else:
        # Built-in mini list
        passwords = [
            "password","123456","12345678","qwerty","abc123","password1",
            "letmein","admin","welcome","monkey","dragon","master","sunshine",
            "iloveyou","princess","password123","pass","1234","test","guest",
            ssid, ssid+"1", ssid+"123", ssid+"2024", ssid+"2025",
            ssid.lower(), ssid.upper(),
        ]
    # For WPA2-PSK, real cracking needs PBKDF2-HMAC-SHA1
    for word in passwords:
        if not word:
            continue
        # Simulate: in real cracking we'd compute PMK = PBKDF2(HMAC-SHA1, word, ssid, 4096, 32)
        # Here we just check if hash matches SHA256(word) as demo
        candidate_hash = hashlib.sha256(word.encode()).hexdigest()
        if pmkid_or_hash.lower() == candidate_hash:
            result["cracked"]   = True
            result["password"]  = word
            result["note"]      = "Found via SHA-256 match (demo mode)"
            return result
    result["note"] = (
        f"Not found in {len(passwords)}-word list. "
        "For real WPA cracking use: hashcat -a 0 -m 22000 capture.hc22000 rockyou.txt"
    )
    result["wordlist_size"] = len(passwords)
    return result


# ── Rogue AP detection ────────────────────────────────────────────────────────
def detect_rogue_ap(known_networks: list, scanned_networks: list = None) -> dict:
    result = {
        "timestamp":    datetime.utcnow().isoformat(),
        "rogue_aps":    [],
        "evil_twins":   [],
        "warnings":     [],
    }
    if scanned_networks is None:
        scanned_networks = SAMPLE_APS[:]
    known_ssids  = {n.get("ssid","") for n in known_networks}
    known_bssids = {n.get("bssid","").upper() for n in known_networks}

    for ap in scanned_networks:
        ssid  = ap.get("ssid","")
        bssid = ap.get("bssid","").upper()
        # Evil twin: same SSID, different BSSID
        if ssid in known_ssids:
            if bssid not in known_bssids:
                result["evil_twins"].append({
                    "ssid":        ssid,
                    "rogue_bssid": bssid,
                    "type":        "Evil Twin Attack",
                    "severity":    "CRITICAL",
                    "description": f"Network '{ssid}' appears with unexpected BSSID {bssid}",
                    "remediation": "Investigate immediately. Users may be connecting to attacker AP.",
                })
        # Rogue: unknown SSID, open network
        if ssid not in known_ssids and ap.get("encryption") == "OPEN":
            result["rogue_aps"].append({
                "ssid":     ssid or "(hidden)",
                "bssid":    bssid,
                "type":     "Unknown Open Network",
                "severity": "HIGH",
                "description": "Unknown open access point detected in environment",
            })
        # Honey trap: open network with corporate-sounding name
        corporate_keywords = ["corp","office","company","internal","secure","vpn","mgmt","admin"]
        if any(k in ssid.lower() for k in corporate_keywords) and ap.get("encryption")=="OPEN":
            result["warnings"].append({
                "ssid":     ssid,
                "bssid":    bssid,
                "type":     "Suspicious Honeypot SSID",
                "severity": "HIGH",
                "description": "Open network with corporate-sounding name — possible honeypot/karma attack",
            })
    result["total_rogues"] = len(result["rogue_aps"]) + len(result["evil_twins"])
    return result
