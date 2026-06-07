"""
Telecom Security module — SS7, Diameter, SIP/VoIP, OSS/BSS, IMS, BGP, SIM, IMSI.
Authorized telecom infrastructure testing only.
"""
import re, hashlib, socket
from datetime import datetime

try:
    import requests as req
    REQ_OK = True
except ImportError:
    REQ_OK = False


# ── SS7 vulnerability assessment ──────────────────────────────────────────────
SS7_THREATS = {
    "SRI-SM Disclosure": {
        "severity":    "HIGH",
        "description": "SendRoutingInfoForSM attack reveals subscriber IMSI and current VLR/MSC.",
        "impact":      "Subscriber location tracking, IMSI harvesting for further attacks.",
        "mitigation":  "Filter MAP SRI-SM messages from untrusted GTs at STP level. Deploy SS7 firewall (Cat-1).",
    },
    "AnyTimeInterrogation (ATI)": {
        "severity":    "CRITICAL",
        "description": "ATI message returns subscriber location (Cell-ID, LAC) without subscriber consent.",
        "impact":      "Real-time location tracking of any subscriber globally.",
        "mitigation":  "Block ATI from external GTs. Whitelist legitimate VPLMN partners only (Cat-2).",
    },
    "USSD Notify Spoofing": {
        "severity":    "HIGH",
        "description": "UnstructuredSS-Notify injects fake USSD prompts to subscriber handset.",
        "impact":      "Social engineering, credential phishing via mobile.",
        "mitigation":  "Restrict UnstructuredSS-Notify to home network HLR (Cat-3).",
    },
    "InsertSubscriberData (ISD) Manipulation": {
        "severity":    "CRITICAL",
        "description": "ISD modifies subscriber profile: call forwarding, barring, supplementary services.",
        "impact":      "Call interception via unconditional forwarding, service denial.",
        "mitigation":  "ISD must only originate from home HLR. Block all external ISD (Cat-3).",
    },
    "CancelLocation Denial-of-Service": {
        "severity":    "HIGH",
        "description": "CancelLocation forces subscriber off network or onto attacker's IMSI catcher.",
        "impact":      "Targeted DoS, forced reconnection to rogue base station.",
        "mitigation":  "Verify CancelLocation source is current VLR. Apply velocity check (Cat-2).",
    },
    "UpdateLocation Hijack": {
        "severity":    "CRITICAL",
        "description": "UpdateLocation registers attacker VLR as subscriber's current location.",
        "impact":      "SMS interception, voice call interception, 2FA bypass.",
        "mitigation":  "Cross-check IMSI velocity. Block UpdateLocation from suspicious GTs (Cat-3).",
    },
    "ProvideSubscriberInfo (PSI)": {
        "severity":    "HIGH",
        "description": "PSI returns subscriber status, location and equipment information.",
        "impact":      "Surveillance, location tracking via legitimate-looking signaling.",
        "mitigation":  "Restrict PSI to home network only (Cat-2).",
    },
    "SendIMSI Lookup": {
        "severity":    "MEDIUM",
        "description": "SendIMSI returns IMSI for a given MSISDN — first stage of larger attacks.",
        "impact":      "IMSI harvesting for downstream SS7 attacks.",
        "mitigation":  "Block SendIMSI from external networks (Cat-1).",
    },
}

def ss7_assess(network_type: str = "operator") -> dict:
    """Generate an SS7 threat exposure report based on common attack categories."""
    result = {
        "network_type":   network_type,
        "timestamp":      datetime.utcnow().isoformat(),
        "threats":        [],
        "filter_categories": {
            "Cat-1": {"name": "Inbound filtering",  "status": "REQUIRED",
                      "description": "Filter SS7 messages that should never come from external networks"},
            "Cat-2": {"name": "Velocity & cross-check", "status": "REQUIRED",
                      "description": "Detect impossible subscriber movement between countries"},
            "Cat-3": {"name": "Subscriber-aware",   "status": "REQUIRED",
                      "description": "Validate source against subscriber's current VPLMN"},
        },
        "recommendations": [],
    }
    for name, info in SS7_THREATS.items():
        result["threats"].append({"attack": name, **info})
    result["recommendations"] = [
        "Deploy a Cat-1/2/3 compliant SS7 firewall at all international interconnect points.",
        "Implement velocity checks for UpdateLocation and CancelLocation messages.",
        "Subscribe to GSMA FS.11 / FS.19 threat intelligence and IR.77 specifications.",
        "Enable signaling logging and centralised SIEM correlation for all SS7 traffic.",
        "Conduct quarterly SS7 penetration tests using authorised vendors.",
        "Implement Home Routing for SMS to prevent SMS interception.",
    ]
    result["total_threats"] = len(result["threats"])
    return result


# ── Diameter (4G/5G) security assessment ──────────────────────────────────────
DIAMETER_THREATS = {
    "Authentication-Information-Request (AIR) Disclosure": {
        "severity":    "CRITICAL",
        "command":     "AIR (CC=318, App=S6a)",
        "description": "Unauthorised AIR retrieves authentication vectors from HSS.",
        "impact":      "Full subscriber authentication bypass, voice/SMS interception.",
        "mitigation":  "Implement Diameter Edge Agent (DEA) with topology hiding. Verify origin-realm.",
    },
    "Update-Location-Request (ULR) Hijack": {
        "severity":    "CRITICAL",
        "command":     "ULR (CC=316, App=S6a)",
        "description": "Fraudulent ULR registers subscriber at attacker MME.",
        "impact":      "Subscriber denial-of-service, traffic redirection, location forging.",
        "mitigation":  "Subscriber velocity check at DEA. Validate Visited-PLMN-Id against IR.21 records.",
    },
    "Cancel-Location-Request (CLR) DoS": {
        "severity":    "HIGH",
        "command":     "CLR (CC=317, App=S6a)",
        "description": "Fake CLR deregisters subscribers, causing service disruption.",
        "impact":      "Targeted denial-of-service per subscriber.",
        "mitigation":  "Verify CLR source matches subscriber's current serving MME.",
    },
    "Insert-Subscriber-Data (IDR/IDA) Tampering": {
        "severity":    "CRITICAL",
        "command":     "IDR (CC=319, App=S6a)",
        "description": "Modify subscriber profile: APN, QoS, barring, call forwarding.",
        "impact":      "Service profile manipulation, call interception, fraud.",
        "mitigation":  "IDR must originate only from HSS in home network. DEA strict filtering.",
    },
    "Notify-Request (NOR) Abuse": {
        "severity":    "MEDIUM",
        "command":     "NOR (CC=323, App=S6a)",
        "description": "Notification messages used to enumerate subscribers.",
        "impact":      "IMSI/MSISDN enumeration for downstream attacks.",
        "mitigation":  "Rate limit NOR. Log all NOR messages from external realms.",
    },
    "Reset-Request (RSR) Denial-of-Service": {
        "severity":    "HIGH",
        "command":     "RSR (CC=322, App=S6a)",
        "description": "RSR forces re-registration of large subscriber populations.",
        "impact":      "Mass denial-of-service event, signalling storm.",
        "mitigation":  "Rate-limit RSR per origin-host. Alert on RSR from unexpected realms.",
    },
}

def diameter_assess() -> dict:
    result = {
        "timestamp":     datetime.utcnow().isoformat(),
        "protocol":      "Diameter (RFC 6733)",
        "applications":  ["S6a (3GPP 29.272)", "S9 (29.215)", "Rx (29.214)", "Gx (29.212)", "Sh (29.328)"],
        "threats":       [],
        "controls":      [
            {"control": "Diameter Edge Agent (DEA)",
             "purpose": "Realm/origin-host validation, topology hiding, message filtering"},
            {"control": "Diameter Routing Agent (DRA)",
             "purpose": "Routing decisions and load distribution"},
            {"control": "Topology Hiding Configuration (THC)",
             "purpose": "Conceal internal HSS/MME identities from peering networks"},
            {"control": "IPsec / TLS over SCTP",
             "purpose": "Encrypt and authenticate Diameter peers"},
        ],
        "recommendations": [
            "Deploy DEA at every Diameter interconnect (IPX/GRX boundary).",
            "Enforce origin-realm / destination-realm whitelisting.",
            "Implement topology hiding for HSS, MME, S-GW identities.",
            "Verify Visited-PLMN-Id against GSMA IR.21 roaming database.",
            "Subscribe to GSMA FS.19 (Diameter Threat) and FS.21 specifications.",
            "Enable Diameter signaling logging with 90-day retention.",
        ],
    }
    for name, info in DIAMETER_THREATS.items():
        result["threats"].append({"attack": name, **info})
    result["total_threats"] = len(result["threats"])
    return result


# ── SIP / VoIP scanner ────────────────────────────────────────────────────────
def sip_scan(target_host: str, port: int = 5060) -> dict:
    """Probe SIP server: OPTIONS request to enumerate version & methods."""
    result = {
        "host":      target_host,
        "port":      port,
        "timestamp": datetime.utcnow().isoformat(),
        "responsive": False,
        "info":      {},
        "findings":  [],
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        options = (
            f"OPTIONS sip:{target_host} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP scanner.local;branch=z9hG4bK-wouapit\r\n"
            f"From: <sip:scanner@scanner.local>;tag=1\r\n"
            f"To: <sip:{target_host}>\r\n"
            f"Call-ID: wouapit-{datetime.utcnow().timestamp()}@scanner.local\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Max-Forwards: 70\r\n"
            f"User-Agent: Wouapit-Hack-SIP-Scanner\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode()
        sock.sendto(options, (target_host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        response = data.decode("utf-8", errors="ignore")
        result["responsive"] = True
        first = response.split("\r\n", 1)[0]
        result["info"]["status_line"] = first

        # Parse headers
        for line in response.split("\r\n"):
            if ":" in line:
                k, _, v = line.partition(":")
                k = k.strip().lower(); v = v.strip()
                if k in ("server", "user-agent", "allow", "supported", "require"):
                    result["info"][k] = v

        # Security checks
        server = result["info"].get("server", "") + " " + result["info"].get("user-agent", "")
        if any(v in server.lower() for v in ["asterisk 1.", "asterisk 11", "asterisk 13", "asterisk 14"]):
            result["findings"].append({
                "type":     "Outdated Asterisk Version",
                "severity": "HIGH",
                "evidence": server,
                "mitigation": "Upgrade to Asterisk 18 LTS or 20 LTS.",
            })
        if "freeswitch" in server.lower() and any(v in server for v in ["1.6", "1.8.0", "1.8.5"]):
            result["findings"].append({
                "type":     "Outdated FreeSWITCH",
                "severity": "HIGH",
                "evidence": server,
            })
        allow_hdr = result["info"].get("allow", "")
        if "REGISTER" in allow_hdr:
            result["findings"].append({
                "type":     "REGISTER Method Allowed",
                "severity": "INFO",
                "description": "Server accepts SIP REGISTER — verify auth and rate-limiting.",
                "mitigation": "Enforce digest authentication, fail2ban, account-lockout policy.",
            })
        if "INVITE" in allow_hdr:
            result["findings"].append({
                "type":     "INVITE Method Allowed",
                "severity": "INFO",
                "description": "Open SIP responder may be abused for toll fraud if auth is weak.",
                "mitigation": "Restrict INVITE to authenticated peers. Block international destinations by default.",
            })
        if not result["info"].get("server"):
            result["findings"].append({
                "type":     "Server Header Not Disclosed",
                "severity": "INFO",
                "description": "Good — server software is not advertised.",
            })
    except socket.timeout:
        result["error"] = "No SIP response (timeout). Port may be filtered or service down."
    except Exception as e:
        result["error"] = str(e)
    return result


def voip_recommendations() -> dict:
    return {
        "category": "VoIP / SIP Security Best Practices",
        "controls": [
            {"control": "TLS for SIP signalling (sips:)",
             "rationale": "Prevent signalling eavesdropping and registration hijack."},
            {"control": "SRTP for media",
             "rationale": "Encrypt voice payload between endpoints."},
            {"control": "Digest authentication + strong passwords",
             "rationale": "Prevent registration takeover and toll fraud."},
            {"control": "Rate limiting & fail2ban on REGISTER/INVITE",
             "rationale": "Mitigate brute-force and SIP scanning."},
            {"control": "Outbound dial-plan restrictions",
             "rationale": "Block premium-rate, international numbers by default."},
            {"control": "SBC (Session Border Controller) at network edge",
             "rationale": "Topology hiding, DoS protection, protocol normalisation."},
            {"control": "Network segmentation: VoIP VLAN",
             "rationale": "Isolate voice traffic from data network."},
            {"control": "Disable unused SIP methods",
             "rationale": "Reduce attack surface (e.g. SUBSCRIBE, NOTIFY if unused)."},
        ],
    }


# ── IMSI Catcher detection ────────────────────────────────────────────────────
def imsi_catcher_indicators() -> dict:
    return {
        "title":     "IMSI Catcher Detection Indicators",
        "timestamp": datetime.utcnow().isoformat(),
        "indicators": [
            {"indicator": "Sudden 2G fallback in 4G/5G area",
             "severity": "HIGH",
             "explanation": "Stingray-class devices force downgrade to 2G/GSM where encryption is weak (A5/0)."},
            {"indicator": "LAC (Location Area Code) change without geographic movement",
             "severity": "HIGH",
             "explanation": "Rogue cell often uses unique LAC to force LU procedure and capture IMSI."},
            {"indicator": "Cell-ID not matching operator's IR.21 records",
             "severity": "CRITICAL",
             "explanation": "Cell broadcasting on operator's MCC/MNC but with unregistered Cell-ID."},
            {"indicator": "Missing or invalid Neighbour Cell List",
             "severity": "MEDIUM",
             "explanation": "Rogue cells often broadcast empty neighbour list to retain UE attachment."},
            {"indicator": "Encryption indicator missing (A5/0)",
             "severity": "CRITICAL",
             "explanation": "Legitimate networks use A5/1 or A5/3. A5/0 = no encryption — clear sign of IMSI catcher."},
            {"indicator": "Abnormally strong signal in unusual location",
             "severity": "MEDIUM",
             "explanation": "Mobile IMSI catchers broadcast at high power to force UEs to camp."},
            {"indicator": "Same Cell-ID seen across multiple geographic locations",
             "severity": "HIGH",
             "explanation": "Mobile/portable IMSI catchers carry their cell config across locations."},
            {"indicator": "Identity Request received without Authentication Request",
             "severity": "CRITICAL",
             "explanation": "Legitimate network completes AKA. IMSI catcher only needs identity."},
        ],
        "tools": [
            "SnoopSnitch (Android, requires Qualcomm chipset + root)",
            "AIMSICD (Android)",
            "Cell-Spy-Catcher",
            "OpenBTS-based monitoring",
            "Operator's drive-test tools (TEMS, Nemo)",
        ],
        "recommendations": [
            "Deploy passive RF monitoring sensors in sensitive locations (government buildings, embassies).",
            "Enable encryption indicator alerts on enterprise mobile devices (MDM policy).",
            "Distribute corporate phones with 2G disabled where coverage allows.",
            "Maintain up-to-date Cell-ID database and alert on anomalies.",
        ],
    }


# ── OSS / BSS security assessment ─────────────────────────────────────────────
OSS_BSS_DOMAINS = {
    "Network Management System (NMS)": {
        "examples": "HP NNMi, IBM Tivoli, SolarWinds, Nokia NetAct, Ericsson OSS",
        "risks":    ["Hardcoded SNMP community strings",
                     "Unpatched servers in management plane",
                     "Default credentials on network elements",
                     "Lack of network segmentation between OSS and production",
                     "Insufficient audit logging of configuration changes"],
        "controls": ["Dedicated OAM VLAN with strict firewall ACLs",
                     "SNMPv3 with authentication and encryption only",
                     "PAM/Bastion host for all NE access (e.g. CyberArk)",
                     "MFA for all OSS/BSS administrators",
                     "Centralised configuration backup and version control"],
    },
    "Element Management System (EMS)": {
        "examples": "Nokia NetAct, Ericsson OSS-RC, Huawei U2000, ZTE NetNumen",
        "risks":    ["Direct access to network elements from EMS",
                     "Shared credentials across operations team",
                     "Legacy protocols (Telnet, FTP) still enabled",
                     "EMS exposed to corporate LAN"],
        "controls": ["Disable Telnet/FTP — use SSH/SFTP/HTTPS only",
                     "Role-based access with named accounts (no shared logins)",
                     "TACACS+/RADIUS centralised authentication",
                     "Session recording for privileged operations"],
    },
    "Charging / Billing Mediation": {
        "examples": "Comverse, Amdocs CRM, Ericsson BSCS, Huawei CBS",
        "risks":    ["Database credentials in clear text in config files",
                     "Charging data records (CDR) exposed during transfer",
                     "Insufficient validation of mediation input",
                     "Insider fraud via direct DB access"],
        "controls": ["Encrypt CDR transfers (SFTP, IPsec)",
                     "Database activity monitoring (DAM) on billing DBs",
                     "Separation of duties: dev/test/prod environments",
                     "Tokenisation of subscriber identifiers in non-prod"],
    },
    "Subscriber Provisioning / CRM": {
        "examples": "Amdocs CES, Oracle CRM, Salesforce Telco Cloud",
        "risks":    ["Excessive privileges for CSR (Customer Service Reps)",
                     "Lack of approval workflow for high-value changes",
                     "API tokens not rotated",
                     "PII exposed in logs and screenshots"],
        "controls": ["Least-privilege RBAC per CSR role",
                     "Approval workflow for SIM swap, MSISDN change",
                     "PII masking in CRM UI and logs",
                     "Quarterly access reviews"],
    },
    "Service Activation / Orchestration": {
        "examples": "Netcracker, Amdocs OMS, custom platforms",
        "risks":    ["Direct API access without rate limiting",
                     "Privileged service accounts with static passwords",
                     "Lack of change tracking on orchestration scripts"],
        "controls": ["API gateway with rate limiting and authentication",
                     "Privileged Access Management (PAM) for service accounts",
                     "GitOps for orchestration scripts with peer review"],
    },
}

def oss_bss_assess() -> dict:
    return {
        "title":          "OSS / BSS Security Assessment Framework",
        "timestamp":      datetime.utcnow().isoformat(),
        "domains":        OSS_BSS_DOMAINS,
        "common_findings": [
            "Legacy protocols (Telnet, FTP) still enabled on production elements",
            "SNMPv1/v2c with default community strings",
            "Shared accounts among operations staff",
            "Insufficient logging on charging/billing systems",
            "PII visible in mediation logs",
            "No MFA for OSS/BSS administrators",
            "Direct DB access from corporate LAN to billing DB",
        ],
        "frameworks":     ["ISO/IEC 27011 (Telecom-specific 27001)",
                           "GSMA NESAS / FS.18 / FS.19",
                           "3GPP TS 33.117 SCAS",
                           "NIST SP 800-53"],
        "recommendations": [
            "Implement dedicated OAM (Operations, Administration, Maintenance) network with strict ACLs.",
            "Deploy PAM/bastion host (CyberArk, BeyondTrust, Delinea) for all privileged access.",
            "Enforce MFA on all OSS/BSS administrator accounts.",
            "Quarterly access certification for OSS/BSS roles.",
            "Centralised SIEM correlation across NMS, EMS, billing, CRM.",
            "Annual telecom-specific penetration test (signaling + OSS).",
        ],
    }


# ── BGP & transport security ──────────────────────────────────────────────────
def bgp_route_check(asn: str) -> dict:
    result = {
        "asn":       asn,
        "timestamp": datetime.utcnow().isoformat(),
        "info":      {},
        "findings":  [],
    }
    if not REQ_OK:
        return {"error": "requests not installed"}
    asn_clean = asn.replace("AS", "").strip()
    try:
        # bgpview.io public API
        r = req.get(f"https://api.bgpview.io/asn/{asn_clean}",
                    headers={"User-Agent": "Wouapit-Hack"}, timeout=8)
        if r.status_code == 200:
            d = r.json().get("data", {})
            result["info"] = {
                "name":           d.get("name"),
                "description":    d.get("description_short"),
                "country":        d.get("country_code"),
                "rir":            d.get("rir_allocation", {}).get("rir_name"),
                "looking_glass":  d.get("looking_glass"),
                "email_contacts": d.get("email_contacts", [])[:3],
            }
        # Prefixes
        r2 = req.get(f"https://api.bgpview.io/asn/{asn_clean}/prefixes",
                     headers={"User-Agent": "Wouapit-Hack"}, timeout=8)
        if r2.status_code == 200:
            d2 = r2.json().get("data", {})
            v4 = d2.get("ipv4_prefixes", [])[:20]
            v6 = d2.get("ipv6_prefixes", [])[:10]
            result["prefixes_v4_count"] = len(d2.get("ipv4_prefixes", []))
            result["prefixes_v6_count"] = len(d2.get("ipv6_prefixes", []))
            result["sample_prefixes"]   = [p.get("prefix") for p in (v4 + v6)]

            # RPKI check on samples
            invalid_rpki = []
            for p in v4[:5]:
                rpki = p.get("roa_status", "Unknown")
                if rpki and rpki.lower() == "invalid":
                    invalid_rpki.append(p.get("prefix"))
            if invalid_rpki:
                result["findings"].append({
                    "type":       "RPKI Invalid Prefixes",
                    "severity":   "HIGH",
                    "prefixes":   invalid_rpki,
                    "mitigation": "Update ROAs to match origin AS; deploy ROV (Route Origin Validation) on uplinks.",
                })
    except Exception as e:
        result["error"] = str(e)

    # Generic BGP security recommendations
    result["recommendations"] = [
        "Publish ROAs (Route Origin Authorisations) for all prefixes in RPKI.",
        "Deploy ROV (Route Origin Validation) on all BGP sessions (drop invalids).",
        "Implement BGPsec or AS-path filtering with strict max-prefix limits.",
        "Apply RFC 7454 BGP operations and security best practices.",
        "Enable BGP TTL security (GTSM, RFC 5082) on all eBGP sessions.",
        "Subscribe to MANRS (Mutually Agreed Norms for Routing Security).",
        "Monitor for route leaks via BGPmon, Cloudflare Radar, or RIPE NCC tools.",
    ]
    return result


# ── 5G / IMS security checklist ───────────────────────────────────────────────
def fivegig_security_checklist() -> dict:
    return {
        "title":     "5G Core & IMS Security Assessment",
        "timestamp": datetime.utcnow().isoformat(),
        "categories": {
            "5G Service-Based Architecture (SBA)": [
                {"check": "Mutual TLS between all NFs (Network Functions)",
                 "spec":  "3GPP TS 33.501", "status": "REQUIRED"},
                {"check": "OAuth 2.0 access tokens for NF-to-NF API calls",
                 "spec":  "TS 33.501 §13.4", "status": "REQUIRED"},
                {"check": "Network Repository Function (NRF) authentication",
                 "spec":  "TS 33.501",     "status": "REQUIRED"},
                {"check": "SCP (Service Communication Proxy) deployed at SBA boundary",
                 "spec":  "TS 23.501",     "status": "RECOMMENDED"},
                {"check": "SEPP (Security Edge Protection Proxy) at PLMN interconnect",
                 "spec":  "TS 33.501 §13.2", "status": "REQUIRED for roaming"},
            ],
            "5G Subscriber Privacy": [
                {"check": "SUCI (SUbscription Concealed Identifier) used instead of IMSI in clear",
                 "spec":  "TS 33.501 §6.12", "status": "REQUIRED"},
                {"check": "Home network's public key provisioned on USIM",
                 "spec":  "TS 33.501", "status": "REQUIRED"},
                {"check": "Subscriber identity de-confidentialisation only inside home network",
                 "spec":  "TS 33.501", "status": "REQUIRED"},
            ],
            "IMS (IP Multimedia Subsystem) Security": [
                {"check": "IMS AKA mutual authentication between UE and P-CSCF",
                 "spec":  "3GPP TS 33.203", "status": "REQUIRED"},
                {"check": "IPsec ESP between UE and P-CSCF",
                 "spec":  "TS 33.203 Annex H", "status": "REQUIRED"},
                {"check": "Border Gateway / IMS-ALG between IMS networks",
                 "spec":  "TS 23.228", "status": "REQUIRED"},
                {"check": "Application Server (AS) trusted via SCSCF authentication",
                 "spec":  "TS 33.203", "status": "REQUIRED"},
            ],
            "VoLTE / VoNR": [
                {"check": "SRTP for media plane",
                 "spec":  "RFC 3711",       "status": "REQUIRED"},
                {"check": "SIP-over-TLS between UE and P-CSCF",
                 "spec":  "TS 24.229",      "status": "RECOMMENDED"},
                {"check": "Emergency call (E911/E112) routing tested",
                 "spec":  "TS 23.167",      "status": "REQUIRED"},
            ],
        },
        "frameworks": [
            "GSMA NESAS (Network Equipment Security Assurance Scheme)",
            "GSMA FS.20 (5G Security Issues)",
            "GSMA FS.36 (SEPP Implementation Guidelines)",
            "3GPP TS 33.501 (5G Security Architecture)",
            "ENISA 5G Security Toolbox",
        ],
        "recommendations": [
            "Conduct NESAS-aligned vendor assessment for all 5G core NFs.",
            "Deploy SEPP at every roaming/interconnect boundary with HTTPS/N32-f message protection.",
            "Enforce SUCI usage (no IMSI exposure on air interface).",
            "Implement 5G slicing security with isolation between slices.",
            "Pen-test the SBA APIs using OWASP API Security Top 10 methodology.",
        ],
    }


# ── SIM / eSIM security ───────────────────────────────────────────────────────
def sim_security_overview() -> dict:
    return {
        "title": "SIM / eSIM / iSIM Security",
        "timestamp": datetime.utcnow().isoformat(),
        "threats": [
            {"threat":   "SIMjacker / WIBattack",
             "severity": "CRITICAL",
             "description": "Exploits S@T Browser / WIB applet via binary SMS to extract location.",
             "mitigation": "Disable S@T Browser and WIB applets where possible. Filter binary SMS at SMSC."},
            {"threat":   "SIM Swap Fraud",
             "severity": "HIGH",
             "description": "Social engineering of customer support to port victim's MSISDN to attacker SIM.",
             "mitigation": "Strong KYC/identity verification, port-out PIN, 24-72h cooling period, MFA in CRM."},
            {"threat":   "Over-The-Air (OTA) Provisioning Abuse",
             "severity": "HIGH",
             "description": "Unauthorised OTA commands modify SIM file system, applets, settings.",
             "mitigation": "Strict OTA key management. Audit OTA commands. Use authenticated OTA (DES/3DES/AES)."},
            {"threat":   "eSIM Profile Hijack",
             "severity": "HIGH",
             "description": "Attacker downloads victim's eSIM profile by intercepting activation code.",
             "mitigation": "GSMA SGP.22 RSP specification. QR code displayed only on physical device. Confirmation code."},
            {"threat":   "Weak Authentication Keys (Ki)",
             "severity": "CRITICAL",
             "description": "Weak or exposed Ki keys allow SIM cloning.",
             "mitigation": "Use Milenage algorithm. HSM-protected Ki. Strict KMS for personalisation."},
        ],
        "best_practices": [
            "Implement port-out PIN for all subscribers (mandatory SIM swap protection).",
            "MFA for customer service staff performing SIM operations.",
            "Disable obsolete SIM toolkit applets (S@T, WIB).",
            "Use Milenage f1-f5 algorithm; deprecate COMP128v1/v2.",
            "Follow GSMA SGP.21/22 for eSIM consumer provisioning.",
            "Monitor for unusual provisioning patterns (mass swap, geographic anomalies).",
        ],
    }
