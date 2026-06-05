"""Cloud & Container Security — Docker image scanner, AWS/Azure/GCP misconfiguration."""
import re, json
from datetime import datetime

try:
    import requests as req
    REQ_OK = True
except ImportError:
    REQ_OK = False

# ── Docker image scanner ──────────────────────────────────────────────────────
SECRET_PATTERNS = [
    (r"(?i)(?:aws_access_key_id|aws_secret_access_key)\s*[=:]\s*([^\s\"']+)", "AWS Credential"),
    (r"AKIA[0-9A-Z]{16}",                        "AWS Access Key"),
    (r"(?i)api[_-]?key\s*[=:]\s*([A-Za-z0-9_\-]{20,})", "API Key"),
    (r"(?i)password\s*[=:]\s*([^\s\"']{8,})",    "Password"),
    (r"(?i)secret\s*[=:]\s*([A-Za-z0-9_\-]{16,})","Secret"),
    (r"(?i)token\s*[=:]\s*([A-Za-z0-9_\-\.]{20,})","Token"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)jdbc:[a-z]+://[^\s\"']+",             "DB Connection String"),
    (r"mongodb(?:\+srv)?://[^\s\"']+",            "MongoDB URI"),
]

DANGEROUS_DOCKERFILE_PATTERNS = [
    (r"USER\s+root",               "Running as root",                  "HIGH",
     "Use a non-root user (e.g. USER appuser)"),
    (r"--privileged",              "Privileged container mode",         "CRITICAL",
     "Remove --privileged flag"),
    (r"EXPOSE\s+22\b",             "SSH exposed in container",         "HIGH",
     "Remove SSH from container. Use kubectl exec instead."),
    (r"curl\s+[^|]+\|\s*(?:bash|sh)", "Curl-pipe-bash (supply chain)", "CRITICAL",
     "Download and verify files before executing"),
    (r"(?i)apt-get\s+install.*--no-install-recommends\s+ssh", "SSH installed", "HIGH",
     "Remove SSH from production containers"),
    (r"ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)\s*=\s*\S+", "Secret in ENV", "CRITICAL",
     "Use Docker secrets or env files excluded from VCS"),
    (r"ADD\s+https?://",           "Downloading from internet in ADD", "MEDIUM",
     "Use COPY with verified local files instead of ADD URL"),
    (r"COPY\s+\..*\s+/",           "Copying entire context to root",   "MEDIUM",
     "Be specific about files copied"),
    (r"RUN\s+chmod\s+[74][74][74]","World-writable/executable permissions","HIGH",
     "Use minimal permissions (e.g. 755 not 777)"),
]

def scan_dockerfile(content: str) -> dict:
    result = {"timestamp": datetime.utcnow().isoformat(),
              "vulnerabilities": [], "secrets": [], "layers": [], "base_image": ""}
    lines = content.splitlines()
    # Extract base image
    for line in lines:
        if line.strip().upper().startswith("FROM"):
            result["base_image"] = line.strip()
            _check_base_image(line, result)
            break
    # Pattern checks
    for pattern, desc, sev, remediation in DANGEROUS_DOCKERFILE_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                result["vulnerabilities"].append({
                    "line":        i,
                    "content":     line.strip()[:100],
                    "type":        desc,
                    "severity":    sev,
                    "remediation": remediation,
                })
    # Secret detection
    for pattern, label in SECRET_PATTERNS:
        for i, line in enumerate(lines, 1):
            m = re.search(pattern, line)
            if m:
                result["secrets"].append({
                    "line":    i,
                    "type":    label,
                    "content": line.strip()[:80],
                    "severity": "CRITICAL",
                })
    # Multi-stage check
    from_count = sum(1 for l in lines if l.strip().upper().startswith("FROM"))
    result["multi_stage"]    = from_count > 1
    result["layer_count"]    = sum(1 for l in lines if l.strip().upper().startswith(("RUN","COPY","ADD")))
    result["risk_score"]     = min(100, len(result["vulnerabilities"])*8 + len(result["secrets"])*15)
    result["total_findings"] = len(result["vulnerabilities"]) + len(result["secrets"])
    return result


def _check_base_image(from_line: str, result: dict):
    from_line_lower = from_line.lower()
    if ":latest" in from_line_lower or (
        ":" not in from_line_lower.replace("from","")
    ):
        result["vulnerabilities"].append({
            "type":        "Unpinned Base Image",
            "severity":    "MEDIUM",
            "content":     from_line.strip(),
            "remediation": "Pin to specific digest: FROM ubuntu:22.04@sha256:...",
        })
    dangerous_bases = ["ubuntu:18.04","ubuntu:16.04","debian:jessie","debian:stretch",
                       "centos:6","centos:7","alpine:3.11","node:14","python:3.7",
                       "php:7.2","php:7.3"]
    for db in dangerous_bases:
        if db in from_line_lower:
            result["vulnerabilities"].append({
                "type":        f"EOL/Outdated Base Image: {db}",
                "severity":    "HIGH",
                "remediation": "Update to a supported, patched base image",
            })


def scan_env_file(content: str) -> dict:
    result = {"timestamp": datetime.utcnow().isoformat(),
              "findings": [], "variables": []}
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            key = key.strip(); val = val.strip().strip('"\'')
            result["variables"].append(key)
            # Check for sensitive values
            sensitive_keys = ["PASSWORD","SECRET","KEY","TOKEN","CREDENTIAL","DSN","PASSPHRASE",
                               "PRIVATE","CERT","AWS","AZURE","GCP","DB_PASS","API"]
            if any(s in key.upper() for s in sensitive_keys) and val and val not in ("","null","undefined","CHANGEME","xxx"):
                result["findings"].append({
                    "line":     i,
                    "key":      key,
                    "value":    val[:8]+"…" if len(val)>8 else val,
                    "severity": "CRITICAL",
                    "type":     "Sensitive Variable with Real Value",
                    "remediation": f"Remove {key} from .env. Use vault/secrets manager.",
                })
            # Check for default/weak values
            weak_values = ["password","123456","admin","test","changeme","secret","default","pass"]
            if val.lower() in weak_values:
                result["findings"].append({
                    "line":     i,
                    "key":      key,
                    "severity": "HIGH",
                    "type":     f"Weak Default Value: {val}",
                    "remediation": f"Change {key} to a strong, unique value.",
                })
    result["total"] = len(result["findings"])
    return result


# ── AWS Misconfiguration Scanner ─────────────────────────────────────────────
def scan_aws_config(config_text: str) -> dict:
    result = {"timestamp": datetime.utcnow().isoformat(),
              "findings": [], "info": {}}
    # Try JSON (IAM policy)
    try:
        policy = json.loads(config_text)
        return _analyze_iam_policy(policy)
    except json.JSONDecodeError:
        pass
    # AWS credentials file
    lines = config_text.splitlines()
    has_key = any("aws_access_key_id" in l.lower() for l in lines)
    has_secret = any("aws_secret_access_key" in l.lower() for l in lines)
    if has_key or has_secret:
        result["findings"].append({
            "type":        "AWS Credentials in Config File",
            "severity":    "CRITICAL",
            "description": "AWS credentials should use IAM roles, not static keys",
            "remediation": "Use IAM instance roles or AWS Secrets Manager",
        })
    # S3 public access
    if '"Principal":"*"' in config_text or '"Principal": "*"' in config_text:
        result["findings"].append({
            "type":        "S3 Bucket Public Access (Principal: *)",
            "severity":    "CRITICAL",
            "description": "Policy allows access to all principals — bucket is public",
            "remediation": "Restrict Principal to specific ARNs. Enable Block Public Access.",
        })
    # CloudTrail disabled
    if "cloudtrail" in config_text.lower() and "false" in config_text.lower():
        result["findings"].append({
            "type":        "CloudTrail Logging Disabled",
            "severity":    "HIGH",
            "remediation": "Enable CloudTrail in all regions for audit logging",
        })
    # Security Group issues
    if '"0.0.0.0/0"' in config_text or '"0.0.0.0/0"' in config_text:
        result["findings"].append({
            "type":        "Security Group Open to 0.0.0.0/0",
            "severity":    "HIGH",
            "description": "Inbound rule allows traffic from any IP",
            "remediation": "Restrict inbound rules to known IP ranges",
        })
    result["total"] = len(result["findings"])
    return result


def _analyze_iam_policy(policy: dict) -> dict:
    result = {"timestamp": datetime.utcnow().isoformat(),
              "policy_type": "IAM Policy", "findings": []}
    for stmt in policy.get("Statement",[]):
        effect    = stmt.get("Effect","")
        actions   = stmt.get("Action",[])
        resources = stmt.get("Resource",[])
        principal = stmt.get("Principal","")
        if isinstance(actions, str):  actions = [actions]
        if isinstance(resources,str): resources = [resources]
        # Wildcard action
        if "*" in actions or "iam:*" in actions or "s3:*" in actions:
            result["findings"].append({
                "type":        "Wildcard Action — Over-Privileged Policy",
                "severity":    "CRITICAL",
                "statement":   stmt,
                "description": f"Action '*' grants all permissions — violates least-privilege",
                "remediation": "Specify minimum required actions explicitly",
            })
        # Wildcard resource
        if "*" in resources and effect == "Allow":
            result["findings"].append({
                "type":        "Wildcard Resource",
                "severity":    "HIGH",
                "description": "Policy applies to all resources (*)",
                "remediation": "Restrict Resource to specific ARNs",
            })
        # Public principal
        if principal in ("*","AWS:*") or (isinstance(principal,dict) and "*" in str(principal)):
            result["findings"].append({
                "type":        "Public Principal (*)",
                "severity":    "CRITICAL",
                "description": "Policy grants access to any AWS principal",
                "remediation": "Restrict Principal to specific account ARNs",
            })
        # Dangerous admin actions
        admin_actions = ["iam:CreateUser","iam:AttachUserPolicy","iam:CreateAccessKey",
                         "sts:AssumeRole","ec2:RunInstances","lambda:InvokeFunction"]
        for aa in admin_actions:
            if aa in actions or "*" in actions:
                result["findings"].append({
                    "type":        f"High-Risk Action: {aa}",
                    "severity":    "HIGH",
                    "description": f"Granting {aa} can lead to privilege escalation",
                    "remediation": f"Restrict {aa} to necessary roles only",
                })
    result["total"] = len(result["findings"])
    return result


# ── Azure misconfiguration ────────────────────────────────────────────────────
def scan_azure_config(config_text: str) -> dict:
    result = {"timestamp": datetime.utcnow().isoformat(),
              "findings": [], "config_type": "Azure"}
    try:
        cfg = json.loads(config_text)
    except Exception:
        cfg = {}
        # Check ARM template text
        if "Microsoft.Storage/storageAccounts" in config_text:
            if '"allowBlobPublicAccess": true' in config_text:
                result["findings"].append({
                    "type":"Azure Blob Public Access Enabled","severity":"CRITICAL",
                    "remediation":"Set allowBlobPublicAccess: false"})
        if '"enableHttpsTrafficOnly": false' in config_text:
            result["findings"].append({
                "type":"Azure Storage HTTP Traffic Allowed","severity":"HIGH",
                "remediation":"Set enableHttpsTrafficOnly: true"})
        if '"minimumTlsVersion": "TLS1_0"' in config_text:
            result["findings"].append({
                "type":"Azure Storage TLS 1.0 Allowed","severity":"HIGH",
                "remediation":"Set minimumTlsVersion to TLS1_2"})
        result["total"] = len(result["findings"])
        return result
    # JSON analysis
    props = cfg.get("properties",cfg)
    if props.get("allowBlobPublicAccess") is True:
        result["findings"].append({"type":"Blob Public Access","severity":"CRITICAL",
                                   "remediation":"Disable allowBlobPublicAccess"})
    if props.get("enableHttpsTrafficOnly") is False:
        result["findings"].append({"type":"HTTP Traffic Allowed","severity":"HIGH",
                                   "remediation":"Enable HTTPS-only"})
    result["total"] = len(result["findings"])
    return result


# ── GCP misconfiguration ──────────────────────────────────────────────────────
def scan_gcp_config(config_text: str) -> dict:
    result = {"timestamp": datetime.utcnow().isoformat(),
              "findings": [], "config_type": "GCP"}
    try:
        cfg = json.loads(config_text)
    except Exception:
        cfg = {}
    # Bucket IAM
    bindings = cfg.get("bindings",[])
    for b in bindings:
        if "allUsers" in b.get("members",[]) or "allAuthenticatedUsers" in b.get("members",[]):
            result["findings"].append({
                "type":        "GCS Bucket Publicly Accessible",
                "severity":    "CRITICAL",
                "role":        b.get("role"),
                "description": "Bucket grants access to allUsers or allAuthenticatedUsers",
                "remediation": "Remove allUsers/allAuthenticatedUsers from IAM bindings",
            })
        if b.get("role") == "roles/owner" and len(b.get("members",[])) > 2:
            result["findings"].append({
                "type":    "Excessive Owner Roles",
                "severity":"HIGH",
                "remediation":"Reduce number of owner role assignments",
            })
    # Service account key check
    if "private_key" in config_text:
        result["findings"].append({
            "type":"GCP Service Account Key in Config","severity":"CRITICAL",
            "remediation":"Use Workload Identity instead of service account keys"})
    result["total"] = len(result["findings"])
    return result
