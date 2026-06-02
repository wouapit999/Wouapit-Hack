import socket
import subprocess
import platform
import ipaddress
import concurrent.futures
from datetime import datetime


def ping_host(ip: str) -> dict | None:
    system = platform.system()
    flag = "-n" if system == "Windows" else "-c"
    cmd = ["ping", flag, "1", "-w", "1000" if system == "Windows" else "1", str(ip)]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=3)
        if result.returncode == 0:
            return {"ip": str(ip), "status": "up"}
    except Exception:
        pass
    return None


def ping_sweep(cidr: str) -> dict:
    result = {"target": cidr, "timestamp": datetime.utcnow().isoformat(), "hosts_up": [], "hosts_down": []}

    try:
        if "/" in cidr:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())[:254]
        else:
            hosts = [ipaddress.ip_address(cidr)]
    except ValueError as e:
        return {"error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(ping_host, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            h = futures[fut]
            if r:
                try:
                    hostname = socket.gethostbyaddr(str(h))[0]
                    r["hostname"] = hostname
                except Exception:
                    r["hostname"] = ""
                result["hosts_up"].append(r)
            else:
                result["hosts_down"].append(str(h))

    result["hosts_up"].sort(key=lambda x: socket.inet_aton(x["ip"]))
    result["up_count"] = len(result["hosts_up"])
    result["total_scanned"] = len(hosts)
    return result


def traceroute(host: str) -> dict:
    result = {"host": host, "timestamp": datetime.utcnow().isoformat(), "hops": []}
    system = platform.system()

    try:
        ip = socket.gethostbyname(host)
        result["ip"] = ip
    except Exception as e:
        return {"error": str(e)}

    if system == "Windows":
        cmd = ["tracert", "-d", "-h", "20", host]
    else:
        cmd = ["traceroute", "-n", "-m", "20", host]

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=30).decode(errors="ignore")
        lines = out.strip().split("\n")
        hop_num = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line) if hasattr(re, 'findall') else []
            import re as _re
            ips = _re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ips:
                hop_num += 1
                result["hops"].append({"hop": hop_num, "ip": ips[0], "raw": line})
            elif "*" in line and any(c.isdigit() for c in line):
                hop_num += 1
                result["hops"].append({"hop": hop_num, "ip": "*", "raw": line})
    except subprocess.TimeoutExpired:
        result["error"] = "Traceroute timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


def banner_grab(host: str, port: int = 80) -> dict:
    result = {"host": host, "port": port, "timestamp": datetime.utcnow().isoformat()}
    try:
        ip = socket.gethostbyname(host)
        result["ip"] = ip
    except Exception as e:
        return {"error": str(e)}

    probes = {
        80:  b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
        443: b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
        21:  b"",
        22:  b"",
        25:  b"",
        110: b"",
        143: b"",
        3306: b"",
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        probe = probes.get(port, b"")
        if probe:
            s.send(probe)
        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        result["banner"] = banner.strip()
    except Exception as e:
        result["error"] = str(e)

    return result
