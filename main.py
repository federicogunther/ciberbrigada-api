from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import asyncio
import subprocess
import json
import re
import os
import tempfile
from typing import Optional

app = FastAPI(title="Ciberbrigada OSINT API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TIMEOUT = 30

# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "online", "service": "Ciberbrigada OSINT API", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "ok"}

# ─────────────────────────────────────────────
# EMAIL - HaveIBeenPwned
# ─────────────────────────────────────────────
@app.get("/api/email/hibp")
async def check_hibp(email: str):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": os.getenv("HIBP_API_KEY", ""),
                    "user-agent": "Ciberbrigada-OSINT/1.0"
                },
                follow_redirects=True
            )
            if r.status_code == 404:
                return {"found": False, "breaches": [], "count": 0, "email": email}
            if r.status_code == 401:
                return {"error": "API key requerida para HIBP v3", "fallback": f"https://haveibeenpwned.com/account/{email}"}
            if r.status_code == 200:
                data = r.json()
                return {
                    "found": True,
                    "count": len(data),
                    "email": email,
                    "breaches": [
                        {
                            "name": b.get("Name"),
                            "domain": b.get("Domain"),
                            "date": b.get("BreachDate"),
                            "description": b.get("Description", "")[:200],
                            "data_classes": b.get("DataClasses", []),
                            "pwn_count": b.get("PwnCount", 0),
                        }
                        for b in data
                    ]
                }
            return {"error": f"HTTP {r.status_code}", "fallback": f"https://haveibeenpwned.com/account/{email}"}
    except Exception as e:
        return {"error": str(e), "fallback": f"https://haveibeenpwned.com/account/{email}"}

# ─────────────────────────────────────────────
# EMAIL - EmailRep
# ─────────────────────────────────────────────
@app.get("/api/email/rep")
async def check_emailrep(email: str):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"https://emailrep.io/{email}",
                headers={"User-Agent": "Ciberbrigada-OSINT/1.0"}
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "found": True,
                    "email": email,
                    "reputation": data.get("reputation", "unknown"),
                    "suspicious": data.get("suspicious", False),
                    "references": data.get("references", 0),
                    "details": data.get("details", {}),
                    "profiles": data.get("details", {}).get("profiles", []),
                    "blacklisted": data.get("details", {}).get("blacklisted", False),
                    "malicious_activity": data.get("details", {}).get("malicious_activity", False),
                    "spam": data.get("details", {}).get("spam", False),
                    "free_provider": data.get("details", {}).get("free_provider", False),
                    "disposable": data.get("details", {}).get("disposable", False),
                    "last_seen": data.get("details", {}).get("last_seen", ""),
                }
            return {"error": f"HTTP {r.status_code}", "fallback": f"https://emailrep.io/{email}"}
    except Exception as e:
        return {"error": str(e), "fallback": f"https://emailrep.io/{email}"}

# ─────────────────────────────────────────────
# IP / DOMINIO - IPinfo
# ─────────────────────────────────────────────
@app.get("/api/ip/info")
async def ip_info(query: str):
    try:
        token = os.getenv("IPINFO_TOKEN", "")
        url = f"https://ipinfo.io/{query}/json"
        if token:
            url += f"?token={token}"
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(url, headers={"User-Agent": "Ciberbrigada-OSINT/1.0"})
            if r.status_code == 200:
                data = r.json()
                return {
                    "found": True,
                    "query": query,
                    "ip": data.get("ip"),
                    "hostname": data.get("hostname"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "org": data.get("org"),
                    "timezone": data.get("timezone"),
                    "loc": data.get("loc"),
                    "postal": data.get("postal"),
                }
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────
@app.get("/api/domain/whois")
async def whois_lookup(domain: str):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"https://api.whois.vu/?q={domain}",
                headers={"User-Agent": "Ciberbrigada-OSINT/1.0"}
            )
            if r.status_code == 200:
                data = r.json()
                return {"found": True, "domain": domain, "data": data}

            # Fallback: rdap
            r2 = await client.get(
                f"https://rdap.org/domain/{domain}",
                headers={"User-Agent": "Ciberbrigada-OSINT/1.0"}
            )
            if r2.status_code == 200:
                d = r2.json()
                events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
                nameservers = [ns.get("ldhName", "") for ns in d.get("nameservers", [])]
                return {
                    "found": True,
                    "domain": domain,
                    "data": {
                        "registrar": next((e.get("value") for e in d.get("entities", []) if "registrar" in e.get("roles", [])), "N/A"),
                        "registered": events.get("registration", "N/A"),
                        "updated": events.get("last changed", "N/A"),
                        "expires": events.get("expiration", "N/A"),
                        "nameservers": nameservers,
                        "status": d.get("status", []),
                    }
                }
            return {"error": "No se pudo obtener WHOIS", "fallback": f"https://who.is/whois/{domain}"}
    except Exception as e:
        return {"error": str(e), "fallback": f"https://who.is/whois/{domain}"}

# ─────────────────────────────────────────────
# DNS LOOKUP
# ─────────────────────────────────────────────
@app.get("/api/domain/dns")
async def dns_lookup(domain: str):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            results = {}
            for rtype in ["A", "MX", "NS", "TXT", "AAAA"]:
                try:
                    r = await client.get(
                        f"https://dns.google/resolve?name={domain}&type={rtype}",
                        headers={"User-Agent": "Ciberbrigada-OSINT/1.0"}
                    )
                    if r.status_code == 200:
                        data = r.json()
                        results[rtype] = [a.get("data") for a in data.get("Answer", [])]
                except:
                    results[rtype] = []
            return {"found": True, "domain": domain, "records": results}
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
# VIRUSTOTAL - con API key del usuario
# ─────────────────────────────────────────────
@app.get("/api/domain/virustotal")
async def virustotal(query: str, apikey: str):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{query}",
                headers={"x-apikey": apikey, "User-Agent": "Ciberbrigada-OSINT/1.0"}
            )
            if r.status_code == 200:
                d = r.json().get("data", {}).get("attributes", {})
                stats = d.get("last_analysis_stats", {})
                return {
                    "found": True,
                    "query": query,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": d.get("reputation", 0),
                    "categories": d.get("categories", {}),
                    "registrar": d.get("registrar", ""),
                    "creation_date": d.get("creation_date", ""),
                    "country": d.get("country", ""),
                }
            return {"error": f"HTTP {r.status_code}", "fallback": f"https://www.virustotal.com/gui/domain/{query}"}
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
# ABUSEIPDB
# ─────────────────────────────────────────────
@app.get("/api/ip/abuse")
async def abuseipdb(ip: str, apikey: Optional[str] = None):
    try:
        key = apikey or os.getenv("ABUSEIPDB_KEY", "")
        if not key:
            return {"error": "API key requerida", "fallback": f"https://www.abuseipdb.com/check/{ip}"}
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": key, "Accept": "application/json"}
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                return {
                    "found": True,
                    "ip": ip,
                    "abuse_score": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode", ""),
                    "usage_type": d.get("usageType", ""),
                    "isp": d.get("isp", ""),
                    "domain": d.get("domain", ""),
                    "total_reports": d.get("totalReports", 0),
                    "last_reported": d.get("lastReportedAt", ""),
                    "is_whitelisted": d.get("isWhitelisted", False),
                }
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
# SHERLOCK - username search
# ─────────────────────────────────────────────
@app.get("/api/username/sherlock")
async def sherlock_search(username: str):
    try:
        result = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, _run_sherlock, username
            ),
            timeout=60
        )
        return result
    except asyncio.TimeoutError:
        return {"error": "Timeout - sherlock tardó más de 60s", "username": username, "command": f"python3 -m sherlock {username}"}
    except Exception as e:
        return {"error": str(e), "command": f"python3 -m sherlock {username}"}

def _run_sherlock(username: str):
    try:
        r = subprocess.run(
            ["python3", "-m", "sherlock", username, "--print-found", "--timeout", "10"],
            capture_output=True, text=True, timeout=55
        )
        found = []
        for line in r.stdout.splitlines():
            if line.startswith("[+]"):
                url = line.replace("[+]", "").strip()
                found.append(url)
        return {
            "found": len(found) > 0,
            "username": username,
            "count": len(found),
            "sites": found,
            "tool": "sherlock"
        }
    except FileNotFoundError:
        return {"error": "Sherlock no instalado", "command": f"python3 -m sherlock {username}"}
    except subprocess.TimeoutExpired:
        return {"error": "Timeout", "command": f"python3 -m sherlock {username}"}

# ─────────────────────────────────────────────
# HOLEHE - email to social accounts
# ─────────────────────────────────────────────
@app.get("/api/email/holehe")
async def holehe_search(email: str):
    try:
        result = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, _run_holehe, email
            ),
            timeout=90
        )
        return result
    except asyncio.TimeoutError:
        return {"error": "Timeout", "email": email, "command": f"holehe {email}"}
    except Exception as e:
        return {"error": str(e)}

def _run_holehe(email: str):
    try:
        r = subprocess.run(
            ["holehe", email, "--only-used", "--no-color"],
            capture_output=True, text=True, timeout=85
        )
        found = []
        not_found = []
        for line in r.stdout.splitlines():
            if "[+]" in line:
                site = line.split("[+]")[-1].strip()
                found.append(site)
            elif "[-]" in line:
                site = line.split("[-]")[-1].strip()
                not_found.append(site)
        return {
            "found": len(found) > 0,
            "email": email,
            "registered_on": found,
            "count": len(found),
            "tool": "holehe"
        }
    except FileNotFoundError:
        return {"error": "Holehe no instalado", "command": f"holehe {email}"}
    except subprocess.TimeoutExpired:
        return {"error": "Timeout"}

# ─────────────────────────────────────────────
# MAIGRET - deep username search
# ─────────────────────────────────────────────
@app.get("/api/username/maigret")
async def maigret_search(username: str):
    try:
        result = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, _run_maigret, username
            ),
            timeout=90
        )
        return result
    except asyncio.TimeoutError:
        return {"error": "Timeout", "username": username, "command": f"maigret {username}"}
    except Exception as e:
        return {"error": str(e)}

def _run_maigret(username: str):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            r = subprocess.run(
                ["maigret", username, "--json", f"{tmpdir}/result.json", "--timeout", "10", "--retries", "1"],
                capture_output=True, text=True, timeout=85
            )
            json_path = f"{tmpdir}/result.json"
            if os.path.exists(json_path):
                with open(json_path) as f:
                    data = json.load(f)
                found = []
                for site, info in data.items():
                    if isinstance(info, dict) and info.get("status") == "Claimed":
                        found.append({"site": site, "url": info.get("url", ""), "tags": info.get("tags", [])})
                return {"found": len(found) > 0, "username": username, "count": len(found), "sites": found, "tool": "maigret"}
            found = []
            for line in r.stdout.splitlines():
                if "[+]" in line:
                    found.append(line.replace("[+]", "").strip())
            return {"found": len(found) > 0, "username": username, "count": len(found), "sites": found, "tool": "maigret"}
    except FileNotFoundError:
        return {"error": "Maigret no instalado", "command": f"maigret {username}"}
    except subprocess.TimeoutExpired:
        return {"error": "Timeout"}

# ─────────────────────────────────────────────
# PHONEINFOGA
# ─────────────────────────────────────────────
@app.get("/api/phone/infoga")
async def phoneinfoga(number: str):
    try:
        result = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, _run_phoneinfoga, number
            ),
            timeout=30
        )
        return result
    except asyncio.TimeoutError:
        return {"error": "Timeout", "command": f"phoneinfoga scan -n \"{number}\""}
    except Exception as e:
        return {"error": str(e)}

def _run_phoneinfoga(number: str):
    try:
        r = subprocess.run(
            ["phoneinfoga", "scan", "-n", number],
            capture_output=True, text=True, timeout=25
        )
        output = r.stdout + r.stderr
        result = {"number": number, "raw": output, "tool": "phoneinfoga"}
        for line in output.splitlines():
            if "Country" in line:
                result["country"] = line.split(":")[-1].strip()
            if "Carrier" in line or "Operator" in line:
                result["carrier"] = line.split(":")[-1].strip()
            if "Line Type" in line:
                result["line_type"] = line.split(":")[-1].strip()
        result["found"] = len(output) > 50
        return result
    except FileNotFoundError:
        return {"error": "PhoneInfoga no instalado", "command": f"phoneinfoga scan -n \"{number}\""}
    except subprocess.TimeoutExpired:
        return {"error": "Timeout"}

# ─────────────────────────────────────────────
# EXIFTOOL - metadata from URL
# ─────────────────────────────────────────────
@app.get("/api/image/exif")
async def exif_from_url(url: str):
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 200:
                return {"error": f"No se pudo descargar la imagen: HTTP {r.status_code}"}
            with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
                tmp.write(r.content)
                tmp_path = tmp.name
        result = await asyncio.get_event_loop().run_in_executor(
            None, _run_exiftool, tmp_path
        )
        os.unlink(tmp_path)
        return result
    except Exception as e:
        return {"error": str(e)}

def _run_exiftool(path: str):
    try:
        r = subprocess.run(
            ["exiftool", "-j", path],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0:
            data = json.loads(r.stdout)[0]
            relevant = {}
            keys_of_interest = ["FileName", "FileSize", "FileType", "MIMEType", "ImageWidth", "ImageHeight",
                                 "Make", "Model", "Software", "DateTime", "DateTimeOriginal", "CreateDate",
                                 "GPSLatitude", "GPSLongitude", "GPSAltitude", "GPSLatitudeRef", "GPSLongitudeRef",
                                 "Artist", "Copyright", "Author", "Creator", "Producer", "Title",
                                 "ExposureTime", "FNumber", "ISO", "FocalLength", "Flash",
                                 "XResolution", "YResolution", "ColorSpace", "Orientation"]
            for k in keys_of_interest:
                if k in data:
                    relevant[k] = data[k]
            has_gps = "GPSLatitude" in relevant and "GPSLongitude" in relevant
            return {
                "found": True,
                "metadata": relevant,
                "has_gps": has_gps,
                "gps_link": f"https://maps.google.com/?q={relevant.get('GPSLatitude')},{relevant.get('GPSLongitude')}" if has_gps else None,
                "tool": "exiftool",
                "total_fields": len(data)
            }
        return {"error": "ExifTool falló", "stderr": r.stderr}
    except FileNotFoundError:
        return {"error": "ExifTool no instalado"}
    except Exception as e:
        return {"error": str(e)}
