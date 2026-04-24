from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import httpx
import asyncio
import subprocess
import json
import os
import tempfile
import re
from typing import Optional
import phonenumbers
from phonenumbers import geocoder, carrier, number_type, PhoneNumberType

app = FastAPI(title="Ciberbrigada OSINT API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TIMEOUT = 60

# ── HEALTH ──────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "online", "service": "Ciberbrigada OSINT API v2"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/tools/check")
def check_tools():
    tools = {}
    for tool, cmd in [
        ("sherlock", ["sherlock", "--version"]),
        ("holehe", ["holehe", "--help"]),
        ("exiftool", ["exiftool", "-ver"]),
    ]:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
            tools[tool] = "disponible" if r.returncode == 0 else "instalado"
        except FileNotFoundError:
            tools[tool] = "no instalado"
        except:
            tools[tool] = "error"
    return {"tools": tools}

# ── USERNAME - SHERLOCK ──────────────────────────────────────────────────
@app.get("/api/username/sherlock")
async def sherlock_search(username: str):
    try:
        result = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, _run_sherlock, username),
            timeout=90
        )
        return result
    except asyncio.TimeoutError:
        return {
            "found": False,
            "username": username,
            "count": 0,
            "sites": [],
            "error": "Timeout — la búsqueda tardó demasiado",
            "command": f"sherlock {username}",
            "tool": "sherlock"
        }
    except Exception as e:
        return {"error": str(e), "username": username, "command": f"sherlock {username}"}

def _run_sherlock(username: str):
    cmds = [
        ["sherlock", username, "--print-found", "--timeout", "10", "--no-color"],
        ["python3", "-m", "sherlock", username, "--print-found", "--timeout", "10", "--no-color"],
        ["python3", "-c", f"""
import sys
try:
    from sherlock_project.sherlock import sherlock, QueryNotifyPrint, QueryStatus
    from sherlock_project.sites import SitesInformation
    import os
    sites = SitesInformation()
    query = QueryNotifyPrint(result_found=True)
    results = sherlock("{username}", sites, query, timeout=10)
    found = [url for url, r in results.items() if r.get("status") and r["status"].status == QueryStatus.CLAIMED]
    print("\\n".join(f"[+] {{u}}" for u in found))
except Exception as e:
    print(f"ERROR: {{e}}", file=sys.stderr)
"""],
    ]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=85)
            found = []
            for line in (r.stdout + r.stderr).splitlines():
                if "[+]" in line and "http" in line:
                    url = line.split("[+]")[-1].strip()
                    if url:
                        found.append(url)
            if found or r.returncode == 0:
                return {
                    "found": len(found) > 0,
                    "username": username,
                    "count": len(found),
                    "sites": found,
                    "tool": "sherlock"
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception:
            continue
    return {
        "found": False,
        "username": username,
        "count": 0,
        "sites": [],
        "error": "Sherlock no disponible en este servidor",
        "fallback": f"https://whatsmyname.app/?q={username}",
        "command": f"sherlock {username}",
        "tool": "sherlock"
    }

# ── USERNAME - WHATSMYNAME (API alternativa) ─────────────────────────────
@app.get("/api/username/wmn")
async def wmn_search(username: str):
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(
                "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
            )
            if r.status_code != 200:
                return {"error": "No se pudo obtener datos de WhatsMyName"}
            data = r.json()
            sites = data.get("sites", [])
            found = []
            check_tasks = []
            async def check_site(site):
                try:
                    url = site.get("uri_check", "").replace("{account}", username)
                    if not url:
                        return
                    async with httpx.AsyncClient(timeout=8, follow_redirects=True) as c:
                        resp = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
                        ecode = site.get("e_code", 200)
                        estring = site.get("e_string", "")
                        if resp.status_code == ecode and (not estring or estring in resp.text):
                            found.append({
                                "site": site.get("name"),
                                "url": url,
                                "category": site.get("cat", "")
                            })
                except:
                    pass
            # Check top 50 sites for speed
            await asyncio.gather(*[check_site(s) for s in sites[:50]])
            return {
                "found": len(found) > 0,
                "username": username,
                "count": len(found),
                "sites": [f"{s['site']}: {s['url']}" for s in found],
                "tool": "whatsmyname"
            }
    except Exception as e:
        return {"error": str(e), "fallback": f"https://whatsmyname.app/?q={username}"}

# ── EMAIL - EMAILREP ────────────────────────────────────────────────────
@app.get("/api/email/rep")
async def check_emailrep(email: str):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"https://emailrep.io/{email}",
                headers={"User-Agent": "Ciberbrigada-OSINT/2.0"}
            )
            if r.status_code == 200:
                d = r.json()
                return {
                    "found": True,
                    "email": email,
                    "reputation": d.get("reputation", "unknown"),
                    "suspicious": d.get("suspicious", False),
                    "references": d.get("references", 0),
                    "blacklisted": d.get("details", {}).get("blacklisted", False),
                    "malicious_activity": d.get("details", {}).get("malicious_activity", False),
                    "spam": d.get("details", {}).get("spam", False),
                    "free_provider": d.get("details", {}).get("free_provider", False),
                    "disposable": d.get("details", {}).get("disposable", False),
                    "last_seen": d.get("details", {}).get("last_seen", ""),
                    "profiles": d.get("details", {}).get("profiles", []),
                }
            return {"error": f"HTTP {r.status_code}", "fallback": f"https://emailrep.io/{email}"}
    except Exception as e:
        return {"error": str(e), "fallback": f"https://emailrep.io/{email}"}

# ── EMAIL - HIBP ────────────────────────────────────────────────────────
@app.get("/api/email/hibp")
async def check_hibp(email: str):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": os.getenv("HIBP_API_KEY", ""),
                    "user-agent": "Ciberbrigada-OSINT/2.0"
                }
            )
            if r.status_code == 404:
                return {"found": False, "breaches": [], "count": 0, "email": email}
            if r.status_code == 401:
                return {"error": "API key requerida", "fallback": f"https://haveibeenpwned.com/account/{email}"}
            if r.status_code == 200:
                data = r.json()
                return {
                    "found": True,
                    "count": len(data),
                    "email": email,
                    "breaches": [
                        {
                            "name": b.get("Name", ""),
                            "domain": b.get("Domain", ""),
                            "date": b.get("BreachDate", ""),
                            "data_classes": b.get("DataClasses", []),
                            "pwn_count": b.get("PwnCount", 0),
                        }
                        for b in data
                    ]
                }
            return {"error": f"HTTP {r.status_code}", "fallback": f"https://haveibeenpwned.com/account/{email}"}
    except Exception as e:
        return {"error": str(e), "fallback": f"https://haveibeenpwned.com/account/{email}"}

# ── EMAIL - HOLEHE ───────────────────────────────────────────────────────
@app.get("/api/email/holehe")
async def holehe_search(email: str):
    try:
        result = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, _run_holehe, email),
            timeout=120
        )
        return result
    except asyncio.TimeoutError:
        return {"error": "Timeout", "email": email, "command": f"holehe {email}"}
    except Exception as e:
        return {"error": str(e)}

def _run_holehe(email: str):
    cmds = [
        ["holehe", email, "--only-used", "--no-color"],
        ["python3", "-m", "holehe", email, "--only-used", "--no-color"],
    ]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=110)
            found = []
            for line in r.stdout.splitlines():
                if "[+]" in line:
                    site = line.split("[+]")[-1].strip()
                    if site:
                        found.append(site)
            return {
                "found": len(found) > 0,
                "email": email,
                "registered_on": found,
                "count": len(found),
                "tool": "holehe"
            }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return {
        "found": False,
        "email": email,
        "registered_on": [],
        "count": 0,
        "error": "Holehe no disponible",
        "command": f"holehe {email}"
    }

# ── PHONE - PHONENUMBERS (lib) + INFO ────────────────────────────────────
@app.get("/api/phone/infoga")
async def phoneinfoga(number: str):
    try:
        # Use phonenumbers library (pure Python, no install issues)
        parsed = phonenumbers.parse(number, None)
        is_valid = phonenumbers.is_valid_number(parsed)
        country = geocoder.description_for_number(parsed, "es")
        op = carrier.name_for_number(parsed, "es")
        ntype = number_type(parsed)
        type_map = {
            PhoneNumberType.MOBILE: "Móvil",
            PhoneNumberType.FIXED_LINE: "Fijo",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fijo o Móvil",
            PhoneNumberType.TOLL_FREE: "Gratuito",
            PhoneNumberType.PREMIUM_RATE: "Tarifa Premium",
            PhoneNumberType.VOIP: "VoIP",
            PhoneNumberType.UNKNOWN: "Desconocido",
        }
        formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        region = phonenumbers.region_code_for_number(parsed)

        result = {
            "found": is_valid,
            "number": formatted,
            "original": number,
            "valid": is_valid,
            "country": country or "Desconocido",
            "region_code": region or "N/A",
            "carrier": op or "Desconocido",
            "line_type": type_map.get(ntype, "Desconocido"),
            "national_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "e164_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "tool": "phonenumbers"
        }

        # Also try phoneinfoga binary if available
        try:
            r = subprocess.run(
                ["phoneinfoga", "scan", "-n", number],
                capture_output=True, text=True, timeout=20
            )
            if r.returncode == 0 and len(r.stdout) > 50:
                result["raw"] = r.stdout
                result["tool"] = "phoneinfoga"
        except:
            pass

        return result
    except phonenumbers.NumberParseException as e:
        return {
            "error": f"Número inválido: {str(e)}",
            "number": number,
            "tip": "Incluí el código de país. Ej: +5491112345678"
        }
    except Exception as e:
        return {"error": str(e), "number": number}

# ── IP / DOMINIO - IPINFO ───────────────────────────────────────────────
@app.get("/api/ip/info")
async def ip_info(query: str):
    try:
        token = os.getenv("IPINFO_TOKEN", "")
        # Try ipinfo.io
        async with httpx.AsyncClient(timeout=15) as client:
            url = f"https://ipinfo.io/{query}/json"
            if token:
                url += f"?token={token}"
            r = await client.get(url, headers={"User-Agent": "Ciberbrigada-OSINT/2.0"})
            if r.status_code == 200:
                d = r.json()
                if "bogon" in d:
                    return {"error": "IP privada o reservada", "query": query}
                return {
                    "found": True,
                    "query": query,
                    "ip": d.get("ip", query),
                    "hostname": d.get("hostname", "N/A"),
                    "city": d.get("city", "N/A"),
                    "region": d.get("region", "N/A"),
                    "country": d.get("country", "N/A"),
                    "org": d.get("org", "N/A"),
                    "timezone": d.get("timezone", "N/A"),
                    "loc": d.get("loc", ""),
                    "postal": d.get("postal", "N/A"),
                }
    except Exception:
        pass

    # Fallback: ip-api.com (no key needed)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"http://ip-api.com/json/{query}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
                headers={"User-Agent": "Ciberbrigada-OSINT/2.0"}
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    return {
                        "found": True,
                        "query": query,
                        "ip": d.get("query", query),
                        "hostname": "N/A",
                        "city": d.get("city", "N/A"),
                        "region": d.get("regionName", "N/A"),
                        "country": d.get("country", "N/A"),
                        "org": d.get("org") or d.get("isp", "N/A"),
                        "timezone": d.get("timezone", "N/A"),
                        "loc": f"{d.get('lat','')},{d.get('lon','')}",
                        "postal": d.get("zip", "N/A"),
                    }
                return {"error": d.get("message", "No encontrado"), "query": query}
    except Exception as e:
        return {"error": str(e), "query": query}

# ── WHOIS ───────────────────────────────────────────────────────────────
@app.get("/api/domain/whois")
async def whois_lookup(domain: str):
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            # Try RDAP first
            r = await client.get(
                f"https://rdap.org/domain/{domain}",
                headers={"User-Agent": "Ciberbrigada-OSINT/2.0"}
            )
            if r.status_code == 200:
                d = r.json()
                events = {e.get("eventAction"): e.get("eventDate","N/A") for e in d.get("events", [])}
                nameservers = [ns.get("ldhName", "") for ns in d.get("nameservers", [])]
                registrar = "N/A"
                for entity in d.get("entities", []):
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break
                return {
                    "found": True,
                    "domain": domain,
                    "data": {
                        "registrar": registrar,
                        "registered": events.get("registration", "N/A"),
                        "updated": events.get("last changed", "N/A"),
                        "expires": events.get("expiration", "N/A"),
                        "nameservers": nameservers,
                        "status": d.get("status", []),
                        "handle": d.get("handle", "N/A"),
                    }
                }

            # Fallback: whois.vu
            r2 = await client.get(f"https://api.whois.vu/?q={domain}")
            if r2.status_code == 200:
                return {"found": True, "domain": domain, "data": r2.json()}

            return {"error": "No se pudo obtener WHOIS", "fallback": f"https://who.is/whois/{domain}"}
    except Exception as e:
        return {"error": str(e), "fallback": f"https://who.is/whois/{domain}"}

# ── DNS ─────────────────────────────────────────────────────────────────
@app.get("/api/domain/dns")
async def dns_lookup(domain: str):
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            results = {}
            for rtype in ["A", "MX", "NS", "TXT", "AAAA", "CNAME"]:
                try:
                    r = await client.get(
                        f"https://dns.google/resolve?name={domain}&type={rtype}",
                        headers={"User-Agent": "Ciberbrigada-OSINT/2.0"}
                    )
                    if r.status_code == 200:
                        data = r.json()
                        results[rtype] = [a.get("data", "") for a in data.get("Answer", [])]
                    else:
                        results[rtype] = []
                except:
                    results[rtype] = []
            return {"found": True, "domain": domain, "records": results}
    except Exception as e:
        return {"error": str(e)}

# ── EXIF - FROM URL ─────────────────────────────────────────────────────
@app.get("/api/image/exif")
async def exif_from_url(url: str):
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 200:
                return {"error": f"No se pudo descargar: HTTP {r.status_code}"}
            ext = url.split(".")[-1].split("?")[0][:4] or "jpg"
            with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tmp:
                tmp.write(r.content)
                tmp_path = tmp.name
        result = await asyncio.get_event_loop().run_in_executor(None, _run_exiftool, tmp_path)
        try:
            os.unlink(tmp_path)
        except:
            pass
        return result
    except Exception as e:
        return {"error": str(e)}

# ── EXIF - FROM FILE UPLOAD ──────────────────────────────────────────────
@app.post("/api/image/exif-upload")
async def exif_from_upload(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        suffix = "." + (file.filename.split(".")[-1] if "." in (file.filename or "") else "jpg")
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name
        result = await asyncio.get_event_loop().run_in_executor(None, _run_exiftool, tmp_path)
        try:
            os.unlink(tmp_path)
        except:
            pass
        return result
    except Exception as e:
        return {"error": str(e)}

def _run_exiftool(path: str):
    try:
        r = subprocess.run(["exiftool", "-j", path], capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            raw = json.loads(r.stdout)[0]
            keys = ["FileName","FileSize","FileType","MIMEType","ImageWidth","ImageHeight",
                    "Make","Model","Software","DateTime","DateTimeOriginal","CreateDate",
                    "GPSLatitude","GPSLongitude","GPSAltitude","GPSLatitudeRef","GPSLongitudeRef",
                    "Artist","Copyright","Author","Creator","Title",
                    "ExposureTime","FNumber","ISO","FocalLength","Flash",
                    "XResolution","YResolution","ColorSpace","Orientation","Duration"]
            metadata = {k: raw[k] for k in keys if k in raw}
            has_gps = "GPSLatitude" in metadata and "GPSLongitude" in metadata
            return {
                "found": True,
                "metadata": metadata,
                "has_gps": has_gps,
                "gps_link": f"https://maps.google.com/?q={metadata.get('GPSLatitude')},{metadata.get('GPSLongitude')}" if has_gps else None,
                "tool": "exiftool",
                "total_fields": len(raw)
            }
        return {"error": "ExifTool no pudo procesar la imagen", "stderr": r.stderr[:200]}
    except FileNotFoundError:
        # Fallback: try to read basic JPEG EXIF with pure Python
        return _basic_exif(path)
    except Exception as e:
        return {"error": str(e)}

def _basic_exif(path: str):
    """Basic EXIF reader without exiftool"""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        img = Image.open(path)
        exif_data = img._getexif()
        if not exif_data:
            return {"found": True, "metadata": {"FileFormat": img.format, "Size": f"{img.size[0]}x{img.size[1]}", "Mode": img.mode}, "has_gps": False, "tool": "PIL"}
        metadata = {}
        gps_info = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                for gps_tag_id, gps_value in value.items():
                    gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                    gps_info[gps_tag] = str(gps_value)
            else:
                metadata[str(tag)] = str(value)[:200]
        if gps_info:
            metadata.update({f"GPS_{k}": v for k, v in gps_info.items()})
        return {"found": True, "metadata": metadata, "has_gps": bool(gps_info), "tool": "PIL"}
    except Exception as e:
        return {"found": False, "error": f"No se pudieron extraer metadatos: {str(e)}"}
