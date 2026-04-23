# Ciberbrigada OSINT Backend

API FastAPI para la plataforma Ciberbrigada OSINT.

## Deploy en Render.com (GRATIS)

1. Subí esta carpeta `cb_backend` a un repositorio de GitHub
2. Entrá a [render.com](https://render.com) y creá una cuenta
3. New → Web Service → conectá el repo
4. Configuración:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Environment:** Python 3

## Endpoints disponibles

| Endpoint | Descripción |
|---|---|
| `GET /api/email/hibp?email=` | HaveIBeenPwned - brechas |
| `GET /api/email/rep?email=` | EmailRep - reputación |
| `GET /api/email/holehe?email=` | Holehe - cuentas registradas |
| `GET /api/username/sherlock?username=` | Sherlock - búsqueda de username |
| `GET /api/username/maigret?username=` | Maigret - búsqueda profunda |
| `GET /api/ip/info?query=` | IPinfo - geolocalización IP |
| `GET /api/domain/whois?domain=` | WHOIS lookup |
| `GET /api/domain/dns?domain=` | DNS records |
| `GET /api/domain/virustotal?query=&apikey=` | VirusTotal (requiere API key) |
| `GET /api/ip/abuse?ip=&apikey=` | AbuseIPDB (requiere API key) |
| `GET /api/phone/infoga?number=` | PhoneInfoga |
| `GET /api/image/exif?url=` | ExifTool - metadatos de imagen |

## Variables de entorno (opcionales)

- `HIBP_API_KEY` - HaveIBeenPwned API key (gratis en hibp)
- `IPINFO_TOKEN` - IPinfo token (gratis, 50k requests/mes)
- `ABUSEIPDB_KEY` - AbuseIPDB key (gratis)
