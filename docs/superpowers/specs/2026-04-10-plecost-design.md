# Plecost v4.0 — Spec de Diseño

> Fecha: 2026-04-10
> Estado: Aprobado

---

## 1. Visión General

Plecost es la mejor herramienta de análisis de seguridad de caja negra para WordPress. Detecta vulnerabilidades en el core, plugins y temas, enumera usuarios, identifica configuraciones inseguras y correlaciona todo con una base de datos CVE actualizada diariamente.

**Principios de diseño:**
- 100% automática — cero interacción durante el scan
- Doble modo: CLI interactiva (Typer + Rich) y librería Python (para Celery workers, APIs, etc.)
- Grafo de tareas async con dependencias explícitas (máximo paralelismo)
- httpx + asyncio; uvloop como dependencia opcional
- Cada hallazgo tiene un ID estable y permanente para dashboards externos

---

## 2. Arquitectura General

### Estructura de paquete

```
plecost/
├── cli.py                      # Typer app — punto de entrada CLI
├── engine/
│   ├── scheduler.py            # Grafo de tareas async con dependencias
│   ├── context.py              # ScanContext: estado compartido entre módulos
│   └── http_client.py          # httpx.AsyncClient wrapper (proxy, auth, stealth)
├── modules/                    # Módulos de detección independientes
│   ├── base.py                 # Clase base ScanModule
│   ├── fingerprint.py
│   ├── plugins.py
│   ├── themes.py
│   ├── users.py
│   ├── xmlrpc.py
│   ├── rest_api.py
│   ├── cves.py
│   ├── misconfigs.py
│   ├── directory_listing.py
│   ├── http_headers.py
│   ├── ssl_tls.py
│   ├── debug_exposure.py
│   ├── content_analysis.py
│   ├── waf.py
│   └── auth.py
├── database/
│   ├── updater.py              # Descarga y procesa CVE DB (usado por GitHub Action)
│   └── store.py                # Lectura local de la DB (SQLite + JSON)
├── reporters/
│   ├── terminal.py             # Rich: tablas, paneles, progress bars
│   └── json_reporter.py        # Volcado JSON estructurado
└── models.py                   # Dataclasses: ScanResult, Finding, Plugin, etc.
```

### Flujo de ejecución

```
CLI/Library → ScanOptions → ScanContext → Scheduler
                                              │
                    ┌─────────────────────────┤
                    ↓                         ↓
             [fingerprint]               [waf] (paralelo desde inicio)
                    │
        ┌───────────┼───────────┬──────────┬──────────┬──────────┐
        ↓           ↓           ↓          ↓          ↓          ↓
    [plugins]   [themes]    [users]    [xmlrpc]  [misconfigs] [auth]
        │           │                                            │
        └─────┬─────┘                                    [auth_checks]
              ↓
           [cves]
              │
      [Terminal Reporter]
      [JSON Reporter]
```

---

## 3. Módulos de Detección

### Grafo de dependencias

| Módulo | Depende de | Se ejecuta en paralelo con |
|--------|-----------|---------------------------|
| fingerprint | — | waf |
| waf | — | fingerprint |
| plugins | fingerprint | themes, users, xmlrpc, misconfigs, http_headers, ssl_tls, debug_exposure, content_analysis, rest_api |
| themes | fingerprint | plugins, users, xmlrpc, ... |
| users | fingerprint | plugins, themes, ... |
| xmlrpc | fingerprint | plugins, themes, ... |
| rest_api | fingerprint | plugins, themes, ... |
| misconfigs | fingerprint | plugins, themes, ... |
| directory_listing | fingerprint | plugins, themes, ... |
| http_headers | fingerprint | plugins, themes, ... |
| ssl_tls | fingerprint | plugins, themes, ... |
| debug_exposure | fingerprint | plugins, themes, ... |
| content_analysis | fingerprint | plugins, themes, ... |
| auth | fingerprint | plugins, themes, ... |
| cves | plugins, themes | — |

### Capacidades por módulo

#### fingerprint
- Versión WP via meta generator tag
- Versión WP via `/readme.html` y `/readme.txt` (stable tag)
- Versión WP via query params `?ver=X.X.X` en JS/CSS
- Versión WP via hashes de archivos en `/wp-includes/`
- Versión WP via feed RSS/Atom (`<generator>`)
- Versión WP via assets versionados en `wp-login.php`
- Detección de tema activo
- Detección de si es WordPress (requisito para todos los demás módulos)

#### plugins
- Fuerza bruta de ~59.000 slugs de plugins WordPress.org
- Detección pasiva de plugins via rutas en HTML source
- Versión via `/wp-content/plugins/{slug}/readme.txt`
- Versión via query params `?ver=X.X` en assets del plugin
- Detección de plugins abandonados (cerrados en WP.org)
- Comparación versión instalada vs. última disponible

#### themes
- Fuerza bruta de ~2.600 slugs de temas WordPress.org
- Detección pasiva via rutas en HTML source
- Versión via `/wp-content/themes/{slug}/style.css` (comentario Version:)
- Versión via `/wp-content/themes/{slug}/readme.txt`
- Temas inactivos instalados

#### users
- Enumeración via author archives `/?author=1` hasta N
- Enumeración via REST API `/wp-json/wp/v2/users`
- Enumeración via RSS/Atom feeds (`<dc:creator>`)
- Enumeración via oEmbed response (metadata de autor)
- Login differential (respuesta diferente para usuario válido vs inválido)
- Verificación de usuario "admin" con ID=1

#### xmlrpc
- Detección de `xmlrpc.php` accesible
- `system.listMethods` disponible
- `pingback.ping` habilitado (amplification DoS)
- Brute force via `system.multicall` (N intentos en 1 request)

#### rest_api
- `/wp-json/wp/v2/users` expone usernames públicamente
- CORS misconfiguration en REST API
- oEmbed endpoint expone información de usuario
- REST API link expuesto en HTML header (`rel="https://api.w.org/"`)
- Application Passwords habilitado

#### cves
- Correlación de versión WP core con CVE DB local
- Correlación de cada plugin detectado con CVE DB local
- Correlación de cada tema detectado con CVE DB local
- Severidad CVSS 3.1 (Critical/High/Medium/Low)
- Flag de exploit público disponible
- Rangos de versión afectados (exactos)

#### misconfigs
- `/wp-config.php` accesible
- Backups de wp-config: `.bak`, `.wp-config.php.swp`, `~`
- `/.env` accesible
- `/.git/` accesible
- `/debug.log` accesible
- `*.sql`, `*.bak` en raíz
- `/wp-admin/install.php` accesible
- `/wp-admin/upgrade.php` accesible
- `/readme.html` y `/license.txt` (version disclosure)
- `/wlwmanifest.xml` en header (Windows Live Writer)
- `wp-cron.php` accesible externamente
- Prefijo de tablas DB default (`wp_`) — inferido por comportamiento
- Security keys no configuradas o débiles — inferido por errores
- `DISALLOW_FILE_EDIT` no activo — inferido por acceso al editor

#### directory_listing
- Directory indexing en `/wp-content/`
- Directory indexing en `/wp-content/plugins/`
- Directory indexing en `/wp-content/themes/`
- Directory indexing en `/wp-content/uploads/`
- Media enumeration via `/?p=1`, `/?p=2`, ...

#### http_headers
- `Strict-Transport-Security` (HSTS) ausente
- `X-Frame-Options` ausente
- `X-Content-Type-Options` ausente
- `Content-Security-Policy` ausente
- `Referrer-Policy` ausente
- `Permissions-Policy` ausente
- `X-XSS-Protection` ausente
- `Server` header expone versión de servidor web
- `X-Powered-By` expone versión de PHP

#### ssl_tls
- Certificado SSL válido y no expirado
- Redirect HTTP → HTTPS ausente
- HSTS preload
- TLS 1.0/1.1 aún soportado (deprecated)

#### debug_exposure
- `WP_DEBUG = true` activo (errores en respuestas HTTP)
- `WP_DEBUG_LOG = true` (log accesible)
- `WP_DEBUG_DISPLAY = true` (errores visibles en pantalla)
- `display_errors = On` en PHP
- `expose_php = On` en PHP
- `allow_url_include = On` en PHP (RFI risk)

#### content_analysis
- Scripts de terceros sospechosos (card skimming patterns)
- iFrames externos inesperados
- Secretos hardcodeados en JS público (API keys, tokens con regex)

#### waf
- Detección de WAF/CDN por headers y comportamiento
- Identificación: Cloudflare, Sucuri, WordFence, Imperva, AWS WAF, Akamai, Fastly

#### auth
- Login con credenciales (`--user` / `--password`)
- Verificación de acceso a `/wp-admin`
- Detección de 2FA activo
- Checks adicionales en panel de administración (autenticado)
- Registro de usuarios abierto (`anyone_can_register`)

---

## 4. CLI

### Comandos

```bash
# Scan básico
plecost scan https://target.com

# Scan completo con autenticación
plecost scan https://target.com --user admin --password secret

# Con proxy y concurrencia
plecost scan https://target.com --proxy http://127.0.0.1:8080 --concurrency 20

# Solo módulos específicos
plecost scan https://target.com --modules fingerprint,plugins,cves

# Excluir módulos
plecost scan https://target.com --skip-modules content_analysis,waf

# Modo stealth (delays, user-agent aleatorio, solo detección pasiva)
plecost scan https://target.com --stealth

# Modo agresivo (máxima concurrencia, fuerza bruta completa)
plecost scan https://target.com --aggressive

# Output JSON
plecost scan https://target.com --output report.json

# Actualizar base de datos CVE
plecost update-db

# Listar módulos disponibles
plecost modules list

# Mostrar detalle de un finding por ID
plecost explain PC-XMLRPC-002
```

### Flags globales

| Flag | Descripción | Default |
|------|-------------|---------|
| `--concurrency N` | Número de requests paralelos | 10 |
| `--timeout N` | Timeout por request (segundos) | 10 |
| `--proxy URL` | Proxy HTTP/SOCKS5 | None |
| `--user-agent UA` | User-Agent personalizado | Plecost/4.0 |
| `--random-user-agent` | Rotar User-Agent aleatoriamente | False |
| `--stealth` | Modo silencioso: delays + passive only | False |
| `--aggressive` | Modo agresivo: max concurrencia | False |
| `--output FILE` | Guardar JSON en fichero | None |
| `--no-color` | Desactivar colores en terminal | False |
| `--quiet` | Solo mostrar hallazgos críticos/altos | False |
| `--force` | Continuar aunque no se detecte WP | False |
| `--disable-tls-checks` | No verificar certificados SSL | False |

---

## 5. API de Librería

```python
from plecost import Scanner, ScanOptions

options = ScanOptions(
    url="https://target.com",
    concurrency=10,
    timeout=10,
    proxy="http://127.0.0.1:8080",      # opcional
    modules=["fingerprint", "plugins", "cves"],  # None = todos
    skip_modules=[],
    credentials=("admin", "secret"),    # opcional
    stealth=False,
    aggressive=False,
    user_agent="Plecost/4.0",
    random_user_agent=False,
    verify_ssl=True,
    force=False,
)

scanner = Scanner(options)
result: ScanResult = await scanner.run()

# Acceso estructurado
print(result.wordpress_version)
print(result.is_wordpress)
for finding in result.findings:
    print(f"[{finding.severity}] {finding.id}: {finding.title}")
    print(f"  Remediación: {finding.remediation}")

result.to_json("report.json")
```

El `Scanner` es completamente independiente de Typer. La CLI es solo una capa de presentación sobre él.

---

## 6. Modelo de Datos

### Finding (hallazgo individual)

```python
@dataclass
class Finding:
    id: str                    # "PC-MCFG-001" — estable y permanente
    remediation_id: str        # "REM-MCFG-001" — ID de mitigación estable
    title: str                 # Título corto del hallazgo
    severity: Severity         # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description: str           # Qué se encontró y por qué es un problema
    evidence: dict             # URL, headers, response snippet, etc.
    remediation: str           # Qué hacer para corregirlo
    references: list[str]      # CVE links, OWASP, WP docs
    cvss_score: float | None   # Solo para CVEs
    module: str                # Módulo que lo detectó
```

### IDs estables por categoría

| Prefijo | Categoría |
|---------|-----------|
| `PC-FP-NNN` | Fingerprint / version disclosure |
| `PC-USR-NNN` | User enumeration |
| `PC-AUTH-NNN` | Authentication |
| `PC-XMLRPC-NNN` | XML-RPC |
| `PC-REST-NNN` | REST API |
| `PC-CVE-NNN` | CVE en core/plugin/tema |
| `PC-MCFG-NNN` | Misconfiguration |
| `PC-DIR-NNN` | Directory listing |
| `PC-HDR-NNN` | HTTP headers |
| `PC-SSL-NNN` | SSL/TLS |
| `PC-DBG-NNN` | Debug exposure |
| `PC-CNT-NNN` | Content analysis |
| `PC-WAF-NNN` | WAF detection |
| `PC-PLG-NNN` | Plugin-specific |
| `PC-THM-NNN` | Theme-specific |

Los IDs son **permanentes** entre versiones. No se reutilizan ni se renumeran aunque se elimine un check.

### ScanResult

```python
@dataclass
class ScanResult:
    scan_id: str               # UUID por ejecución
    url: str
    timestamp: datetime
    duration_seconds: float
    is_wordpress: bool
    wordpress_version: str | None
    plugins: list[Plugin]
    themes: list[Theme]
    users: list[User]
    waf_detected: str | None
    findings: list[Finding]
    summary: ScanSummary       # Conteo por severidad
```

---

## 7. Base de Datos CVE

### Estrategia
- GitHub Action actualiza la DB **diariamente** usando NVD API 2.0 + WPScan Vulnerability DB pública
- La DB se publica como **release artifact** en GitHub (SQLite + JSON pre-procesado)
- Plecost descarga la DB con `plecost update-db` (verifica hash SHA256)
- La DB se almacena en `~/.plecost/db/`

### Estructura SQLite
```sql
-- Vulnerabilidades indexadas por software + versión
CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,        -- "PC-CVE-001" o CVE-YYYY-NNNNN
    software_type TEXT,         -- "core" | "plugin" | "theme"
    software_slug TEXT,         -- "wordpress" | "woocommerce" | "twentytwentyfour"
    version_from TEXT,
    version_to TEXT,
    cvss_score REAL,
    severity TEXT,
    title TEXT,
    description TEXT,
    remediation TEXT,
    references TEXT,            -- JSON array
    has_exploit INTEGER,        -- 0 | 1
    published_at TEXT
);

-- Wordlist de plugins (slugs conocidos)
CREATE TABLE plugins_wordlist (
    slug TEXT PRIMARY KEY,
    last_updated TEXT,
    active_installs INTEGER
);

-- Wordlist de temas
CREATE TABLE themes_wordlist (
    slug TEXT PRIMARY KEY,
    last_updated TEXT
);
```

---

## 8. Distribución

### pip
```bash
pip install plecost
pip install plecost[fast]    # incluye uvloop
```

### Docker
```bash
docker run --rm ghcr.io/cr0hn/plecost scan https://target.com
docker run --rm ghcr.io/cr0hn/plecost scan https://target.com \
  --proxy http://host.docker.internal:8080 \
  --output /data/report.json \
  -v $(pwd):/data
```

---

## 9. Estrategia de Testing

### Tipos de tests

#### Unit tests (`tests/unit/`)
- Parseo de HTML, feeds, headers (sin red)
- Correlación de versiones con CVE DB (mocks de DB)
- IDs estables: no duplicados, formato correcto, ninguno cambia entre versiones
- Serialización/deserialización de dataclasses
- Que cada finding tiene su remediación asociada

#### Integration tests (`tests/integration/`)
- Scheduler: grafo de dependencias, paralelismo correcto
- HTTP client: proxy, auth, timeouts, retries (con respx mock)
- Descarga y parsing de CVE DB
- Reporters: JSON válido, completo y con todos los campos

#### Functional tests (`tests/functional/`)
- Docker Compose levanta WordPress 6.x deliberadamente vulnerable
- Scan end-to-end verifica findings **exactos** esperados
- Scan autenticado detecta findings adicionales
- Modo stealth genera menos requests
- CLI via subprocess: flags, output JSON válido

#### Contract tests (`tests/contract/`)
- `Scanner(options).run()` siempre devuelve `ScanResult` completo
- Los IDs `PC-XXX-NNN` y `REM-XXX-NNN` son invariantes entre versiones
- La API pública no rompe entre versiones minor

#### Property-based tests (`tests/property/`)
- URLs malformadas/extremas no crashean el scanner
- Versiones de WP/plugins raras o malformadas no crashean el parser
- Responses HTTP truncadas/malformadas no crashean los módulos

### Infraestructura
- **pytest** + **pytest-asyncio**
- **respx** para mockear httpx en unit/integration
- **Docker Compose** con WordPress 6.x + MySQL + plugins vulnerables para functional tests
- **Hypothesis** para property-based tests
- **coverage** con umbral mínimo del 80%
- **GitHub Actions**: unit + integration en cada PR; functional tests diariamente

### WordPress Docker de test
El `docker-compose.test.yml` incluye:
- WordPress con versión desactualizada deliberadamente
- Plugins vulnerables conocidos instalados (ej: WP File Manager < 6.9)
- `WP_DEBUG=true`, directory listing habilitado
- XML-RPC activo, REST API sin restricciones
- Usuario "admin" con password débil
- Headers de seguridad ausentes

---

## 10. GitHub Actions

### `update-cve-db.yml` (diario)
1. Descarga vulnerabilidades de NVD API 2.0 (WordPress + plugins + temas)
2. Descarga wordlist actualizada de plugins de WordPress.org
3. Construye SQLite + JSON pre-procesado
4. Publica como release artifact con SHA256
5. Actualiza `db/latest.json` con URL y hash

### `ci.yml` (en cada PR)
1. Linting (ruff)
2. Type checking (mypy)
3. Unit tests
4. Integration tests
5. Coverage report

### `docker.yml` (en cada release)
1. Build imagen Docker
2. Push a `ghcr.io/cr0hn/plecost`

---

## 11. README

El README incluirá:
- Logo/banner ASCII art de plecost
- Badges: CI, versión pip, Docker pulls, CVE DB última actualización
- Demo GIF de un scan completo
- Instalación (pip, Docker)
- Uso rápido (3 ejemplos en 30 segundos)
- Tabla completa de módulos y capacidades
- Tabla de IDs de findings
- Comparativa con WPScan, Wordfence, ScanTower
- Contributing guide
- License
