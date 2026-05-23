# Diseño: Mejoras de Enumeración de Usuarios + Módulo BruteForce

**Fecha:** 2026-05-24  
**Versión:** 3.0 (final — 3 rondas de moderador + 2 críticos)  
**Estado:** Aprobado por el usuario

---

## Contexto

Plecost actualmente enumera usuarios WordPress con solo 2 técnicas (REST API + author archives IDs 1-10). WPScan tiene 8 técnicas. Esta especificación define las mejoras necesarias para cerrar ese gap y añadir un módulo de brute force de contraseñas.

Arquitectura del proyecto: asyncio puro, módulos que extienden `ScanModule`, `ScanContext` con `ctx.users`, `ScanOptions` con `module_options: dict[str, dict[str, str]]`.

---

## PARTE A: UsersModule — Mejoras

### Técnicas nuevas a implementar

#### T1: REST API con paginación completa (modifica `_rest_api`)

- **Endpoint:** `GET /wp-json/wp/v2/users?per_page=100&page=N`
- **Lógica:** Leer `X-WP-TotalPages` de la primera respuesta. Iterar `range(1, total_pages+1)` secuencialmente (NO con gather interno para no saturar pool httpx).
- **Parada:** Si `status != 200` o body no es lista JSON, romper el bucle.
- **Finding:** PC-USR-001 (existente), MEDIUM 5.3 — se mantiene, la lógica de reporte agrega el finding una vez con el total de usuarios encontrados.

#### T2: Author archives — ampliar rango con early-stop (modifica `_author_archives`)

- **Rango:** fast=25 IDs (era 10), deep=100 IDs. Configurable via `module_options["users"]["max_author_id"]`.
- **Early-stop:** Si 3 IDs consecutivos no devuelven 301/302, romper el bucle. Indica que author archives está desactivado.
- **Finding:** PC-USR-002 (existente), MEDIUM 5.3.

#### T3: WordPress Core Sitemap (nueva: `_wp_sitemap_users`)

- **Endpoint:** `GET /wp-sitemap-users-1.xml`
- **Condición de éxito:** `status_code == 200` y body contiene `<urlset`
- **Parsing:**
  ```python
  _SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
  try:
      root = ET.fromstring(r.text)
  except ET.ParseError:
      return
  for loc in root.findall(f".//{{{_SITEMAP_NS}}}loc"):
      url_text = loc.text or ""
      if m := re.search(r'/author/([^/]+)/', url_text):
          # add_user(...)
  ```
- **Finding:** PC-USR-003 (nuevo), INFO 3.1 — sitemaps son públicos intencionalmente.

#### T4: RSS feed `<dc:creator>` (nueva: `_rss_feed`)

- **Endpoint:** `GET /?feed=rss2`
- **Regex unificada (CDATA + no-CDATA):**
  ```python
  _RSS_CREATOR_RE = re.compile(
      r'<dc:creator>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</dc:creator>',
      re.S
  )
  ```
- **Finding:** PC-USR-004 (nuevo), MEDIUM 5.3 — misma severidad que REST API.

#### T5: Yoast SEO Author Sitemap (nueva: `_yoast_author_sitemap`)

- **Endpoint:** `GET /author-sitemap.xml`
- **Parsing:** Mismo patrón que T3 (namespace XML idéntico).
- **Finding:** PC-USR-005 (nuevo), INFO 3.1. ID separado de PC-USR-003 para no emitir el mismo ID dos veces.

#### T6: oEmbed user extraction (nueva: `_oembed_user`)

- **Endpoint:** `GET /wp-json/oembed/1.0/embed?url={ctx.url}`
- **Condición de extracción:** Solo si `author_url` contiene `/author/<slug>/`. Si no, descartar (no usar `author_name` como username provisional).
- **Finding:** Ninguno propio. Solo popula `ctx.users` con `source="oembed"`.

#### T7: HTML author links (nueva: `_html_author_links`)

- **Input:** `homepage_html` (obtenido antes del gather en `run()`)
- **Regex:** `re.findall(r'href=["\'][^"\']+/author/([a-z0-9_\-]+)/', homepage_html)`
- **Guard:** `if not homepage_html: return`
- **Finding:** Ninguno propio. Solo popula `ctx.users` con `source="html_links"`.

---

### Estructura del método `run()` refactorizado

```python
async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
    if not ctx.is_wordpress and not ctx.opts.force:
        return

    # Obtener homepage para T7 ANTES del gather
    homepage_html = ""
    try:
        r = await http.get(ctx.url + "/")
        if r.status_code == 200:
            homepage_html = r.text
    except Exception:
        pass

    await asyncio.gather(
        self._rest_api_paginated(ctx, http),
        self._author_archives(ctx, http),
        self._wp_sitemap_users(ctx, http),
        self._yoast_author_sitemap(ctx, http),
        self._rss_feed(ctx, http),
        self._oembed_user(ctx, http),
        self._html_author_links(ctx, http, homepage_html),
        return_exceptions=True,  # convención del proyecto
    )
```

---

### Finding IDs de UsersModule (finales)

| ID | Rem. ID | Técnica | Severidad | CVSS |
|----|---------|---------|-----------|------|
| PC-USR-001 | REM-USR-001 | REST API paginada | MEDIUM | 5.3 |
| PC-USR-002 | REM-USR-002 | Author archives | MEDIUM | 5.3 |
| PC-USR-003 | REM-USR-003 | WP Core sitemap | INFO | 3.1 |
| PC-USR-004 | REM-USR-004 | RSS feed dc:creator | MEDIUM | 5.3 |
| PC-USR-005 | REM-USR-005 | Yoast SEO author sitemap | INFO | 3.1 |

PC-USR-006 reservado (gap intencional — login error enum movido a BruteForce).

---

### module_options para clave `"users"`

| Clave | Tipo | Default fast | Default deep | Descripción |
|-------|------|-------------|-------------|-------------|
| `max_author_id` | str(int) | `"25"` | `"100"` | Rango máximo de IDs para author archives |

---

## PARTE B: BruteForceModule

### Archivo

`plecost/modules/brute_force.py` — módulo único, no subpaquete.

### Clase y dependencias

```python
class BruteForceModule(ScanModule):
    name = "brute_force"
    depends_on = ["users"]  # NO ["xmlrpc"] — evita comportamiento indefinido con --skip-module
```

### Activación

El módulo hace early return silencioso si no está habilitado:

```python
def _is_enabled(self, ctx: ScanContext) -> bool:
    if ctx.opts.brute_force:
        return True
    return ctx.opts.module_options.get("brute_force", {}).get("enabled", "false") == "true"
```

**NO se activa con `--aggressive`** — flag completamente separado para evitar activación accidental.

### Flujo de ejecución

```
run()
  ├── Early return si no habilitado (silencioso)
  ├── Early return si ctx.users vacío → PC-BRU-003 (INFO)
  ├── Early return si ctx.waf_detected → PC-BRU-004 (INFO)
  ├── Fase 0: _login_error_enum() — confirmar usuarios por diferencia de mensajes
  ├── Cargar wordlist (interna o externa)
  ├── Construir pares (username, password) — variantes dinámicas primero
  ├── asyncio.gather(*[_try_one(u, p) for u, p in pairs], return_exceptions=True)
  └── Emitir findings (PC-BRU-001 único con lista, PC-BRU-002 si sin rate limiting)
```

### Fase 0: `_login_error_enum`

```python
async def _login_error_enum(self, ctx, http) -> set[str]:
    """
    Para cada usuario en ctx.users, hace POST a wp-login.php con password dummy.
    Si el error es "incorrect password" (no "invalid username"), el usuario existe.
    Solo ejecutada si --brute-force está activo.
    """
    confirmed: set[str] = set()
    fake_pass = "_plecost_probe_" + secrets.token_hex(8)
    for user in ctx.users:
        result = await self._attempt_login(ctx, http, user.username, fake_pass)
        if result == "connection_reset":
            return confirmed  # rate limiting, abortar
        if result == "invalid_password":
            confirmed.add(user.username)
    if confirmed:
        ctx.add_finding(Finding(id="PC-BRU-005", ...))
    return confirmed
```

### Detección de éxito/fallo/rate-limiting en `_attempt_login`

```python
async def _attempt_login(self, ctx, http, username, password) -> str:
    """
    Returns: "success" | "invalid_password" | "invalid_username"
           | "rate_limited" | "connection_reset" | "error"
    """
    try:
        r = await http.post(
            f"{ctx.url}/wp-login.php",
            data={"log": username, "pwd": password,
                  "wp-submit": "Log+In", "redirect_to": "/wp-admin/",
                  "testcookie": "1"},
            follow_redirects=False,
        )
    except (httpx.ConnectError, httpx.TransportError):
        return "connection_reset"  # Fail2Ban RST

    if self._is_rate_limited(r):
        return "rate_limited"

    # Éxito: condición primaria = cookie de sesión
    if "wordpress_logged_in_" in r.headers.get("set-cookie", ""):
        return "success"

    body = r.text[:4096].lower()
    if any(s in body for s in ("incorrect password", "the password you entered")):
        return "invalid_password"
    if any(s in body for s in ("invalid username", "is not registered")):
        return "invalid_username"

    return "error"
```

### Detección de rate limiting

```python
_RATE_LIMIT_BODY = [
    # HTTP 200 con bloqueo en body (Wordfence, LLAR, WP Cerber, etc.)
    "your access to this site has been limited",   # Wordfence
    "too many failed login attempts",              # Limit Login Attempts Reloaded
    "your ip address is blacklisted",              # WP Cerber
    "error: sorry, but this ip range has been banned",  # Login LockDown
    "you have been locked out",                    # iThemes Security
    "temporarily blocked",
    "access denied",
    # Captchas
    "g-recaptcha", "hcaptcha", "cf-challenge", "captcha",
]

def _is_rate_limited(self, response: httpx.Response) -> bool:
    if response.status_code in (429, 403):
        return True
    body_lower = response.text[:2048].lower()
    return any(s in body_lower for s in _RATE_LIMIT_BODY)
```

### Detección de 2FA

Tras login exitoso, GET secundario a `/wp-admin/` con la cookie obtenida:

```python
_2FA_STRINGS = [
    "two-factor", "2fa", "two factor", "authentication code",
    "verify your identity", "enter the code", "otp", "one-time password",
    "google authenticator", "authy", "wp 2fa",
    # añadidos en v3.0
    "duo", "two-step", "rublon", "miniorange", "verify code",
]
```

Si 2FA detectado: PC-BRU-001 con `severity=Severity.HIGH` (7.5) y `evidence["2fa_detected"]=True`.

### Wordlist interna (~60 contraseñas)

```python
_DEFAULT_PASSWORDS = [
    "password", "password1", "password123", "Password1", "Password123",
    "wordpress", "WordPress", "wordpress123", "WordPress123",
    "admin", "admin123", "Admin123", "admin1234", "Admin1234",
    "administrator", "Administrator",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "Qwerty123", "letmein", "letmein123",
    "welcome", "welcome1", "Welcome1", "welcome123",
    "iloveyou", "monkey", "dragon", "master", "master123",
    "sunshine", "princess", "football", "shadow", "superman",
    "michael", "jessica", "batman", "trustno1",
    "wp_admin", "wp-admin", "wpuser", "wppass", "changeme",
    "test", "test123", "Test123", "demo", "demo123",
    "install", "setup", "default", "secret", "secret123",
    "abc123", "pass123", "login123", "user123", "root",
    "p@ssw0rd", "P@ssw0rd", "P@$$w0rd",
]
```

### Variantes dinámicas del username

```python
def _build_username_variants(username: str) -> list[str]:
    year = datetime.date.today().year
    return [
        username,
        f"{username}123", f"{username}1234",
        f"{username}!", f"{username}#",
        f"{username}{year}", f"{username}{year - 1}",
    ]
```

### Wordlist externa

- **Activación:** `--brute-force-wordlist /path/to/list.txt` (nuevo campo `brute_force_wordlist: str | None = None` en `ScanOptions`)
- **Límites:** 10.000 entradas en fast, 50.000 en deep
- **Carga:** `asyncio.to_thread(_read_wordlist_sync, path, limit)` — no bloqueante
- **Comportamiento:** reemplaza la interna por defecto; `--brute-force-combine` las combina (nuevo campo `brute_force_combine: bool = False` en `ScanOptions`)
- **Path inexistente:** emite PC-BRU-006 (LOW) y usa wordlist interna

### Concurrencia

```python
sem = asyncio.Semaphore(concurrency)  # default=1
checked: list[int] = [0]

async def _try_one(username: str, password: str) -> None:
    async with sem:
        result = await self._attempt_login(ctx, http, username, password)
    # delay FUERA del semáforo (no ocupa el slot)
    await asyncio.sleep(delay_ms / 1000.0)
    # progress y stop_on_success checks...

    # progress siempre en finally
    try:
        ...
    finally:
        checked[0] += 1
        ctx.report_progress(self.name, checked[0], total)
```

Parámetros via `module_options["brute_force"]`:
- `concurrency` (int, default `"1"`)
- `delay_ms` (int, default `"2000"`)
- `stop_on_success` (bool, default `"true"`)
- `max_attempts_per_user` (int, default `"0"` = sin límite)

### Evidence de PC-BRU-001 — un único finding con lista

```python
# NO emitir un finding por credencial — emitir uno solo con todas:
ctx.add_finding(Finding(
    id="PC-BRU-001",
    severity=Severity.CRITICAL,  # o HIGH si 2FA detectado
    evidence={
        "credentials": [
            f"  • {u} / {p[:2]}***{p[-1:]}"  # password enmascarada
            for u, p in found_credentials
        ],
        "count": len(found_credentials),
        "login_url": f"{ctx.url}/wp-login.php",
    },
    ...
))
```

### Finding IDs de BruteForceModule (finales)

| ID | Rem. ID | Severidad | CVSS | Condición de emisión |
|----|---------|-----------|------|----------------------|
| PC-BRU-001 | REM-BRU-001 | CRITICAL (HIGH si 2FA) | 9.8 / 7.5 | ≥1 credencial válida |
| PC-BRU-002 | REM-BRU-002 | HIGH | 7.5 | Wordlist completa sin bloqueo y sin éxito |
| PC-BRU-003 | REM-BRU-003 | INFO | 0.0 | Sin usuarios en ctx.users o módulo no habilitado |
| PC-BRU-004 | REM-BRU-004 | INFO | 0.0 | WAF detectado, brute force no ejecutado |
| PC-BRU-005 | REM-BRU-005 | MEDIUM | 5.3 | Username confirmado via login error enum |
| PC-BRU-006 | REM-BRU-006 | LOW | 0.0 | Wordlist externa no encontrada, usando interna |

---

## PARTE C: Cambios en archivos existentes

### `plecost/models.py`

1. Añadir en `ScanOptions` (después de `deep: bool`):
   ```python
   brute_force: bool = False
   brute_force_wordlist: str | None = None
   brute_force_combine: bool = False
   ```
2. Añadir en `_CATEGORY_PREFIXES`:
   ```python
   ("PC-BRU-", "brute_force"),
   ```

### `plecost/engine/context.py`

Añadir en `__init__`:
```python
self.xmlrpc_accessible: bool = False
self.xmlrpc_multicall_available: bool = False
```

### `plecost/modules/xmlrpc.py`

Al final de `run()`, añadir:
```python
ctx.xmlrpc_accessible = True
```
Y cuando se detecta `system.multicall` (ya existe PC-XMLRPC-004):
```python
ctx.xmlrpc_multicall_available = True
```

### `plecost/scanner.py`

1. Importar `BruteForceModule`.
2. Añadir `BruteForceModule()` en la lista de módulos después de `UsersModule()`.
3. En `run_many()`, propagar los tres nuevos campos:
   ```python
   opts = ScanOptions(
       ...  # todos los campos existentes
       brute_force=self._opts.brute_force,
       brute_force_wordlist=self._opts.brute_force_wordlist,
       brute_force_combine=self._opts.brute_force_combine,
   )
   ```

### `plecost/cli.py`

1. Nuevas opciones en el comando `scan`:
   ```python
   brute_force: bool = typer.Option(False, "--brute-force", help="...")
   brute_force_wordlist: Optional[str] = typer.Option(None, "--brute-force-wordlist", ...)
   brute_force_combine: bool = typer.Option(False, "--brute-force-combine", ...)
   ```
2. `_ALL_MODULE_NAMES`: añadir `"brute_force"` después de `"users"`.
3. `_FINDINGS_REGISTRY`: añadir PC-USR-003, PC-USR-004, PC-USR-005, PC-BRU-001..006.

### `plecost/locales/en.json` y `es.json`

Añadir keys para todos los nuevos findings: `findings.pc_usr_003.*`, `findings.pc_usr_004.*`, `findings.pc_usr_005.*`, `findings.pc_bru_001.*` ... `findings.pc_bru_006.*`.

### `tests/contract/test_finding_ids.py`

Añadir a `KNOWN_FINDING_IDS`:
```python
"PC-USR-003", "PC-USR-004", "PC-USR-005",
"PC-BRU-001", "PC-BRU-002", "PC-BRU-003", "PC-BRU-004", "PC-BRU-005", "PC-BRU-006",
```

### Archivos de tests nuevos

- `tests/unit/test_module_users_v2.py` — tests para T3-T7 (sitemaps, RSS, oEmbed, HTML)
- `tests/unit/test_module_brute_force.py` — tests para BruteForceModule completo

---

## Decisiones de Scope

### IN SCOPE v1

Todo lo documentado en esta especificación.

### DEFERRED v2

- xmlrpc multicall como vector de ataque real (PC-XMLRPC-004 ya reporta el riesgo)
- GraphQL user enumeration (`/graphql`)
- PC-BRU-001 ajuste de severidad por rol verificado (requiere segundo request extra)
- Wordlist > 60 contraseñas (breach databases curadas)

---

## Notas de implementación

- `asyncio_mode = "auto"` en pyproject.toml — NO añadir `@pytest.mark.asyncio`
- respx: añadir catch-all en todos los tests nuevos: `respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))`
- Tests de XML deben incluir el namespace correcto: `xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"`
- La contraseña nunca se almacena en claro en `evidence` — siempre enmascarada
- `httpx.SSLError` no existe — usar `(httpx.ConnectError, httpx.TransportError)` para errores de conexión
