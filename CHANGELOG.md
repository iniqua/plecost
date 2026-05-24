## [4.6.0] — 2026-05-24

### Added
- **G-017 — `active_installs` desde WP.org API** (`cli.py`): nueva función `_sync_active_installs()` llamada al final de `update-db`. Pagina la WP.org API (plugins/themes, per_page=100, máx 50 páginas) y actualiza los registros con `active_installs=0`. Fast-scan `--top 150` ahora ordena correctamente por popularidad real en lugar de aleatorio. API no disponible → warning y continúa sin crash (AC-4).
- **RCG-7 — retry backoff + protección del header Authorization** (`downloader.py`): `_fetch_bytes()` reintenta hasta 3 veces en 429/5xx con delay `2^attempt + uniform(0,1)s`. `_make_headers()` acepta `url` y solo incluye `Authorization: Bearer` cuando el hostname es `*.github.com` o `raw.githubusercontent.com` — previene exfiltración del GITHUB_TOKEN a URLs no-GitHub (ej. WP.org API).
- **BRU-RL — jitter + circuit breaker adaptativo** (`brute_force.py`): delay entre intentos cambia de `sleep(2.0)` fijo a `sleep(random.uniform(0.3, 1.5))`. Nueva clase `_RateLimitCircuitBreaker` con estados CLOSED/OPEN/HALF_OPEN/EXHAUSTED: 3 respuestas 429 consecutivas abren el circuit; state machine OPEN(10s)→HALF_OPEN probe→si 429: OPEN(20s)→OPEN(30s)→EXHAUSTED tras 60s total. EXHAUSTED emite PC-BRU-007 con `total_wait_seconds=60`. Non-429 en HALF_OPEN restaura CLOSED.

### Tests
- `tests/unit/test_database_active_installs.py`: 7 tests spec-driven para G-017 (AC-1 a AC-5)
- `tests/unit/test_database_downloader_retry.py`: 20 tests para RCG-7 (retry en 429/5xx, Authorization header, URL validation)
- `tests/unit/test_module_brute_force_cb.py`: 17 tests para BRU-RL (10 unitarios de `_RateLimitCircuitBreaker`, 7 de integración); tests pre-existentes de AC-13 actualizados para reflejar tolerancia de 3 429s consecutivos

### Verified
- Rescan de plesk.com y fucking-navidad.com: `PC-WSH-150`, `PC-WSH-001`, `PC-MCFG-007`, `PC-MCFG-008` ausentes — falsos positivos eliminados confirmados post-merge.

## [4.5.2] — 2026-05-24

### Changed
- **PC-WSH-150 China Chopper — detección confirmada con POST probe** (`mu_plugins.py`):
  - En fast mode (default): `MuPluginsDetector` retorna `[]` inmediatamente sin hacer ningún request HTTP — elimina todos los falsos positivos en ese modo.
  - En deep mode (`--deep`): se mantiene el GET scan con filtro catch-all, y se añade un POST probe activo para confirmar ejecución de código PHP. Solo se emite PC-WSH-150 CRITICAL si la confirmación tiene éxito.
  - Mecanismo anti-reflexión: el payload usa `printf(strrev("REVERSED_NONCE"))` — el body POST contiene el nonce invertido; solo PHP ejecutando `strrev()` puede producir el nonce forward en la respuesta, lo que previene falsos positivos por WAFs/debug handlers que reflejan el cuerpo de la petición.
  - Se prueban 6 parámetros en orden: `password`, `cmd`, `c`, `pass`, `p`, `key` — cada uno con payload directo y variante `eval(base64_decode(...))`.
  - El finding PC-WSH-150 ahora incluye `probe_param` (parámetro que confirmó) y `confirmed=True` en el evidence.
  - Título actualizado: `"China Chopper webshell confirmed in wp-content/mu-plugins"`.
  - Añadido `ctx.report_progress()` en bloque `finally` para evitar congelado de barra de progreso en modo verbose.
- **CLI warning en deep mode**: se imprime `[!] Deep mode: mu-plugins PHP probe active. This sends POST requests to PHP files on the target server. Only use with explicit authorization.` antes de iniciar el scan cuando `--deep` está activo.

### Tests
- 9 tests nuevos spec-driven en `tests/unit/test_module_webshells_mu_plugins.py` (21 total):
  - AC-2: verificación de que todos los nombres del wordlist se sondean en deep mode
  - AC-3: verificación de que GET 404 no dispara POST probe
  - AC-6: 6 tests individuales (uno por parámetro) + test para variante b64
  - AC-9: test de CLI warning con verificación positiva (warning presente) y negativa (ausente en fast mode)
- 2 tests reescritos para eliminar aserciones tautológicas

## [4.5.1] — 2026-05-24

### Fixed
- **PC-WSH-150 falso positivo (mu-plugins body vacío)**: archivos PHP en `/wp-content/mu-plugins/` que devuelven HTTP 200 con 0 bytes ahora emiten CRITICAL (no se suprimen silenciosamente). La description incluye la nota "empty response — may indicate China Chopper-style shell — manual verification required". El filtro catch-all se aplica correctamente también en respuestas vacías, evitando FP cuando el servidor devuelve 0 bytes para todas las rutas.
- **PC-MCFG-007 / PC-MCFG-008 falsos positivos (install.php / upgrade.php)**: los findings de `wp-admin/install.php` y `wp-admin/upgrade.php` ahora solo se emiten si el cuerpo de la respuesta contiene el formulario activo de instalación/actualización (detección positiva con regex HTML). En sitios ya instalados donde WordPress devuelve "Already installed" o "No upgrade required", el scanner no emite ningún finding, independientemente del idioma.
- **KNOWN_LATEST_VERSION actualizado a 7.0**: la constante hardcodeada en `wp_hardening.py` se actualizó de `6.8.1` a `7.0` (WordPress 7.0 es la versión estable actual, verificado vía API oficial de WordPress el 2026-05-24). Sitios con WP < 7.0 ahora se reportan correctamente como desactualizados.

### Tests
- 17 tests nuevos spec-driven añadidos:
  - `tests/unit/test_module_webshells_mu_plugins.py`: 3 tests AC-1 (body vacío, body con contenido, catch-all con tamaño cero)
  - `tests/unit/test_module_misconfigs_install_upgrade.py`: 10 tests AC-2/AC-3 (install.php con formulario activo, sin formulario, upgrade.php con y sin upgrade pendiente)
  - `tests/unit/test_module_wp_hardening.py`: 4 tests AC-4 (versiones 6.8.1, 6.9, 7.0, None)

## [4.5.0] — 2026-05-24

### Added
- **UsersModule — 7 técnicas de enumeración**: REST API con paginación completa (X-WP-TotalPages), author archives 1-25/1-100 IDs con early-stop, /wp-sitemap-users-1.xml (PC-USR-003), RSS `<dc:creator>` (PC-USR-004), Yoast /author-sitemap.xml (PC-USR-005), oEmbed (solo si author_url contiene /author/), y HTML author links
- **BruteForceModule**: nuevo módulo activado con `--brute-force`. Prueba ~70 contraseñas internas + variantes dinámicas del username con `--brute-force-defaults`. Soporta wordlist externa (`--brute-force-wordlist`), combinación (`--brute-force-combine`), límite 10k/50k líneas. Detección de éxito por cookie `wordpress_logged_in_`. Rate limiting detection (429/403/200+body/ConnectError). Finding PC-BRU-001 con passwords mascaradas.
- **Nuevos findings**: PC-USR-003 (sitemap), PC-USR-004 (RSS), PC-USR-005 (Yoast sitemap), PC-BRU-001 (credenciales encontradas), PC-BRU-002 (2FA detectado), PC-BRU-003 (sin usuarios), PC-BRU-004 (sin credenciales), PC-BRU-007 (rate limiting detectado), PC-BRU-008 (sin wordlist configurada)
- **ScanOptions**: campos `brute_force`, `brute_force_use_defaults`, `brute_force_wordlist`, `brute_force_combine` con propagación correcta en `run_many()`
- **ScanContext**: atributos `xmlrpc_accessible` y `xmlrpc_multicall_available` poblados por XMLRPCModule
- **CLI**: flags `--brute-force`, `--brute-force-defaults`, `--brute-force-wordlist`, `--brute-force-combine`
- **run_many() callbacks**: `on_finding`, `on_module_start`, `on_module_done`, `on_module_progress` ahora se propagan al Scanner interno de cada target en scans masivos

### Changed
- **`--brute-force` ya NO activa la lista interna por defecto**: ahora requiere `--brute-force-defaults` explícito (o `brute_force_use_defaults=True` en la API) para evitar ataques accidentales. Sin wordlist → emite PC-BRU-008 y termina sin hacer ningún intento de credenciales.
- **`--brute-force-combine` sin `--brute-force-defaults`**: solo usa la wordlist externa; no mezcla contraseñas internas.

### Fixed
- **UsersModule — author archives**: errores de red cuentan como miss consecutivo en vez de abortar toda la enumeración
- **BruteForceModule — path traversal**: `_load_wordlist()` valida que el path sea un archivo regular antes de abrirlo
- **UsersModule — paginación REST**: cap a 100 páginas máximo para evitar DoS contra el propio scanner por target malicioso
- **BruteForceModule — ID collision**: PC-BRU-007 para rate-limiting; PC-BRU-003 exclusivo para "sin usuarios"
- **UsersModule — RSS dedup**: guard de deduplicación compara `username` (no `display_name`)
- **UsersModule — descriptions**: `', '.join(...)` en vez de Python list repr

### Tests
- 41 nuevos tests spec-driven etiquetados por AC (Wave 4a/4b + correcciones API)
- Cobertura total: 85% (threshold 75%), 467 tests

---

## [4.4.0] — 2026-05-23

### Fixed
- **CVE Engine — rejected_cves rehabilitación**: `_apply_upserts()` ahora elimina de `rejected_cves` antes de reinsertar un CVE, evitando que CVEs rehabilitados queden suprimidos permanentemente (G2-003)
- **CVE Engine — upsert-wins-delete**: En un patch donde el mismo CVE aparece en `upsert[]` y `delete[]`, el upsert tiene prioridad — el CVE no queda blacklisted (G2-002)
- **CVE Engine — validación de fecha ISO 8601**: `_update_last_patch_date()` valida el formato antes de comparar; fechas malformadas ya no envenenan `last_patch_date` (G-002)
- **CVE Engine — deduplicación de batch**: duplicados `(cve_id, slug)` en el mismo patch se colapsan antes del procesamiento, evitando `IntegrityError` por batch (G-012)
- **CVE Engine — validación extendida**: `_validate_patch()` rechaza `slug=""` y severidades inválidas; `has_exploit=None` y `references=None` se coercionan a valores seguros (G-011, G2-009, G2-010, G2-014)
- **CVE Engine — blacklist de CVEs no existentes**: `_apply_deletes()` solo añade a `rejected_cves` si el CVE existe en `normalized_vulns` (G-007)
- **CVE Engine — SELECT mínimo en deletes**: La verificación de existencia en `_apply_deletes()` usa `SELECT cve_id LIMIT 1` en vez de cargar el objeto ORM completo (CB-3)
- **CVEStore — `:memory:` sin FileNotFoundError**: `CVEStore.from_url(":memory:")` ya no lanza `FileNotFoundError` (G-001)
- **Scanner — db_url en run_many()**: `run_many()` propaga `db_url` a cada scan individual, evitando que escaneos bulk ignoren la DB custom (G2-001)
- **CVEsModule — theme.vulns populado**: El módulo CVE ahora popula `theme.vulns` con `find_all_by_slug("theme", ...)`, igual que hace con plugins (G2-005)
- **CVEsModule — rejected_ids fetch-once**: `get_rejected_ids()` se llama una sola vez al inicio del módulo, eliminando 300+ queries redundantes en modo fast-scan (G-016)
- **Terminal reporter — Rich markup escaping**: Campos CVE externos (title, description) se escapan antes de interpolarse en markup Rich, evitando inyección de etiquetas (CA-2)
- **CLI — engine.dispose() en try/finally**: `engine.dispose()` se llama aunque `_clean_low_confidence_records()` lance una excepción (G3-001)

### Tests
- 44 nuevos tests: cobertura completa de `_is_affected()` (6 branches), `find_all_by_slug()`, filtrado `rejected_cves`, wordlists, pipeline CVE end-to-end (2 integration tests)
- Cobertura total: 84.39% (threshold 75%)

---

## [4.3.0] — 2026-05-22

### Added — Nuevo motor de normalización CVE v2

El proceso de correlación CVE←→plugin de WordPress ha sido completamente rediseñado para eliminar falsos positivos sistemáticos que afectaban a las versiones anteriores.

#### El problema anterior

El motor de la v4.2.x usaba exclusivamente Jaro-Winkler con threshold 0.82 para mapear nombres de CPE del NVD (ej: `element_pack`) a slugs de WordPress.org (ej: `bdthemes-element-pack-lite`). Esto producía:

- **Falsos positivos por similitud fonética**: `element_pack` → asignado a `elementor` (score 0.88, mayor que el slug correcto)
- **Registros basura**: cuando no había match, el motor asignaba `slug = nombre_cpe` con confianza 0.5, generando 1.740 registros inútiles
- **CVEs de betas con rango universal**: versiones como `5.8:beta1` generaban rango `*–*` (todos los usuarios afectados)

**Resultado medido en producción:** 71% de los findings eran falsos positivos.

#### El nuevo motor (pipeline en cascada)

El nuevo motor aplica señales en orden de fiabilidad, con cortocircuito en la primera señal de alta confianza:

1. **Exact match canónico** — normaliza `_` → `-` y compara contra el wordlist. `contact_form_7` → `contact-form-7`. Confianza: 1.0.

2. **Extracción desde URLs de referencia** — el 65-70% de los CVEs en NVD incluyen referencias directas a `plugins.trac.wordpress.org/.../bdthemes-element-pack-lite/` o `wordpress.org/plugins/word-replacer-ultra/`. El slug está ahí de forma explícita. Confianza: 0.95. Cero falsos positivos por diseño (el slug extraído se valida contra el wordlist).

3. **Jaro-Winkler con threshold elevado a 0.90** — solo como último recurso. Elimina el falso positivo de `element_pack→elementor` (score 0.8828 < 0.90).

4. **Sin match → sin inserción** — si ninguna etapa supera el threshold de confianza, el CVE no se inserta. Mejor un CVE no reportado que un CVE falso.

5. **Detección de prereleases** — CPEs con `beta`/`rc`/`alpha` en el URI se descartan silenciosamente.

#### Limpieza automática en `update-db`

`plecost update-db` ahora incluye una fase de limpieza que elimina los registros heredados con `match_confidence=0.5` cuyo slug no existe en ninguna wordlist conocida. La limpieza es idempotente y segura: preserva registros con slug en wordlist aunque tengan confianza baja.

#### Resultado

| Métrica | v4.2.x | v4.3.0 |
|---|---|---|
| Falsos positivos en producción | ~70% | <5% |
| CVEs basura (slug=product) | 1.740 | 0 |
| Cobertura de URL extraction | — | 65-70% de CVEs |
| Threshold Jaro-Winkler | 0.82 | 0.90 |

### Fixed

- **PC-XMLRPC-005**: eliminado falso positivo cuando WordPress bloquea métodos autenticados a nivel de aplicación (`faultCode: 405`) — ya cubierto en 4.2.8.
- **PC-SSL-003**: eliminado duplicado de PC-HDR-001 — ya cubierto en 4.2.8.
- **PC-MCFG-003**: eliminado falso positivo de `.env` con soft-404 de WordPress — ya cubierto en 4.2.8.
- **CVE-2024-1733**: corregido mapeo incorrecto `wordfence` → `word-replacer-ultra` — ya cubierto en 4.2.8.
- **CVE-2022-1546**: eliminado mapeo incorrecto a `woocommerce-products-filter` — ya cubierto en 4.2.8.

### Tests

- `plecost-db/tests/unit/test_updater.py`: 17 nuevos tests para el pipeline de normalización (extracción URL, canonical, prerelease, JW threshold, no-fallback).
- `plecost/tests/unit/test_cli_migration.py`: 7 tests para la limpieza de registros de baja confianza.


## [4.2.8] — 2026-05-22

### Fixed (CVE DB — low-confidence cleanup)
- **`_clean_low_confidence_records()`**: nueva función ejecutada automáticamente al inicio de `plecost update-db`. Elimina los registros de `normalized_vulns` donde `match_confidence=0.5` y el slug no existe en ninguna wordlist conocida (`plugins_wordlist` ni `themes_wordlist`). El pipeline antiguo generaba ~1.740 registros de fallback donde `slug=cpe_product_name` para CVEs que no tenían un mapeo a WordPress — estos producían falsos positivos durante el escaneo. La limpieza es idempotente: si no hay registros que eliminar, no emite ningún mensaje.

### Tests (CVE DB — low-confidence cleanup)
- Añadido `tests/unit/test_cli_migration.py` con 7 tests que cubren los AC-1 a AC-4: eliminación de orphans, preservación de slugs en wordlist (plugins y themes), preservación de registros con confianza alta, idempotencia, BD vacía y escenario mixto.



### Fixed (XMLRPCModule)
- **`XMLRPCModule` (PC-XMLRPC-005)**: eliminado falso positivo en detección de brute-force protection. Cuando WordPress deshabilita los métodos autenticados vía filtro `xmlrpc_enabled`, devuelve HTTP 200 con `faultCode: 405` en el cuerpo XML — no un HTTP 403/429 de WAF. El detector ahora parsea el `faultCode` XML: `405` = método desactivado a nivel de aplicación (protección real → PC-XMLRPC-006), `403` = credenciales incorrectas pero método funcional (sin protección → PC-XMLRPC-005).

### Tests (XMLRPCModule)
- Añadidos 3 tests en `tests/unit/test_module_xmlrpc.py`: `test_wp_application_level_protection_no_005_finding`, `test_wrong_credentials_emits_005`, `test_http_403_block_emits_006`.

### Fixed (SSLTLSModule)
- **`SSLTLSModule` (PC-SSL-003)**: eliminado finding duplicado de HSTS ausente. El módulo `ssl_tls` emitía `PC-SSL-003` (LOW) por el mismo header `Strict-Transport-Security` que ya detecta `http_headers` como `PC-HDR-001` (MEDIUM). El check HSTS se elimina de `ssl_tls` — la responsabilidad de los headers HTTP pertenece exclusivamente al módulo `http_headers`. `PC-SSL-003` se retira del uso activo pero se mantiene en el registro de IDs por compatibilidad.

### Tests (SSLTLSModule)
- Añadido `test_ssl_tls_does_not_emit_pc_ssl_003` en `tests/unit/test_module_ssl_tls.py`.

### Fixed (MisconfigsModule)
- **`MisconfigsModule` (PC-MCFG-003)**: eliminado falso positivo de `.env` expuesto en WordPress con soft-404. WordPress intercepta peticiones a rutas inexistentes devolviendo la página del sitio con HTTP 200 y `Content-Type: text/html`. El check ahora descarta la respuesta si: (1) el `Content-Type` contiene `text/html` para archivos de texto plano (`.env`, `.git/HEAD`, `debug.log`, `backup.sql`, `wp-config.php.bak`), o (2) la URL final tras seguir redirects difiere de la URL solicitada.

### Tests (MisconfigsModule)
- Añadidos 3 tests en `tests/unit/test_module_misconfigs.py`: `test_env_soft404_html_response_no_finding`, `test_env_plaintext_response_emits_finding`, `test_env_redirect_to_different_url_no_finding`.
- Actualizado `test_detects_env_file` para incluir `Content-Type: text/plain` en el mock.

### Fixed (CVE DB)
- **CVE-2024-1733 (PC-CVE-CVE-2024-1733)**: corregido mapeo incorrecto — el CVE pertenece al plugin `word-replacer-ultra` (Word Replacer Pro), no a `wordfence`. El normalizador upstream usó la URL de Wordfence Threat Intel de las referencias para inferir el slug, en vez del plugin afectado real.
- **CVE-2022-1546 (PC-CVE-CVE-2022-1546)**: eliminado mapeo incorrecto — el CVE pertenece a "WooCommerce - Product Importer", no a `woocommerce-products-filter` (HUSKY). Ambos plugins comparten parte del nombre pero son software distinto.
- **Nuevo mecanismo `local_patches.py`**: correcciones locales persistentes que se aplican al final de `plecost update-db`, permitiendo corregir entradas incorrectas del upstream sin esperar a un nuevo `full.json`.

### Tests (CVE DB)
- Añadido `tests/unit/test_database_local_patches.py` con 5 tests para el mecanismo de correcciones locales (AC-1 a AC-5).

## [4.2.7] — 2026-05-06

### Fixed
- **`ResponseFingerprintDetector` (PC-WSH-200)**: añadido `/wp-content/mu-plugins/` a `_CORE_WP_DIRS`. Los mu-plugins legítimos que definen funciones sin `echo` devuelven body vacío al accederse directamente — ya los cubre `MuPluginsDetector` con lógica catch-all más precisa. El fingerprint china_chopper ya no duplica detección con más FP en ese directorio.
- **`KnownPathsDetector` (PC-WSH-001)**: saltados paths en `/wp-admin/` y `/wp-includes/` (fix previo completado).
- **`FakePluginRestDetector` (PC-WSH-300)**: en modo fast (`--deep` no activo), la severidad es ahora `MEDIUM` en vez de `HIGH`. En modo fast se usa la wordlist top-150 y un plugin legítimo fuera de ese ranking no aparece en `ctx.plugins`, lo que generaba un HIGH falso. En modo deep (wordlist completa) la ausencia sigue siendo `HIGH`.

### Tests
- `test_module_webshells_fake_plugins.py`: dividido en `test_detects_fake_plugin_not_in_ctx_fast_mode` (espera MEDIUM) y `test_detects_fake_plugin_not_in_ctx_deep_mode` (espera HIGH).
- `test_module_webshells_known_paths.py`: añadidos 3 tests de no-regresión: `test_no_finding_for_core_wp_admin_paths`, `test_no_finding_for_core_wp_includes_paths`, `test_still_detects_shell_in_uploads_after_core_exclusion`.
- `test_module_webshells_response_fp.py`: añadidos `test_no_false_positive_china_chopper_in_mu_plugins` y `test_china_chopper_still_detected_in_uploads`.

## [4.2.6] — 2026-05-06

### Fixed
- **`ResponseFingerprintDetector` (PC-WSH-200)**: eliminado falso positivo de China Chopper en directorios del core de WordPress (`/wp-admin/`, `/wp-includes/`). Archivos legítimos como `wp-admin/includes/image.php` devuelven HTTP 200 con body vacío cuando se acceden directamente (sin parámetros ni nonce), lo que hacía coincidir erróneamente el fingerprint de China Chopper (`len(body) == 0`). Ahora el fingerprint de body vacío solo se aplica a directorios donde los atacantes sueltan shells (uploads, mu-plugins, raíz) — no a directorios del core.

### Tests
- Añadido `test_no_false_positive_on_core_wp_empty_body` en `tests/unit/test_module_webshells_response_fp.py`: verifica que `wp-admin/includes/image.php`, `wp-admin/css/*.php` y `wp-includes/images/*.php` con 200+body vacío no generan `PC-WSH-200 china_chopper`.

## [4.2.5] — 2026-04-27

### Added
- **`BaseDetector._detect_catch_all()`**: nuevo método compartido que detecta servidores catch-all mediante doble probe + comparación de tamaño con tolerancia del 5%. Previene falsos positivos masivos en sitios Hugo/Cloudflare/SPA que devuelven HTTP 200 para cualquier path.

### Fixed
- **`UploadsPhpDetector`**: reemplazada comparación exacta de cuerpo (`r.text == baseline_body`) por `_detect_catch_all()`. Elimina hasta 273 × PC-WSH-100 falsos positivos en sitios Cloudflare con contenido dinámico por petición (Ray IDs).
- **`MuPluginsDetector`**: reemplazada comparación exacta de cuerpo por `_detect_catch_all()`. Elimina hasta 25 × PC-WSH-150 falsos positivos en las mismas condiciones.

### Tests
- Creado `tests/unit/test_webshells_base_detector.py` con 7 tests unitarios del helper `_detect_catch_all`.
- Añadidos 2 tests en `tests/unit/test_module_webshells_uploads.py`: escenario Cloudflare catch-all y webshell real con tamaño diferente.
- Añadidos 2 tests en `tests/unit/test_module_webshells_mu_plugins.py`: ídem.

## [4.2.4] — 2026-04-22

### Added
- **`Finding.category`**: nuevo campo auto-derivado del ID del finding — categoría semántica de grano fino (p.ej. `ssl_certificate`, `credentials_exposed`, `webshell`, `cve`…). Se calcula automáticamente en `__post_init__` sin necesidad de tocar ningún módulo existente. Función pública `derive_finding_category(id)` exportable.
- **`findings_by_category`** en JSON reporter: el JSON de salida incluye ahora un bloque `findings_by_category` con los findings agrupados por categoría, además de la lista plana `findings` (retrocompatible).
- **Taxonomía de 28 categorías**: `ssl_certificate`, `ssl_redirect`, `hsts`, `clickjacking`, `content_security_policy`, `http_headers`, `version_disclosure`, `credentials_exposed`, `source_code_exposed`, `debug_exposure`, `backup_files`, `admin_scripts`, `directory_listing`, `user_enumeration`, `xmlrpc`, `rest_api_exposure`, `cve`, `open_registration`, `woocommerce_api_exposure`, `woocommerce_cve`, `wp_ecommerce`, `wp_ecommerce_cve`, `card_skimmer`, `suspicious_content`, `webshell`, `waf_detected`, `infrastructure`, `authentication`, `attack_surface`.

## [Unreleased] — 2026-04-17

### Docs
- **README**: añadido índice (Table of Contents) al principio del documento
- **README**: sección "Comparison" movida justo después de "What is Plecost?" para mayor visibilidad
- **README**: tabla comparativa frente a WPScan completamente reescrita y ampliada — cubre ahora 5 dimensiones (arquitectura técnica, capacidades de escaneo, detección de vulnerabilidades, salida e integración, independencia de datos) con más de 50 características comparadas
- **README**: añadida sección narrativa "Data Independence" explicando las limitaciones del tier gratuito de WPScan (25 tokens/día) frente al modelo local de Plecost
- **README**: módulo `webshells` añadido a la tabla de Detection Modules (faltaba)
- **README**: contador de módulos corregido a 18

## [4.2.3] — 2026-04-16

### Added (PR #36 — ffr4nz)
- **xmlrpc**: detección activa de rate limiting / guardrails — plecost envía 5 intentos de login consecutivos contra `xmlrpc.php`; si ninguno recibe 403/429/406 ni corte de conexión, emite `PC-XMLRPC-005` HIGH ("Brute-Force Protection Missing"); si se detecta bloqueo, emite `PC-XMLRPC-006` INFO ("Guardrails Active")
- **xmlrpc**: nuevo finding `PC-XMLRPC-004` HIGH cuando `system.multicall` está habilitado (amplificación de fuerza bruta)
- **i18n**: claves `pc_xmlrpc_004`, `pc_xmlrpc_005`, `pc_xmlrpc_006` en `en.json` y `es.json`

### Fixed (post-merge cleanup)
- `PC-XMLRPC-INFO` renombrado a `PC-XMLRPC-006` para cumplir el patrón `PC-[A-Z]+-\d{3}`
- `data=` → `content=` en llamadas httpx dentro de `xmlrpc.py` (elimina DeprecationWarning)
- Añadidos `PC-XMLRPC-004`, `PC-XMLRPC-005`, `PC-XMLRPC-006` a `KNOWN_FINDING_IDS` en contrato de tests

### Fixed
- **pre-flight / SSL auto-retry**: cuando httpx no puede verificar el certificado SSL del objetivo, plecost ahora reintenta automáticamente con `verify=False` sin intervención del usuario. Se emite un finding informativo `PC-PRE-002` para notificar que el certificado no pudo verificarse, pero el escaneo continúa normalmente. Antes, todos los métodos de detección de WordPress fallaban silenciosamente con `except Exception: pass` y plecost reportaba "WordPress: No" sin ninguna indicación del problema real.
- **contract tests**: añadidos `PC-PRE-001` y `PC-PRE-002` a `KNOWN_FINDING_IDS` en `tests/contract/test_finding_ids.py`.

## [4.2.2] — 2026-04-15

### Fixed
- **webshells / uploads_php**: `UploadsPhpDetector` now performs a baseline probe against a non-existent path (`__plecost_probe_xyz__.php`) before scanning the wordlist. On soft-200 servers (those that return HTTP 200 for any path), responses matching the baseline body are skipped as false positives, eliminating hundreds of duplicate CRITICAL findings.
- **webshells / mu_plugins**: `MuPluginsDetector` applies the same soft-200 baseline probe strategy against `wp-content/mu-plugins/`, preventing mass-duplicate findings on servers that return 200 for all paths.
- **plugins**: passive detection of plugin slugs from the homepage HTML no longer creates false-positive "unknown version" findings. When the active wordlist scan confirms a plugin does not exist (soft-200 content mismatch or 404), the slug is now removed from the found set so it is not reported.
- **terminal / VerboseDisplay**: `_render()` no longer renders the full module list in a fixed-height table, which caused the last modules (magecart, webshells) to be clipped at small terminal heights. The display now shows at most the 12 most recent module rows with a compact `done/total` header line (using `box=None`), ensuring running and recently-completed modules are always visible.

## [4.2.1] — 2026-04-14

### Fixed
- `PluginVuln` now includes `description`, `remediation`, and `references` fields in JSON output so downstream tooling has full CVE details without cross-referencing the `findings` array.
- Fixed missing type annotations in `i18n.py` and `webshells/detectors/fake_plugins.py` that caused mypy strict-mode failures in CI.

## [unreleased] — 2026-04-14

### Added
- Full internationalization (i18n) support with `plecost/locales/en.json` and `es.json`
- `--lang` CLI flag on `scan`, `explain`, and `modules list` commands to force output language
- `PLECOST_LANG` environment variable for language selection (lower priority than `--lang`)
- Language auto-detection from system locale (`LANG`, `LC_ALL`) with English fallback
- `plecost/i18n.py` module with `t(key, **kwargs)` and `set_language(lang)` API
- New languages can be added by dropping a JSON file in `plecost/locales/`

### Changed
- `reporters/terminal.py`: all hardcoded labels replaced with `t()` calls
- `modules/wp_ecommerce.py`: all Finding strings now use i18n keys (13 findings localized)
- `modules/misconfigs.py`: `_CHECKS` tuples use i18n keys; `_check()` calls `t()` at runtime
- `cli.py`: `explain` and `modules list` commands fully localized

---

## [Unreleased] — 2026-04-14

### Fixed
- **plugins**: passive scan no longer overwrites a found `?ver=` version with `None` when the same plugin slug appears multiple times in the HTML; now keeps the best version seen across all occurrences
- **themes**: same fix — first occurrence without `?ver=` is now upgraded if a later occurrence has the parameter
- **plugins / themes**: passive detection window for `?ver=` extended from 100 to 200 characters after the path match, reducing missed versions on deeper resource paths
- **plugins / themes**: plugins/themes detected passively but absent from the brute-force wordlist now receive a targeted `readme.txt` / `style.css` fetch to recover the version instead of always showing `unknown`
- **plugins / themes**: `readme.txt` "Stable tag" and `style.css` "Version:" now always take precedence over `?ver=` from HTML; previously sub-package assets with different version strings could pollute the reported version (e.g. woocommerce showing 4.0.0 instead of 5.0.0)
- **plugins / themes**: when the server returns HTTP 200 for non-existent paths (WordPress routing all requests through `index.php`), the brute-force scanner now validates response content using readme.txt / style.css header patterns instead of trusting the status code; this eliminates false positives where all plugins in the wordlist were reported as installed
- **plugins / themes**: passive HTML detections (plugin/theme path in page source) are kept with `version=null` even when readme.txt / style.css cannot be validated; only brute-force wordlist candidates are discarded on content mismatch — a plugin referenced in the HTML is considered installed regardless
- 12 new regression tests covering all five fixed scenarios

### Added
- `webshells` module: remote webshell detection for WordPress sites
  - `KnownPathsDetector`: probes ~100-300 known webshell filenames across WP directories; includes catch-all preflight guard to eliminate false positives
  - `UploadsPhpDetector`: detects PHP execution in `wp-content/uploads/` across all year/month subdirs (2020–present)
  - `MuPluginsDetector`: probes must-use plugins directory (`wp-content/mu-plugins/`) — primary vector for persistent backdoors in 2024-2025 attacks
  - `ResponseFingerprintDetector`: fingerprints HTTP response bodies against China Chopper, WSO/FilesMan, b374k, c99shell, Godzilla/Behinder, and polyglot image/PHP families
  - `ChecksumsDetector` (requires credentials): verifies 20 high-risk WordPress core files via `api.wordpress.org/core/checksums/`
  - `FakePluginRestDetector` (requires credentials): uses `/wp-json/wp/v2/plugins` with Basic Auth to detect unauthorized or hidden plugins
- 6 new finding IDs: `PC-WSH-001`, `PC-WSH-100`, `PC-WSH-150`, `PC-WSH-200`, `PC-WSH-250`, `PC-WSH-300`
- Module option `--module-option webshells:wordlist=extended` activates ~300-path wordlist
- Module option `--module-option webshells:detectors=name1,name2` runs only specified detectors
- `FakePluginRestDetector` in `plecost/modules/webshells/detectors/fake_plugins.py` — queries WP REST API `/wp-json/wp/v2/plugins` with Basic Auth and flags any active plugin not previously detected by passive scanning, emits `PC-WSH-300` (HIGH, CVSS 7.5)
- 4 unit tests in `tests/unit/test_module_webshells_fake_plugins.py`: fake plugin flagged, known plugin skipped, no credentials skipped, 401 response skipped
- `UploadsPhpDetector` in `plecost/modules/webshells/detectors/uploads_php.py` — probes `wp-content/uploads/` (root and dated year/month subdirectories) for accessible PHP files, emits `PC-WSH-100` (CRITICAL, CVSS 9.8) on any HTTP 200 response
- 3 unit tests in `tests/unit/test_module_webshells_uploads.py`: PHP in uploads root, PHP in dated subdir, no finding on 403
- `KnownPathsDetector` in `plecost/modules/webshells/detectors/known_paths.py` — probes known webshell filenames across common WordPress directories, emits `PC-WSH-001` (CRITICAL, CVSS 9.8) on hit
- Preflight catch-all guard: detects sites that return 200 for arbitrary paths and skips scan to avoid mass false positives
- Content-type FP guard: only flags responses with `text/html`, `text/plain`, or `application/x-httpd-php` content types
- 4 unit tests in `tests/unit/test_module_webshells_known_paths.py`: 200/text-html hit, all-404, image content-type FP guard, catch-all site skip
- `magecart` module: detects Magecart/card-skimming JavaScript on WooCommerce and WP eCommerce checkout pages via blocklist lookup (`PC-MGC-000` through `PC-MGC-004`)
- `MagecartDomain` ORM model and `get_magecart_domains()` store query in `plecost/database/`
- `MagecartInfo` dataclass in `plecost/models.py`; added `magecart` field to `ScanResult` and `ScanContext`
- `download_magecart_domains()` in `plecost/database/downloader.py` for fetching blocklist from GitHub releases
- `apply_magecart_patch()` in `plecost/database/patch_applier.py` for applying domain blocklist updates
- 5 new finding IDs: `PC-MGC-000` (INFO), `PC-MGC-001` (CRITICAL), `PC-MGC-002` (CRITICAL), `PC-MGC-003` (HIGH), `PC-MGC-004` (MEDIUM)
- Unit tests for `MagecartModule` (`tests/unit/test_module_magecart.py`): 14 tests covering `_should_run`, URL generation, detection per category, summary emission, graceful 404 handling, inline/same-domain script filtering, and store call verification
- DB-layer tests for `MagecartDomain` store queries (`tests/unit/test_database_magecart.py`): active domain matching, empty-list guard, soft-delete exclusion
- Contract test update: `PC-MGC-000` through `PC-MGC-004` added to `KNOWN_FINDING_IDS` in `tests/contract/test_finding_ids.py`

## [Unreleased] - 2026-04-14 (magecart module implementation)

### Added
- New `magecart` security module (`plecost/modules/magecart.py`) detecting Magecart / card-skimming JavaScript on WooCommerce and WP eCommerce checkout pages
- Scans `/checkout`, `/cart`, `/?pagename=checkout`, `/?pagename=cart` via passive GET requests
- Extracts external script `src` attributes and checks domains against the local CVE database blocklist
- Finding IDs: PC-MGC-000 (INFO summary), PC-MGC-001 (CRITICAL, Magecart domain on checkout), PC-MGC-002 (CRITICAL, dropper on checkout), PC-MGC-003 (HIGH, exfiltrator on checkout), PC-MGC-004 (MEDIUM, known domain on non-checkout page)
- Severity mapping supports three domain categories: `magecart`, `dropper`, `exfiltrator`
- `ctx.magecart` populated with `MagecartInfo` (detected, pages_scanned, scripts_analyzed, malicious_domains)
- Module only runs when WooCommerce or WP eCommerce is detected (`depends_on: fingerprint, woocommerce, wp_ecommerce`)

## [Unreleased] - 2026-04-13

### Added
- Extended `tests/property/test_robustness.py` with three new Hypothesis tests: `plugins._VER_RE` never raises on arbitrary text, all `_FINDINGS_REGISTRY` IDs match the `PC-<MODULE>-<ID>` pattern, and `ScanContext.url` never retains a trailing slash
- New `tests/contract/test_json_output_schema.py` with 10 golden/schema tests verifying the JSON output contract: required top-level keys, ecommerce fields always present, Finding field completeness, ScanSummary keys, Severity serialized as uppercase string, timestamp as ISO string, correct types for lists/booleans/numbers
- 8 new unit tests for `FingerprintModule` covering `_try_feed()`, `_try_rest_api()`, and `_try_wp_paths()` (normal server and WAF blanket scenarios)

## [4.2.0] - 2026-04-13

### Added
- New `wp_ecommerce` security module detecting misconfigurations and vulnerabilities in WP eCommerce (wp-e-commerce) plugin
- 13 new finding IDs: PC-WPEC-000 through PC-WPEC-010, PC-WPEC-020, PC-WPEC-021
- Passive checks: plugin directory listing, uploads directory exposure, digital downloads directory exposure, admin script exposure (db-backup.php, display-log.php), ChronoPay gateway detection and callback endpoint check
- Semi-active checks (--module-option wpec:mode=semi-active): CVE-2024-1514 (ChronoPay SQL Injection) and CVE-2026-1235 (PHP Object Injection) detection
- PC-WPEC-003: always-emitted finding flagging WP eCommerce as abandoned since 2020 with unpatched CVEs
- `wp_ecommerce` JSON section in scan output with version, active_gateways, and checks_run

---

## [4.1.0] — 2026-04-13

### Added
- New `woocommerce` module for detecting vulnerabilities and misconfigurations in WooCommerce and its official plugins (Payments, Blocks, Stripe Gateway)
- Generic per-module options system: `--module-option MODULE:KEY=VALUE` in CLI and `ScanOptions.module_options` in library API
- 16 new finding IDs: PC-WC-000 to PC-WC-021
- `WooCommerceInfo` dataclass in `ScanResult` with dedicated section in JSON output
- Passive checks: WooCommerce fingerprinting, sub-plugin detection (Payments, Blocks, Stripe), REST API open without auth, wc-logs directory listing, uploads directory exposure
- Semi-active checks (require `--module-option woocommerce:mode=semi-active`): CVE-2023-28121 (WooCommerce Payments auth bypass, CVSS 9.8) and CVE-2023-34000 (Stripe Gateway IDOR, CVSS 7.5)
- Authenticated checks (require consumer key/secret in module_options): system-status and payment-gateways
- 25 unit tests with respx

### Fixed
- `Scanner.run_many()` now propagates `module_options` to all targets in multi-target scans

---

## 2026-04-13 — Per-plugin CVE detail tables in scan output

### Added
- `PluginVuln` dataclass in `models.py`: lightweight CVE record for display (cve_id, title, severity, cvss_score, has_exploit, version_range)
- `Plugin.vulns: list[PluginVuln]` field: all known CVEs for the plugin slug regardless of installed version
- `Plugin.vuln_count` property: derived from `len(vulns)`
- `CVEStore.find_all_by_slug()`: returns all non-rejected CVEs for a slug without version filtering
- Terminal reporter: per-plugin CVE tables after the summary table, sorted by severity (CRITICAL first), with color-coded severity and exploit indicator

### Changed
- `CVEsModule.run()`: populates `plugin.vulns` for every detected plugin via `find_all_by_slug()`
- `CVEStore.count_by_slug()` replaced by `find_all_by_slug()` (count derived from result length)

---

## 2026-04-13 — README: remove build-db/sync-db sections, fix CVE DB refs, update workflows

### Changed
- `README.md`: removed `build-db` and `sync-db` entries from Table of Contents
- `README.md`: updated Environment Variables table — dropped `NVD_API_KEY` row, narrowed `PLECOST_DB_URL` scope to `update-db`
- `README.md`: removed CLI Reference sections for `plecost build-db` and `plecost sync-db`
- `README.md`: updated "Which command to use?" table to reference `plecost-db` repo
- `README.md`: updated "How it works" — `update-db` release URL points to `Plecost/plecost-db`, items 2/3 reference `plecost-db` commands with repo links
- `README.md`: updated `docs/cve-patch-system/` link to `https://github.com/Plecost/plecost-db/tree/main/docs/cve-patch-system`
- `README.md`: updated "Using PostgreSQL" section — removed `build-db` command, added `plecost-db build-db` block
- `README.md`: removed "NVD API rate limiting during build-db" troubleshooting section
- `README.md`: fixed from-source install path (`cd plecost` instead of `cd plecost/src`)
- `.github/workflows/ci.yml`: removed `v3.0.0` from push branch triggers; added `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`
- `.github/workflows/docker-publish.yml`: added `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`
- `.github/workflows/pypi-publish.yml`: added `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`

---

## 2026-04-13 — Eliminar build-db/sync-db, mover módulos/workflows/docs a plecost-db

### Removed
- `plecost/cli.py`: eliminados comandos `build-db` y `sync-db` del CLI
- `plecost/database/updater.py`: módulo de generación inicial de BD (movido a plecost-db)
- `plecost/database/incremental.py`: módulo de sincronización incremental (movido a plecost-db)
- `tests/unit/test_database_updater.py`, `tests/unit/test_database_incremental.py`, `tests/integration/test_database_updater.py`
- `.github/workflows/update-cve-db.yml`, `.github/workflows/update-databases.yml` (movidos a plecost-db)
- `docs/cve-patch-system/` y `docs/cve-database-architecture-decision.md` (movidos a plecost-db)

### Changed
- `plecost/database/downloader.py`: `GITHUB_REPO` apunta ahora a `Plecost/plecost-db`
- `tests/unit/test_database_downloader.py`: URLs actualizadas a `Plecost/plecost-db`

---

## 2026-04-12 — Add tests for patch_applier (13 tests, 0% → coverage)

### Added
- `tests/unit/test_database_patch_applier.py`: 13 tests covering apply_patch, validation, deletes, idempotence, date tracking

---

## 2026-04-12 — README: document JSON patch system

### Changed
- `README.md`: added "How the patch system works" table explaining incremental update sizes and link to docs/cve-patch-system/

---

## 2026-04-12 — update-db: improved error messages for first-run and network failures

### Changed
- `plecost/cli.py`: `update-db` distinguishes 404/401/5xx/ConnectError with actionable messages
- `plecost/cli.py`: first-run message explains that subsequent updates will be small

---

## 2026-04-12 — Minor fixes: .gitignore and Dockerfile

### Fixed
- `.gitignore`: added `.hypothesis/` to ignore hypothesis test database files
- `Dockerfile`: removed duplicate uvloop installation (already included via [fast] extra)

---

## 2026-04-12 — patch_applier: batching and progress logging

### Changed
- `plecost/database/patch_applier.py`: `_apply_upserts()` flushes every 2000 records to avoid memory pressure with large full.json files
- `plecost/database/patch_applier.py`: added `logging` calls at INFO/DEBUG level for progress visibility
- `plecost/database/patch_applier.py`: extracted `_build_values()` helper to remove duplication

---

## 2026-04-12 — Fix GitHub Actions workflow: consistent DB path + guaranteed patch file

### Fixed
- `.github/workflows/update-cve-db.yml`: use single `DB_PATH` env var for consistent DB path across all steps
- `.github/workflows/update-cve-db.yml`: generate empty patch JSON if sync-db produces no output

---

## 2026-04-12 — docs: detailed technical documentation for the CVE JSON patch system

### Added
- `docs/cve-patch-system/README.md`: overview, system diagram, quick-reference command table, index of all documents in the folder
- `docs/cve-patch-system/architecture.md`: full technical architecture — motivation for JSON over SQLite, GitHub release artifact layout, step-by-step client and CI flows, database model reference (`NormalizedVuln`, `RejectedCve`, `DbMetadata`), CPE-to-slug mapping explanation, rejected CVE audit trail rationale
- `docs/cve-patch-system/file-formats.md`: complete format specification for every artifact — `index.json`, `index.checksum`, `patch-YYYY-MM-DD.json`, `full.json`, `full.checksum` — with annotated examples derived from the actual code and field-level reference tables
- `docs/cve-patch-system/operations.md`: operational guide covering first install, daily update, CI failure recovery, manual CVE rejection via SQL, PostgreSQL usage, and common troubleshooting scenarios
- `docs/cve-patch-system/code-guide.md`: developer guide for extending the system — adding patch format fields, integrating new CVE sources (Wordfence/Patchstack), extension points in `patch_applier.py`, testing patterns, and common pitfalls

---

## 2026-04-12 — update-db uses JSON patch system; sync-db supports --output-patch; new CI workflow

### Changed
- `plecost/cli.py` — `update-db` command now uses the JSON patch system instead of downloading a monolithic SQLite file:
  - New `--force-full` flag forces re-download of `full.json` even if patches are available
  - New helper coroutines `_update_db_async()`, `_get_metadata()`, `_set_metadata()` implement the full patch flow:
    1. Fetch remote `index.checksum` (~64 bytes) and compare with locally stored value in `db_metadata`
    2. If different (or `--force-full`): download `full.json` on first run, then apply all missing daily patches
    3. Store updated `index_checksum` in `db_metadata` after success
  - `update-db` still only supports SQLite; PostgreSQL users should use `build-db`
- `plecost/cli.py` — `sync-db` command now passes `--output-patch` option through to `IncrementalUpdater`
- `.github/workflows/update-cve-db.yml` — replaced old workflow (download SQLite + publish) with new patch-generation workflow:
  - Downloads existing DB via `plecost update-db`
  - Runs `plecost sync-db --output-patch patch-YYYY-MM-DD.json` to generate today's patch
  - Downloads existing patch files from the `db-patches` release
  - Builds `full.json` (all upserts/deletes merged) and `index.json` with SHA256 for each patch
  - Publishes everything (full.json, full.checksum, index.json, index.checksum, patch-*.json) to the `db-patches` release tag (overwriting)

---

## 2026-04-12 — incremental updater generates daily JSON patch file

### Changed
- `plecost/database/updater.py`: `process_nvd_batch()` now accepts an optional `collected: list[dict] | None = None` parameter; when provided, each processed vulnerability record (matching the daily-patch JSON schema) is appended to the list in addition to being persisted in the DB
- `plecost/database/incremental.py`: `IncrementalUpdater.__init__()` now accepts `output_patch: str | None = None`; when set, `run()` writes a daily-patch JSON file (`date`, `source`, `upsert`, `delete`) to the given path after completing the sync

---

## 2026-04-12 — JSON patch system: RejectedCve model, patch_applier module, store filtering

### Added
- `plecost/database/models.py`: new `RejectedCve` model (`rejected_cves` table) — soft-delete table for CVEs removed/disputed from NVD; never physically deletes rows
- `plecost/database/patch_applier.py`: new module implementing JSON patch application — `apply_patch()` validates then applies upserts and soft-deletes in a single transaction; `get_last_patch_date()` returns last patch timestamp; portable across SQLite and PostgreSQL via SQLAlchemy select/setattr pattern
- `plecost/database/store.py`: `CVEStore.find()` now filters out any CVE IDs present in `rejected_cves` before returning vulnerability records

---

## 2026-04-12 — Overhaul downloader.py for JSON patch system with SHA256 verification

### Changed
- `plecost/database/downloader.py`: replaced single-SQLite-download approach with a new JSON patch system:
  - New constants: `PATCHES_RELEASE_TAG`, `BASE_URL`, `INDEX_URL`, `INDEX_CHECKSUM_URL`, `FULL_JSON_URL`, `FULL_CHECKSUM_URL`
  - New async functions: `fetch_remote_index_checksum()`, `fetch_index()`, `download_full_json()`, `download_patch()`
  - Internal helpers: `_sha256_file()`, `_sha256_bytes()`, `_fetch_bytes()`, `_stream_to_file()`, `_make_headers()`
  - All downloads include SHA256 verification against checksums fetched from GitHub releases
  - `download_latest_db()` kept as deprecated legacy function for backwards compatibility

## 2026-04-12 — Audit fixes: severity bug, silent failures, themes display, 43 new tests

### Fixed
- `plecost/modules/ssl_tls.py`: PC-SSL-002 severity corrected from `MEDIUM` to `HIGH` (aligned with CLI registry)
- `plecost/modules/ssl_tls.py`: SSL error detection now catches `httpx.TransportError` (covers all transport-layer SSL/TLS failures) and checks for "tls" in addition to "ssl" and "certificate"
- `plecost/scanner.py`: replaced silent `except Exception: pass` on CVE DB load with a stderr warning directing user to run `plecost update-db`
- `plecost/scanner.py`: translated Spanish comment to English
- `plecost/reporters/terminal.py`: detected themes are now displayed in a Rich table (was missing, themes were detected but never shown)
- `plecost/database/store.py`: `CVEStore.from_url()` raises `FileNotFoundError` with actionable message when SQLite DB file doesn't exist

### Added
- `tests/unit/test_module_ssl_tls.py`: 6 tests for SSL/TLS module
- `tests/unit/test_module_debug_exposure.py`: 8 tests for debug exposure module
- `tests/unit/test_module_content_analysis.py`: 9 tests for content analysis module
- `tests/unit/test_database_engine.py`: 3 tests for database engine factory
- `tests/unit/test_database_downloader.py`: 3 tests for GitHub release downloader
- `tests/unit/test_database_updater.py`: 10 tests for NVD batch processor and Jaro-Winkler matching
- `tests/unit/test_database_incremental.py`: 3 tests for incremental NVD sync
- Total test count: 65 → 108 (+43 new tests)

### Removed
- `plecost/database/updater.py`: dead `DatabaseUpdater._upsert_vuln()` method

---

## 2026-04-11 — CVE DB guard, dead code removal, CLI envvar support

### Fixed
- `plecost/database/store.py`: `CVEStore.from_url()` now raises `FileNotFoundError` with a clear message if the SQLite file does not exist, instead of failing silently downstream
- `plecost/database/updater.py`: removed dead `DatabaseUpdater._upsert_vuln()` method that only delegated to `_upsert_vuln_free()`

### Added
- `plecost/cli.py`: added `envvar` support to key CLI options:
  - `--db-url` → `PLECOST_DB_URL` (in `update-db`, `build-db`, `sync-db` commands)
  - `--timeout` → `PLECOST_TIMEOUT` (in `scan` command)
  - `--output` → `PLECOST_OUTPUT` (in `scan` command)

---

## 2026-04-10 — i18n, mypy fixes and git hooks

### Changed
- Translated all Spanish text to English across the entire codebase (comments, docstrings, CLI messages, error messages, logs, documentation, CHANGELOG)
- Files translated: `plecost/cli.py`, `plecost/database/downloader.py`, `plecost/database/incremental.py`, `plecost/database/updater.py`, `plecost/database/models.py`, `plecost/database/store.py`, `tests/functional/test_scanner_functional.py`, `CHANGELOG.md`, `ANALYSIS.md`, `docs/cve-database-architecture-decision.md`, `docs/superpowers/specs/2026-04-10-plecost-design.md`

### Fixed
- `plecost/database/engine.py`: fixed `dict` type without arguments → `dict[str, Any]`
- `plecost/database/updater.py`: replaced all deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)`, typed `params` as `dict[str, str | int]`, typed `vulns` as `list[object]`, removed redundant `from datetime import timezone` in method body
- `plecost/database/incremental.py`: added explicit `str()` cast on `row.value` to fix mypy `Returning Any` error

### Added
- `.githooks/pre-push`: pre-push hook running ruff, mypy and pytest before each push
- `.githooks/README.md`: instructions to activate the hooks with `git config core.hooksPath .githooks`

---

## [4.2.0] - 2026-04-10

### Changed
- CVE database distribution system redesigned:
  - `plecost update-db`: downloads pre-built DB from GitHub releases (fast, for end users)
  - `plecost build-db`: builds DB from scratch from NVD (for maintainers, first run)
  - `plecost sync-db`: incremental update (only new/modified CVEs since last sync)
  - GitHub Action uses incremental sync: downloads DB from previous release, applies NVD delta, publishes new release
  - `db_metadata` table in SQLite stores `last_nvd_sync` for incremental updates
  - Support for `NVD_API_KEY` environment variable (higher rate limit: 0.6s vs 6s between requests)
  - `DatabaseUpdater` accepts `years_back` and `nvd_api_key` in constructor
  - `process_nvd_batch` refactored as a free reusable function from `updater.py` and `incremental.py`
  - New module `plecost/database/downloader.py`: streaming download from GitHub releases
  - New module `plecost/database/incremental.py`: `IncrementalUpdater` for NVD delta sync
  - `.github/workflows/update-cve-db.yml` updated with `contents: write` permissions and incremental flow

---

## [4.1.0] - 2026-04-10

### Changed
- Complete redesign of the CVE database system
  - SQLAlchemy 2.0 async (aiosqlite for SQLite, asyncpg for PostgreSQL)
  - New `NormalizedVuln` model with exact version ranges (versionStartIncluding/Excluding, versionEndIncluding/Excluding)
  - Real CPE parsing from NVD with target_sw=wordpress filter
  - Inline Jaro-Winkler fuzzy matching (no extra dependency) for slug→CPE product mapping
  - Downloads the last 5 years of CVEs from NVD with pagination
  - `DatabaseUpdater` accepts `db_url` instead of `db_path` (SQLite and PostgreSQL support)
  - `CVEStore` fully async with `from_url()` factory method
  - `scanner.py`: wordlist loading and store moved to async `run()`
  - `cves.py`: `store.find()` is now called with `await`
  - `cli.py update-db`: new flag `--db-url` replacing `--db-path`
  - Removed `aiofiles` dependency, added `sqlalchemy[asyncio]>=2.0` and `aiosqlite>=0.19`
  - Unit tests updated for the new async SQLAlchemy store

---

## 2026-04-10 — Technical debate and architectural decision for the CVE database

### Added
- `docs/cve-database-architecture-decision.md`: Decision document resulting from a structured technical debate among 5 approaches (CPE Purist, WP-Specific APIs, Pre-built Dictionary, Layered Hybrid, NLP/Similarity) to solve the slug→CVE mapping problem in Plecost v4.0
  - Winning approach is Delta (Layered Hybrid): NVD for WordPress Core, specialized WP APIs (Patchstack/Wordfence) for plugins/themes, curated seed dictionary for top 500 plugins
  - Concrete technical proposal: SQLAlchemy 2.0 async models, SQLite/PostgreSQL engine factory, layered updater flow, O(1) lookup at scan time
  - Effort estimate: ~10.5 days / 1 sprint

---

## [4.0.1] - 2026-04-11

### Changed
- License changed from FSL-1.1-MIT to PolyForm Noncommercial License 1.0.0
  - Standard license drafted by lawyers, no automatic conversion to open source
  - Commercial use requires a paid license (contact: cr0hn@cr0hn.com)
  - Link: https://polyformproject.org/licenses/noncommercial/1.0.0/
- README completely rewritten in English
- Improved professional appearance: Nuclei/WPScan style, clean tables, demo output, architecture, benchmarks

---

## 2026-04-10 — Functional tests against real WordPress with Docker

### Added
- `docker-compose.test.yml`: updated with improved healthcheck (mysqladmin with credentials, curl wp-login.php) and correct environment variables
- `tests/functional/test_scanner_functional.py`: 8 functional tests verifying WordPress detection, version, findings, summary, readme.html, REST API and JSON reporter
- `tests/conftest.py`: registers the `functional` marker for pytest
- `scripts/run_functional_tests.sh`: CI helper script that starts Docker, waits for WordPress and runs the tests
- `pyproject.toml`: added `markers` in `[tool.pytest.ini_options]` with the `functional` marker

---

## 2026-04-10 — Import fixes and test quality

### Fixed
- Removed 11 unused imports in test files (`pytest`, `json`, `asyncio`, `VulnerabilityRecord`, `Plugin`, `Theme`, `User`) detected by ruff
- All 53 unit tests pass correctly
- mypy and ruff clean in `plecost/` and `tests/`

---

## [4.0.0] - 2026-04-10

### Changed
- License changed from MIT to FSL-1.1-MIT (Functional Source License)
  - Free use for research, internal audits and open source projects
  - Prohibited to offer as SaaS or paid service
  - Automatically converts to MIT after 4 years

---

## 2026-04-10 — CI/CD workflows

### Added
- `.github/workflows/docker-publish.yml`: publica imagen multi-arch (amd64/arm64) en `ghcr.io/Plecost/plecost` al hacer push a main (tag `latest`) o push de tags `v*.*.*`
- `.github/workflows/pypi-publish.yml`: publica paquete en PyPI con trusted publishing (OIDC) al hacer push de tags `v*.*.*`
- `Dockerfile`: added standard OCI labels (`source`, `description`, `licenses`) and `uvloop` installation

---

## 2026-04-10 — v4.0.0

Complete rewrite from scratch. Plecost v4.0.0 is a fully async WordPress security scanner built with httpx + asyncio.

### New Features
- 15 detection modules: fingerprint, waf, plugins, themes, users, xmlrpc, rest_api, misconfigs, directory_listing, http_headers, ssl_tls, debug_exposure, content_analysis, auth, cves
- Async task scheduler with explicit dependency graph (maximum parallelism)
- Full Python library API: `from plecost import Scanner, ScanOptions`
- Stable finding IDs (PC-XXX-NNN) for dashboard integration
- Daily CVE database updates via GitHub Actions
- Rich terminal reporter with colored output and tables
- JSON reporter for automation pipelines
- Typer CLI with commands: scan, update-db, modules list, explain
- Docker support: `ghcr.io/cr0hn/plecost`
- Celery-compatible async scanner
- TDD: 62 tests across unit/integration/contract/property suites

### Architecture
- Python 3.11+, httpx, typer, rich, packaging, SQLite
- `pyproject.toml` with hatchling build backend
- Optional uvloop for better async performance

---

Version 1.1.2
=============

Improvements and fixes
----------------------

- Fixed issue: #18 (https://github.com/Plecost/plecost/issues/18)

New features
------------

- Added option to set custom hostname. Issue #20 (https://github.com/Plecost/plecost/issues/20)


Version 1.1.1
=============

Internal modifications
----------------------

- Improved CVE database. Now it implement full-text queries to locate plugins CVEs.
- Improved internal system that does the scan -> increased the performance
- Minor PEP8 improvements.
- Changed BeatufilSoup 4 HTML parser in favor of Lxml -> more fault tolerant & performance

Improvements and fixes
----------------------

- Fixed the plugin update system to the new Wordpress scaffolding.
- Fixed CVE update system. Now It tracks all CVEs until me updating moment.
- Performance improvements.
- Now Plecost runs on Python: 3.3, 3.4, 3.5 and 3.6
- Updated Wordpress plugin list
- Updated CVE database

New features
------------

- Added new system to detect remote wordpress version, based in version links of statics

Version 1.0.0
=============

Internal modifications
----------------------

- Code REWRITTEN in Python 3.
- Removed threads support in favor of asyncio connections.

Improvements and fixes
----------------------

- Improved (a lot) the performance, thanks to asyncio module.
- Improved vulnerability search for plugins.
- Improved verbosity feature, adding different verbosity levels, not only one.
- Fixed a lot of bugs.

New features
------------

- Added vulnerability search for wordpress version. Now Plecost indicated CVEs to installed wordpress.
- Added progress bars
- Automatic learning of site redirects and follow them.
- Possibility of install using pip
- Added command line option to consult plugins vulnerabilities and CVE database.
- Added CVE searcher for outdated wordpress versions.