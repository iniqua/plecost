#!/bin/sh
set -e

WP="wp --path=/var/www/html --allow-root"

echo ">>> Installing WordPress core..."
$WP core install \
  --url="http://localhost:8765" \
  --title="Damn Vulnerable WordPress" \
  --admin_user=admin \
  --admin_password=admin \
  --admin_email=admin@example.com \
  --skip-email

echo ">>> Creating additional users..."
$WP user create editor      editor@example.com      --role=editor     --user_pass=editor123
$WP user create author1     author1@example.com     --role=author     --user_pass=author123
$WP user create subscriber1 subscriber1@example.com --role=subscriber --user_pass=sub123

echo ">>> Preparing uploads directory..."
mkdir -p /var/www/html/wp-content/uploads
chmod 777 /var/www/html/wp-content/uploads

echo ">>> Installing vulnerable plugins (install phase)..."

# CVE-2020-24186 — unauthenticated RCE via file upload (CVSS 9.8)
$WP plugin install wpdiscuz --version=7.0.4

# CVE-2020-35489 — unrestricted file upload
$WP plugin install contact-form-7 --version=5.3.1

# CVE-2021-32790 and others
$WP plugin install woocommerce --version=5.0.0

# CVE-2021-34648 — unauthenticated email injection
$WP plugin install ninja-forms --version=3.4.34.2

# CVE-2020-11738 — unauthenticated path traversal
$WP plugin install duplicator --version=1.3.26

# CVE-2020-27615 — SQL injection
$WP plugin install loginizer --version=1.6.3

# CVE-2021-33203 — authenticated XSS
$WP plugin install wp-super-cache --version=1.7.1

# CVE-2022-1329 — authenticated RCE
$WP plugin install elementor --version=3.1.2

# CVE-2021-24875 — reflected XSS
$WP plugin install wordfence --version=7.5.0

echo ">>> Installing vulnerable e-commerce plugins..."

# CVE-2023-28121 — unauthenticated privilege escalation (CVSS 9.8), affects < 4.8.2
$WP plugin install woocommerce-payments --version=3.9.0

# CVE-2021-39351 — stored XSS, affects < 2.11.6
$WP plugin install easy-digital-downloads --version=2.11.5

# CVE-2021-34634 — SQL injection, affects < 2.10.4
$WP plugin install give --version=2.10.3

# CVE-2021-24987 — stored XSS, affects < 3.0.0
$WP plugin install yith-woocommerce-wishlist --version=2.2.9

# CVE-2019-15826 — order information disclosure, affects < 4.3.1
$WP plugin install woocommerce-gateway-stripe --version=4.3.0

echo ">>> Activating plugins (best-effort — some older versions may fail)..."

# wordfence needs wflogs dir to exist before activation (otherwise fatal error on fopen)
mkdir -p /var/www/html/wp-content/wflogs

# yith-woocommerce-wishlist 2.2.9 uses curly-brace array syntax removed in PHP 8.
# Activating it crashes WordPress for all subsequent commands — keep installed but inactive.
# wpdiscuz 7.0.4 activation hook denies access from CLI — keep installed but inactive.
# Remaining plugins are activated individually so one failure doesn't stop the rest.
for slug in contact-form-7 woocommerce ninja-forms duplicator loginizer \
            wp-super-cache elementor wordfence woocommerce-payments \
            easy-digital-downloads give woocommerce-gateway-stripe; do
    $WP plugin activate "$slug" || echo "WARNING: could not activate $slug (still installed and detectable)"
done
echo "NOTE: wpdiscuz and yith-woocommerce-wishlist are installed but not activated (PHP 8 incompatibility or CLI restriction). Plecost detects them via file headers regardless."

echo ">>> Installing vulnerable theme..."
# twentytwenty 1.6 — multiple minor vulnerabilities
$WP theme install twentytwenty --version=1.6 --activate

echo ">>> Setting up webshell test fixtures..."

# Override uploads .htaccess — WordPress normally denies PHP execution in uploads.
# We allow it here so the webshell detectors have something to find.
cat > /var/www/html/wp-content/uploads/.htaccess << 'HTEOF'
# DVWP: allow PHP execution in uploads for webshell detection testing
<Files *.php>
    Allow from all
    Satisfy Any
</Files>
HTEOF

# Create dated subdirectory for UploadsPhpDetector (year/month path probing)
YEAR=$(date +%Y)
mkdir -p "/var/www/html/wp-content/uploads/${YEAR}/04"

# Create mu-plugins directory (not present by default in WordPress)
mkdir -p /var/www/html/wp-content/mu-plugins

# ── Fixture: shell.php — triggers KnownPathsDetector (PC-WSH-001)
cat > /var/www/html/wp-content/uploads/shell.php << 'EOF'
<?php
// DVWP test fixture — generic shell name
echo "DVWP webshell fixture";
EOF

# ── Fixture: c99.php — triggers ResponseFingerprintDetector c99shell (PC-WSH-200)
cat > /var/www/html/wp-content/uploads/c99.php << 'EOF'
<?php
// DVWP test fixture — c99shell family fingerprint
echo "c99shell v1.0 test fixture";
EOF

# ── Fixture: wso.php — triggers ResponseFingerprintDetector wso_filesman (PC-WSH-200)
cat > /var/www/html/wp-content/uploads/wso.php << 'EOF'
<?php
// DVWP test fixture — WSO/FilesMan family fingerprint
echo '<form method="post">';
echo '<input type="hidden" name="a" value="">';
echo '<input type="hidden" name="c" value="">';
echo '<input type="hidden" name="charset" value="UTF-8">';
echo '</form>';
EOF

# ── Fixture: 1.php — triggers ResponseFingerprintDetector china_chopper (PC-WSH-200)
# PHP outputs 0 bytes (no echo) — matches china_chopper empty-body fingerprint
cat > /var/www/html/wp-content/uploads/1.php << 'EOF'
<?php
// DVWP test fixture — china_chopper fingerprint (empty response body)
EOF

# ── Fixture: image.php in dated subdir — triggers UploadsPhpDetector (PC-WSH-100)
cat > "/var/www/html/wp-content/uploads/${YEAR}/04/image.php" << 'EOF'
<?php
// DVWP test fixture — PHP in dated uploads subdirectory
echo "DVWP uploads subdir fixture";
EOF

# ── Fixture: cache.php in mu-plugins — triggers MuPluginsDetector (PC-WSH-150)
cat > /var/www/html/wp-content/mu-plugins/cache.php << 'EOF'
<?php
// DVWP test fixture — mu-plugins backdoor simulation
// Must-Use plugins load on every request and are hidden from admin panel
echo "DVWP mu-plugins fixture";
EOF

echo ""
echo "========================================"
echo " DVWP ready at http://localhost:8765"
echo " Admin: admin / admin"
echo "========================================"
echo ""
echo "Installed plugins:"
$WP plugin list --format=table
