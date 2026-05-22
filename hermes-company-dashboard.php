<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    header('Location: /login/');
    exit;
}

if (empty($_SESSION['hermes_auth']) || empty($_SESSION['hermes_user'])) {
    header('Location: /login/');
    exit;
}

$role = strtolower(trim((string)($_SESSION['hermes_role'] ?? '')));
if (!in_array($role, ['company_owner', 'company_admin', 'company_user'], true)) {
    header('Location: /login/');
    exit;
}

$module = (string)($_GET['module'] ?? 'dashboard');
if (!in_array($module, ['dashboard', 'empresa', 'clientes', 'cotizaciones'], true)) {
    $module = 'dashboard';
}

function h($value)
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function ensure_column(PDO $pdo, $table, $column, $definition)
{
    $st = $pdo->prepare(
        'SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c LIMIT 1'
    );
    $st->execute(['t' => $table, 'c' => $column]);
    if (!$st->fetchColumn()) {
        $pdo->exec('ALTER TABLE `' . $table . '` ADD COLUMN `' . $column . '` ' . $definition);
    }
}

function column_exists(PDO $pdo, $table, $column)
{
    $st = $pdo->prepare(
        'SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c LIMIT 1'
    );
    $st->execute(['t' => $table, 'c' => $column]);
    return (bool)$st->fetchColumn();
}

function normalize_slug($value)
{
    $slug = strtolower(trim((string)$value));
    $slug = preg_replace('/[^a-z0-9]+/', '-', $slug);
    $slug = trim((string)$slug, '-');
    if ($slug === '') {
        $slug = 'empresa';
    }
    return substr($slug, 0, 90);
}

function uploads_root_dir($create = false)
{
    $root = __DIR__ . DIRECTORY_SEPARATOR . 'uploads';
    if ($create && !is_dir($root) && !mkdir($root, 0775, true) && !is_dir($root)) {
        throw new RuntimeException('No se pudo crear el directorio uploads.');
    }
    return $root;
}

function logo_relative_dir($tenantCompanyId)
{
    return 'empresa_logos/' . (int)$tenantCompanyId;
}

function logo_absolute_dir($tenantCompanyId, $create = false)
{
    $root = uploads_root_dir($create);
    $dir = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, logo_relative_dir((int)$tenantCompanyId));
    if ($create && !is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
        throw new RuntimeException('No se pudo crear directorio de logos.');
    }
    return $dir;
}

function logo_ext_from_mime($mime)
{
    $map = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
    ];
    return $map[$mime] ?? null;
}

function store_logo($file, $tenantCompanyId)
{
    $error = (int)($file['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($error !== UPLOAD_ERR_OK) {
        throw new RuntimeException('Selecciona un logo valido para subir.');
    }

    $tmp = (string)($file['tmp_name'] ?? '');
    if ($tmp === '' || !is_uploaded_file($tmp)) {
        throw new RuntimeException('No se pudo leer el archivo temporal.');
    }

    $size = (int)($file['size'] ?? 0);
    if ($size <= 0 || $size > 4 * 1024 * 1024) {
        throw new RuntimeException('El logo debe pesar maximo 4MB.');
    }

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = (string)$finfo->file($tmp);
    $ext = logo_ext_from_mime($mime);
    if ($ext === null) {
        throw new RuntimeException('Formato no permitido. Usa JPG, PNG o WEBP.');
    }

    $dir = logo_absolute_dir((int)$tenantCompanyId, true);
    $name = 'empresa_' . (int)$tenantCompanyId . '_logo_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
    $path = $dir . DIRECTORY_SEPARATOR . $name;

    if (!move_uploaded_file($tmp, $path)) {
        throw new RuntimeException('No se pudo guardar el logo subido.');
    }

    return logo_relative_dir((int)$tenantCompanyId) . '/' . $name;
}

function delete_logo_if_exists($relativePath)
{
    $rel = trim((string)$relativePath);
    if ($rel === '') {
        return;
    }

    $root = rtrim(str_replace('\\', '/', uploads_root_dir(false)), '/');
    $abs = $root . '/' . ltrim(str_replace('\\', '/', $rel), '/');
    if (!str_starts_with($abs, $root . '/')) {
        return;
    }
    if (is_file($abs)) {
        @unlink($abs);
    }
}

function logo_public_url($relativePath)
{
    $rel = trim((string)$relativePath);
    if ($rel === '') {
        return '';
    }
    $rel = preg_replace('#/+#', '/', str_replace('\\', '/', $rel));
    $rel = ltrim((string)$rel, '/');
    if (str_starts_with($rel, 'uploads/')) {
        $rel = substr($rel, 8);
    }
    if ($rel === '') {
        return '';
    }
    $parts = array_map(static fn($p) => rawurlencode($p), explode('/', $rel));
    return '/uploads/' . implode('/', $parts);
}

  function dashboard_module_url($module)
  {
    $safe = in_array($module, ['dashboard', 'empresa', 'clientes', 'cotizaciones'], true) ? $module : 'dashboard';
    return '/empresa/dashboard/?module=' . rawurlencode($safe);
  }

  function money_clp($value)
  {
    return number_format((float)$value, 0, ',', '.');
  }

  function billing_cycle_days($billingCycle)
  {
    $code = strtolower(trim((string)$billingCycle));
    if ($code === 'annual' || $code === 'anual') {
      return 365;
    }
    return 30;
  }

  function quote_money_breakdown($subtotal, $descuentoPct)
  {
    $subtotal = max(0, (float)$subtotal);
    $descuentoPct = max(0, min(100, (float)$descuentoPct));
    $descuentoMonto = round($subtotal * ($descuentoPct / 100), 2);
    $neto = round($subtotal - $descuentoMonto, 2);
    $ivaMonto = round($neto * 0.19, 2);
    $total = round($neto + $ivaMonto, 2);

    return [
      'subtotal' => $subtotal,
      'descuento_pct' => $descuentoPct,
      'descuento_monto' => $descuentoMonto,
      'neto' => $neto,
      'iva_monto' => $ivaMonto,
      'total' => $total,
    ];
  }

  function quote_statuses()
  {
    return [
      'Pendiente',
      'Aceptada',
      'Pendiente OC',
      'OC Recepcionada',
      'Facturada',
      'Pagada',
      'Rechazada',
    ];
  }

  function next_quote_number(PDO $pdo, $tenantCompanyId)
  {
    $prefix = 'COT-' . date('Y') . '-';
    $st = $pdo->prepare(
      'SELECT numero_cotizacion
       FROM tenant_quotes
       WHERE tenant_company_id = :tenant_company_id
         AND numero_cotizacion LIKE :prefix
       ORDER BY id DESC
       LIMIT 1'
    );
    $st->execute([
      'tenant_company_id' => (int)$tenantCompanyId,
      'prefix' => $prefix . '%',
    ]);
    $last = (string)$st->fetchColumn();
    $n = 1;
    if (preg_match('/^(?:COT-\d{4}-)(\d{4,})$/', $last, $m)) {
      $n = ((int)$m[1]) + 1;
    }
    return $prefix . str_pad((string)$n, 4, '0', STR_PAD_LEFT);
  }

$flash = ['ok' => '', 'error' => ''];
$accountLoginEmail = (string)($_SESSION['hermes_user'] ?? '');
$companyName = (string)($_SESSION['hermes_company_name'] ?? 'Empresa');
$companyEmail = (string)($_SESSION['hermes_company_email'] ?? $accountLoginEmail);
$signupId = (int)($_SESSION['hermes_company_id'] ?? 0);
$tenantCompanyId = 0;

$profile = [
    'nombre' => $companyName,
    'rut' => '',
    'direccion' => '',
    'telefono' => '',
    'celular' => '',
    'email_principal' => $companyEmail,
    'condicion_de_pago' => '',
    'entrega' => '',
    'validez' => '',
    'moneda' => 'CLP',
    'sitio_web' => '',
    'contacto_principal_nombre' => '',
    'contacto_principal_cargo' => '',
    'notas_internas' => '',
    'logo_filename' => '',
];

$usage = [
    'plan_code' => 'basico',
    'storage_limit_mb' => 1024,
    'storage_used_mb' => 0,
    'percent' => 0,
];

$customers = [];
$quotes = [];
$quoteItemsByQuote = [];
$quotePreview = null;
$quotePreviewItems = [];
$logoPublicUrl = '';
$dashStatusCatalog = [];
$dashStatusTotals = [];
$dashTotalQuotes = 0;
$dashTotalAmount = 0.0;
$dashAcceptedCount = 0;
$dashAcceptedAmount = 0.0;
$dashPendingAmount = 0.0;
$dashRejectedAmount = 0.0;
$dashConversionRate = 0;
$dashMaxStatusAmount = 0.0;
$dashTopClients = [];
$dashMaxClientAmount = 0.0;
$dashRecentQuotes = [];
$dashCustomersTotal = 0;
$dashCurrencyCode = 'CLP';
$planBilling = [
  'payment_status' => 'unpaid',
  'plan_status' => 'pending_payment',
  'billing_cycle' => 'monthly',
  'billing_cycle_name' => 'Mensual',
  'is_enabled' => 0,
  'days_left' => null,
  'next_renewal_label' => 'Pendiente',
  'notice_tone' => 'warn',
  'notice_title' => 'Pago pendiente',
  'notice_text' => 'Tu plan aun no registra pago activo. Regulariza para mantener el acceso operativo.',
  'payment_url' => '',
  'can_pay_renewal' => false,
];
$openCustomerModal = false;
$openQuoteModal = false;
$customerForm = [
  'id' => '',
  'rut' => '',
  'razon_social' => '',
  'nombre_fantasia' => '',
  'direccion' => '',
  'comuna' => '',
  'ciudad' => '',
  'telefono' => '',
  'celular' => '',
  'email' => '',
  'contacto' => '',
  'notas_internas' => '',
];
$quoteForm = [
  'id' => '',
    'customer_id' => '',
    'numero_cotizacion' => '',
    'fecha_emision' => date('Y-m-d'),
    'validez_dias' => '15',
  'estado' => 'Pendiente',
    'descuento_pct' => '0',
  'terminos_condiciones_adicionales' => '',
    'observaciones' => '',
    'items' => [
        ['descripcion' => '', 'cantidad' => '1', 'precio' => '0'],
    ],
];

  if ($_SERVER['REQUEST_METHOD'] !== 'POST' && isset($_SESSION['hermes_company_postback']) && is_array($_SESSION['hermes_company_postback'])) {
    $postback = $_SESSION['hermes_company_postback'];
    unset($_SESSION['hermes_company_postback']);

    if (isset($postback['module']) && in_array((string)$postback['module'], ['dashboard', 'empresa', 'clientes', 'cotizaciones'], true)) {
      $module = (string)$postback['module'];
    }
    if (isset($postback['flash']) && is_array($postback['flash'])) {
      $flash['ok'] = (string)($postback['flash']['ok'] ?? '');
      $flash['error'] = (string)($postback['flash']['error'] ?? '');
    }
    $openCustomerModal = !empty($postback['openCustomerModal']);
    $openQuoteModal = !empty($postback['openQuoteModal']);

    if (isset($postback['customerForm']) && is_array($postback['customerForm'])) {
      $customerForm = array_merge($customerForm, $postback['customerForm']);
    }
    if (isset($postback['quoteForm']) && is_array($postback['quoteForm'])) {
      $quoteForm = array_merge($quoteForm, $postback['quoteForm']);
      if (isset($postback['quoteForm']['items']) && is_array($postback['quoteForm']['items'])) {
        $quoteForm['items'] = $postback['quoteForm']['items'];
      }
    }
  }

try {
    $cfg = require __DIR__ . '/.db_credentials.php';
    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $cfg['host'], (int)$cfg['port'], $cfg['dbname'], $cfg['charset']);
    $pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    $pdo->exec('CREATE TABLE IF NOT EXISTS account_signups (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(190) NOT NULL,
        company_name VARCHAR(190) NOT NULL,
        contact_name VARCHAR(190) NOT NULL,
        phone VARCHAR(40) NULL,
        password_hash VARCHAR(255) NOT NULL,
        status VARCHAR(40) NOT NULL DEFAULT "pending_email_verification",
        email_verified_at DATETIME NULL,
        payment_status VARCHAR(20) NOT NULL DEFAULT "unpaid",
        plan_code VARCHAR(40) NOT NULL DEFAULT "basico",
        billing_cycle VARCHAR(20) NOT NULL DEFAULT "monthly",
        tenant_company_id BIGINT UNSIGNED NULL,
        activated_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_account_signups_email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS tenant_companies (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        signup_id BIGINT UNSIGNED NULL,
        company_name VARCHAR(190) NOT NULL,
        company_slug VARCHAR(90) NOT NULL,
        owner_email VARCHAR(190) NOT NULL,
        contact_name VARCHAR(190) NULL,
        phone VARCHAR(40) NULL,
        plan_code VARCHAR(40) NOT NULL DEFAULT "basico",
        billing_cycle VARCHAR(20) NOT NULL DEFAULT "monthly",
        plan_status VARCHAR(40) NOT NULL DEFAULT "pending_payment",
        is_enabled TINYINT(1) NOT NULL DEFAULT 0,
        status VARCHAR(40) NOT NULL DEFAULT "pending_payment",
        created_by VARCHAR(190) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_tenant_companies_slug (company_slug),
        UNIQUE KEY uq_tenant_companies_email (owner_email),
        KEY idx_tenant_companies_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');

    if (column_exists($pdo, 'tenant_companies', 'business_email') && column_exists($pdo, 'tenant_companies', 'owner_email')) {
        try {
            $pdo->exec('ALTER TABLE tenant_companies MODIFY business_email VARCHAR(190) NULL');
        } catch (Throwable $ignored) {
        }
        $pdo->exec('UPDATE tenant_companies SET business_email = owner_email WHERE (business_email IS NULL OR business_email = "") AND owner_email IS NOT NULL AND owner_email <> ""');
    }

    $pdo->exec('CREATE TABLE IF NOT EXISTS tenant_company_profiles (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        tenant_company_id BIGINT UNSIGNED NOT NULL,
        nombre VARCHAR(150) NOT NULL,
        rut VARCHAR(30) NOT NULL,
        direccion VARCHAR(255) NOT NULL,
        telefono VARCHAR(50) NULL,
        celular VARCHAR(50) NULL,
        email_principal VARCHAR(150) NOT NULL,
        condicion_de_pago TEXT NULL,
        entrega TEXT NULL,
        validez TEXT NULL,
        moneda VARCHAR(10) NOT NULL DEFAULT "CLP",
        sitio_web VARCHAR(180) NULL,
        contacto_principal_nombre VARCHAR(120) NULL,
        contacto_principal_cargo VARCHAR(120) NULL,
        notas_internas TEXT NULL,
        logo_filename VARCHAR(255) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_tenant_profile_company (tenant_company_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');

    ensure_column($pdo, 'tenant_company_profiles', 'tenant_company_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'nombre', 'VARCHAR(150) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_company_profiles', 'rut', 'VARCHAR(30) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_company_profiles', 'direccion', 'VARCHAR(255) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_company_profiles', 'telefono', 'VARCHAR(50) NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'celular', 'VARCHAR(50) NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'email_principal', 'VARCHAR(150) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_company_profiles', 'condicion_de_pago', 'TEXT NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'entrega', 'TEXT NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'validez', 'TEXT NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'moneda', 'VARCHAR(10) NOT NULL DEFAULT "CLP"');
    ensure_column($pdo, 'tenant_company_profiles', 'sitio_web', 'VARCHAR(180) NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'contacto_principal_nombre', 'VARCHAR(120) NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'contacto_principal_cargo', 'VARCHAR(120) NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'notas_internas', 'TEXT NULL');
    ensure_column($pdo, 'tenant_company_profiles', 'logo_filename', 'VARCHAR(255) NULL');

    $pdo->exec('CREATE TABLE IF NOT EXISTS tenant_customers (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        tenant_company_id BIGINT UNSIGNED NOT NULL,
        rut VARCHAR(30) NOT NULL,
        razon_social VARCHAR(180) NOT NULL,
        nombre_fantasia VARCHAR(180) NULL,
        direccion VARCHAR(255) NOT NULL,
        comuna VARCHAR(120) NULL,
        ciudad VARCHAR(120) NULL,
        telefono VARCHAR(50) NULL,
        celular VARCHAR(50) NULL,
        email VARCHAR(150) NULL,
        contacto VARCHAR(150) NULL,
        notas_internas TEXT NULL,
        estado TINYINT(1) NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_customers_company_rut (tenant_company_id, rut)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');

    ensure_column($pdo, 'tenant_customers', 'tenant_company_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column($pdo, 'tenant_customers', 'rut', 'VARCHAR(30) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_customers', 'razon_social', 'VARCHAR(180) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_customers', 'nombre_fantasia', 'VARCHAR(180) NULL');
    ensure_column($pdo, 'tenant_customers', 'direccion', 'VARCHAR(255) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_customers', 'comuna', 'VARCHAR(120) NULL');
    ensure_column($pdo, 'tenant_customers', 'ciudad', 'VARCHAR(120) NULL');
    ensure_column($pdo, 'tenant_customers', 'telefono', 'VARCHAR(50) NULL');
    ensure_column($pdo, 'tenant_customers', 'celular', 'VARCHAR(50) NULL');
    ensure_column($pdo, 'tenant_customers', 'email', 'VARCHAR(150) NULL');
    ensure_column($pdo, 'tenant_customers', 'contacto', 'VARCHAR(150) NULL');
    ensure_column($pdo, 'tenant_customers', 'notas_internas', 'TEXT NULL');
    ensure_column($pdo, 'tenant_customers', 'estado', 'TINYINT(1) NOT NULL DEFAULT 1');

    $pdo->exec('CREATE TABLE IF NOT EXISTS tenant_quotes (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      tenant_company_id BIGINT UNSIGNED NOT NULL,
      customer_id BIGINT UNSIGNED NOT NULL,
      numero_cotizacion VARCHAR(80) NOT NULL,
      fecha_emision DATE NOT NULL,
      validez_dias INT UNSIGNED NOT NULL DEFAULT 15,
      descuento_pct DECIMAL(5,2) NOT NULL DEFAULT 0,
      subtotal DECIMAL(14,2) NOT NULL DEFAULT 0,
      total DECIMAL(14,2) NOT NULL DEFAULT 0,
      estado VARCHAR(40) NOT NULL DEFAULT "Pendiente",
      terminos_condiciones_adicionales TEXT NULL,
      observaciones TEXT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uq_tenant_quotes_numero (tenant_company_id, numero_cotizacion),
      KEY idx_tenant_quotes_customer (tenant_company_id, customer_id),
      KEY idx_tenant_quotes_estado (tenant_company_id, estado)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');

    ensure_column($pdo, 'tenant_quotes', 'tenant_company_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column($pdo, 'tenant_quotes', 'customer_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column($pdo, 'tenant_quotes', 'numero_cotizacion', 'VARCHAR(80) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_quotes', 'fecha_emision', 'DATE NULL');
    ensure_column($pdo, 'tenant_quotes', 'validez_dias', 'INT UNSIGNED NOT NULL DEFAULT 15');
    ensure_column($pdo, 'tenant_quotes', 'descuento_pct', 'DECIMAL(5,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_quotes', 'subtotal', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_quotes', 'total', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_quotes', 'estado', 'VARCHAR(40) NOT NULL DEFAULT "Pendiente"');
    ensure_column($pdo, 'tenant_quotes', 'terminos_condiciones_adicionales', 'TEXT NULL');
    ensure_column($pdo, 'tenant_quotes', 'observaciones', 'TEXT NULL');

    $pdo->exec('CREATE TABLE IF NOT EXISTS tenant_quote_items (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      tenant_quote_id BIGINT UNSIGNED NOT NULL,
      orden INT UNSIGNED NOT NULL DEFAULT 1,
      descripcion VARCHAR(255) NOT NULL,
      cantidad DECIMAL(14,2) NOT NULL DEFAULT 1,
      precio_unitario DECIMAL(14,2) NOT NULL DEFAULT 0,
      total_linea DECIMAL(14,2) NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      KEY idx_tenant_quote_items_quote (tenant_quote_id, orden)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');

    ensure_column($pdo, 'tenant_quote_items', 'tenant_quote_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column($pdo, 'tenant_quote_items', 'orden', 'INT UNSIGNED NOT NULL DEFAULT 1');
    ensure_column($pdo, 'tenant_quote_items', 'descripcion', 'VARCHAR(255) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_quote_items', 'cantidad', 'DECIMAL(14,2) NOT NULL DEFAULT 1');
    ensure_column($pdo, 'tenant_quote_items', 'precio_unitario', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_quote_items', 'total_linea', 'DECIMAL(14,2) NOT NULL DEFAULT 0');

    $pdo->exec('CREATE TABLE IF NOT EXISTS tenant_plan_usage (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        tenant_company_id BIGINT UNSIGNED NOT NULL,
        plan_code VARCHAR(40) NOT NULL DEFAULT "basico",
        storage_limit_mb INT UNSIGNED NOT NULL DEFAULT 1024,
        storage_used_mb INT UNSIGNED NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_usage_company (tenant_company_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');

      ensure_column($pdo, 'account_signups', 'billing_cycle', 'VARCHAR(20) NOT NULL DEFAULT "monthly"');
      ensure_column($pdo, 'tenant_companies', 'billing_cycle', 'VARCHAR(20) NOT NULL DEFAULT "monthly"');

    if ($signupId > 0) {
        $stSignup = $pdo->prepare('SELECT id, company_name, email, tenant_company_id, payment_status, plan_code, billing_cycle, activated_at, created_at, payment_access_token, payment_access_expires_at FROM account_signups WHERE id = :id LIMIT 1');
        $stSignup->execute(['id' => $signupId]);
        $signup = $stSignup->fetch();
        if ($signup) {
            $companyName = (string)($signup['company_name'] ?? $companyName);
        $accountLoginEmail = (string)($signup['email'] ?? $accountLoginEmail);
        if ($companyEmail === '') {
          $companyEmail = $accountLoginEmail;
        }
            $tenantCompanyId = (int)($signup['tenant_company_id'] ?? 0);
            $planBilling['payment_status'] = strtolower(trim((string)($signup['payment_status'] ?? 'unpaid')));
            $planCodeFromSignup = (string)($signup['plan_code'] ?? 'basico');
            $billingCycleFromSignup = strtolower(trim((string)($signup['billing_cycle'] ?? 'monthly')));
            if (!in_array($billingCycleFromSignup, ['monthly', 'annual'], true)) {
              $billingCycleFromSignup = 'monthly';
            }
            $planBilling['billing_cycle'] = $billingCycleFromSignup;
            $planBilling['billing_cycle_name'] = ($billingCycleFromSignup === 'annual') ? 'Anual' : 'Mensual';
            if ($planCodeFromSignup !== '') {
              $usage['plan_code'] = $planCodeFromSignup;
            }

            $token = trim((string)($signup['payment_access_token'] ?? ''));
            $expiresTs = strtotime((string)($signup['payment_access_expires_at'] ?? ''));
            if ($token !== '' && $expiresTs !== false && $expiresTs > time()) {
              $planBilling['payment_url'] = '/pagar-plan/?pt=' . rawurlencode($token);
              $planBilling['can_pay_renewal'] = true;
            }

            $cycleDays = billing_cycle_days($planBilling['billing_cycle']);
            $referenceAt = trim((string)($signup['activated_at'] ?? ''));
            if ($referenceAt === '') {
              $referenceAt = trim((string)($signup['created_at'] ?? ''));
            }
            $referenceTs = strtotime($referenceAt);
            if ($referenceTs !== false) {
              $nextRenewalTs = strtotime('+' . $cycleDays . ' days', $referenceTs);
              if ($nextRenewalTs !== false) {
                $planBilling['days_left'] = (int)ceil(($nextRenewalTs - time()) / 86400);
                $planBilling['next_renewal_label'] = date('d/m/Y', $nextRenewalTs);
              }
            }
        }
    }

    if ($tenantCompanyId <= 0 && $signupId > 0) {
        $stTenant = $pdo->prepare('SELECT id, plan_status, is_enabled, plan_code, billing_cycle FROM tenant_companies WHERE signup_id = :signup_id LIMIT 1');
        $stTenant->execute(['signup_id' => $signupId]);
        $row = $stTenant->fetch();
        if ($row) {
            $tenantCompanyId = (int)$row['id'];
            $planBilling['plan_status'] = strtolower(trim((string)($row['plan_status'] ?? 'pending_payment')));
            $planBilling['is_enabled'] = (int)($row['is_enabled'] ?? 0);
            $tenantBillingCycle = strtolower(trim((string)($row['billing_cycle'] ?? 'monthly')));
            if (!in_array($tenantBillingCycle, ['monthly', 'annual'], true)) {
              $tenantBillingCycle = 'monthly';
            }
            $planBilling['billing_cycle'] = $tenantBillingCycle;
            $planBilling['billing_cycle_name'] = ($tenantBillingCycle === 'annual') ? 'Anual' : 'Mensual';
            if (!empty($row['plan_code'])) {
              $usage['plan_code'] = (string)$row['plan_code'];
            }
        }
    }

    if ($tenantCompanyId <= 0 && $accountLoginEmail !== '') {
        $stTenant = $pdo->prepare('SELECT id, plan_status, is_enabled, plan_code, billing_cycle FROM tenant_companies WHERE owner_email = :owner_email LIMIT 1');
      $stTenant->execute(['owner_email' => $accountLoginEmail]);
        $row = $stTenant->fetch();
        if ($row) {
            $tenantCompanyId = (int)$row['id'];
            $planBilling['plan_status'] = strtolower(trim((string)($row['plan_status'] ?? 'pending_payment')));
            $planBilling['is_enabled'] = (int)($row['is_enabled'] ?? 0);
            $tenantBillingCycle = strtolower(trim((string)($row['billing_cycle'] ?? 'monthly')));
            if (!in_array($tenantBillingCycle, ['monthly', 'annual'], true)) {
              $tenantBillingCycle = 'monthly';
            }
            $planBilling['billing_cycle'] = $tenantBillingCycle;
            $planBilling['billing_cycle_name'] = ($tenantBillingCycle === 'annual') ? 'Anual' : 'Mensual';
            if (!empty($row['plan_code'])) {
              $usage['plan_code'] = (string)$row['plan_code'];
            }
        }
    }

    if ($tenantCompanyId <= 0) {
        $slugBase = normalize_slug($companyName);
        $slug = $slugBase;
        $n = 1;
        while (true) {
            $stSlug = $pdo->prepare('SELECT id FROM tenant_companies WHERE company_slug = :slug LIMIT 1');
            $stSlug->execute(['slug' => $slug]);
            if (!$stSlug->fetch()) {
                break;
            }
            $n++;
            $slug = substr($slugBase, 0, 75) . '-' . $n;
        }

        $columns = 'signup_id, company_name, company_slug, owner_email, contact_name, phone, plan_code, billing_cycle, plan_status, is_enabled, status, created_by';
        $values = ':signup_id, :company_name, :company_slug, :owner_email, :contact_name, :phone, :plan_code, :billing_cycle, :plan_status, :is_enabled, :status, :created_by';
        $params = [
            'signup_id' => ($signupId > 0 ? $signupId : null),
            'company_name' => $companyName,
            'company_slug' => $slug,
            'owner_email' => ($accountLoginEmail !== '' ? $accountLoginEmail : $companyEmail),
            'contact_name' => null,
            'phone' => null,
            'plan_code' => 'basico',
          'billing_cycle' => 'monthly',
            'plan_status' => 'paid',
            'is_enabled' => 1,
            'status' => 'active',
            'created_by' => 'company_dashboard_bootstrap',
        ];
        if (column_exists($pdo, 'tenant_companies', 'business_email')) {
            $columns .= ', business_email';
            $values .= ', :business_email';
          $params['business_email'] = ($accountLoginEmail !== '' ? $accountLoginEmail : $companyEmail);
        }

        $insTenant = $pdo->prepare('INSERT INTO tenant_companies (' . $columns . ') VALUES (' . $values . ')');
        $insTenant->execute($params);
        $tenantCompanyId = (int)$pdo->lastInsertId();

        if ($signupId > 0) {
            $upSignup = $pdo->prepare('UPDATE account_signups SET tenant_company_id = :tenant_company_id WHERE id = :id');
            $upSignup->execute(['tenant_company_id' => $tenantCompanyId, 'id' => $signupId]);
        }
    }

      $quoteForm['numero_cotizacion'] = next_quote_number($pdo, $tenantCompanyId);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = (string)($_POST['action'] ?? '');

        if ($action === 'save_company_logo') {
            try {
                if (!isset($_FILES['logo'])) {
                    throw new RuntimeException('Debes seleccionar un logo para subir.');
                }
                $stCurrentLogo = $pdo->prepare('SELECT logo_filename FROM tenant_company_profiles WHERE tenant_company_id = :tenant_company_id LIMIT 1');
                $stCurrentLogo->execute(['tenant_company_id' => $tenantCompanyId]);
                $currentLogoRow = $stCurrentLogo->fetch();
                $currentLogo = (string)($currentLogoRow['logo_filename'] ?? '');

                $newLogo = store_logo($_FILES['logo'], $tenantCompanyId);

                if ($currentLogoRow) {
                    $upLogo = $pdo->prepare('UPDATE tenant_company_profiles SET logo_filename = :logo_filename WHERE tenant_company_id = :tenant_company_id');
                    $upLogo->execute(['logo_filename' => $newLogo, 'tenant_company_id' => $tenantCompanyId]);
                } else {
                    $insLogo = $pdo->prepare(
                        'INSERT INTO tenant_company_profiles (tenant_company_id, nombre, rut, direccion, email_principal, moneda, logo_filename)
                         VALUES (:tenant_company_id, :nombre, :rut, :direccion, :email_principal, :moneda, :logo_filename)'
                    );
                    $insLogo->execute([
                        'tenant_company_id' => $tenantCompanyId,
                        'nombre' => ($companyName !== '' ? $companyName : 'Empresa'),
                        'rut' => 'PENDIENTE',
                        'direccion' => 'PENDIENTE',
                        'email_principal' => ($companyEmail !== '' ? $companyEmail : 'empresa@local.invalid'),
                        'moneda' => 'CLP',
                        'logo_filename' => $newLogo,
                    ]);
                }

                if ($currentLogo !== '' && $currentLogo !== $newLogo) {
                    delete_logo_if_exists($currentLogo);
                }
                $flash['ok'] = 'Logo de empresa actualizado correctamente.';
            } catch (Throwable $e) {
                $flash['error'] = $e instanceof RuntimeException ? $e->getMessage() : 'No se pudo subir el logo.';
            }
            $module = 'empresa';
        }

        if ($action === 'save_company_profile') {
            $profileInput = [
                'nombre' => trim((string)($_POST['nombre'] ?? '')),
                'rut' => strtoupper(trim((string)($_POST['rut'] ?? ''))),
                'direccion' => trim((string)($_POST['direccion'] ?? '')),
                'telefono' => trim((string)($_POST['telefono'] ?? '')),
                'celular' => trim((string)($_POST['celular'] ?? '')),
                'email_principal' => trim((string)($_POST['email_principal'] ?? '')),
                'condicion_de_pago' => trim((string)($_POST['condicion_de_pago'] ?? '')),
                'entrega' => trim((string)($_POST['entrega'] ?? '')),
                'validez' => trim((string)($_POST['validez'] ?? '')),
                'moneda' => strtoupper(trim((string)($_POST['moneda'] ?? 'CLP'))),
                'sitio_web' => trim((string)($_POST['sitio_web'] ?? '')),
                'contacto_principal_nombre' => trim((string)($_POST['contacto_principal_nombre'] ?? '')),
                'contacto_principal_cargo' => trim((string)($_POST['contacto_principal_cargo'] ?? '')),
                'notas_internas' => trim((string)($_POST['notas_internas'] ?? '')),
            ];

            if ($profileInput['nombre'] === '' || $profileInput['rut'] === '' || $profileInput['direccion'] === '' || $profileInput['email_principal'] === '') {
                $flash['error'] = 'Completa nombre, RUT, direccion y email principal.';
            } elseif (!filter_var($profileInput['email_principal'], FILTER_VALIDATE_EMAIL)) {
                $flash['error'] = 'El email principal no es valido.';
            } else {
                $upProfile = $pdo->prepare(
                    'INSERT INTO tenant_company_profiles (
                        tenant_company_id, nombre, rut, direccion, telefono, celular,
                        email_principal, condicion_de_pago, entrega, validez, moneda,
                        sitio_web, contacto_principal_nombre, contacto_principal_cargo, notas_internas
                     ) VALUES (
                        :tenant_company_id, :nombre, :rut, :direccion, :telefono, :celular,
                        :email_principal, :condicion_de_pago, :entrega, :validez, :moneda,
                        :sitio_web, :contacto_principal_nombre, :contacto_principal_cargo, :notas_internas
                     )
                     ON DUPLICATE KEY UPDATE
                        nombre = VALUES(nombre),
                        rut = VALUES(rut),
                        direccion = VALUES(direccion),
                        telefono = VALUES(telefono),
                        celular = VALUES(celular),
                        email_principal = VALUES(email_principal),
                        condicion_de_pago = VALUES(condicion_de_pago),
                        entrega = VALUES(entrega),
                        validez = VALUES(validez),
                        moneda = VALUES(moneda),
                        sitio_web = VALUES(sitio_web),
                        contacto_principal_nombre = VALUES(contacto_principal_nombre),
                        contacto_principal_cargo = VALUES(contacto_principal_cargo),
                        notas_internas = VALUES(notas_internas)'
                );
                $upProfile->execute(array_merge(['tenant_company_id' => $tenantCompanyId], $profileInput));

                $upTenant = $pdo->prepare('UPDATE tenant_companies SET company_name = :company_name, owner_email = :owner_email WHERE id = :id');
                $upTenant->execute([
                    'company_name' => $profileInput['nombre'],
                  'owner_email' => ($accountLoginEmail !== '' ? $accountLoginEmail : $companyEmail),
                    'id' => $tenantCompanyId,
                ]);
                if (column_exists($pdo, 'tenant_companies', 'business_email')) {
                    $upBiz = $pdo->prepare('UPDATE tenant_companies SET business_email = :business_email WHERE id = :id');
                  $upBiz->execute(['business_email' => ($accountLoginEmail !== '' ? $accountLoginEmail : $companyEmail), 'id' => $tenantCompanyId]);
                }

                $companyName = $profileInput['nombre'];
                $companyEmail = $profileInput['email_principal'];
                $_SESSION['hermes_company_name'] = $companyName;
                $_SESSION['hermes_company_email'] = $companyEmail;
                $flash['ok'] = 'Datos de empresa guardados correctamente.';
                $module = 'empresa';
            }
        }

        if ($action === 'add_customer' || $action === 'update_customer') {
          $isEditCustomer = $action === 'update_customer';
          $customerId = (int)($_POST['customer_id'] ?? 0);
          $customerInput = [
                'rut' => strtoupper(trim((string)($_POST['rut'] ?? ''))),
                'razon_social' => trim((string)($_POST['razon_social'] ?? '')),
                'nombre_fantasia' => trim((string)($_POST['nombre_fantasia'] ?? '')),
                'direccion' => trim((string)($_POST['direccion'] ?? '')),
                'comuna' => trim((string)($_POST['comuna'] ?? '')),
                'ciudad' => trim((string)($_POST['ciudad'] ?? '')),
                'telefono' => trim((string)($_POST['telefono'] ?? '')),
                'celular' => trim((string)($_POST['celular'] ?? '')),
                'email' => trim((string)($_POST['email'] ?? '')),
                'contacto' => trim((string)($_POST['contacto'] ?? '')),
                'notas_internas' => trim((string)($_POST['notas_internas'] ?? '')),
            ];
              $customerForm = array_merge(['id' => (string)$customerId], $customerInput);

            if ($customerInput['rut'] === '' || $customerInput['razon_social'] === '' || $customerInput['direccion'] === '') {
              $flash['error'] = 'Para guardar cliente completa RUT, razon social y direccion.';
                $openCustomerModal = true;
            } elseif ($customerInput['email'] !== '' && !filter_var($customerInput['email'], FILTER_VALIDATE_EMAIL)) {
                $flash['error'] = 'El email del cliente no es valido.';
                $openCustomerModal = true;
            } else {
                try {
                if ($isEditCustomer) {
                  if ($customerId <= 0) {
                    throw new RuntimeException('Cliente invalido para editar.');
                  }
                  $stOwnCustomer = $pdo->prepare(
                    'SELECT id FROM tenant_customers WHERE id = :id AND tenant_company_id = :tenant_company_id LIMIT 1'
                  );
                  $stOwnCustomer->execute(['id' => $customerId, 'tenant_company_id' => $tenantCompanyId]);
                  if (!$stOwnCustomer->fetchColumn()) {
                    throw new RuntimeException('El cliente no pertenece a tu empresa.');
                  }

                  $upCustomer = $pdo->prepare(
                    'UPDATE tenant_customers
                     SET rut = :rut,
                       razon_social = :razon_social,
                       nombre_fantasia = :nombre_fantasia,
                       direccion = :direccion,
                       comuna = :comuna,
                       ciudad = :ciudad,
                       telefono = :telefono,
                       celular = :celular,
                       email = :email,
                       contacto = :contacto,
                       notas_internas = :notas_internas
                     WHERE id = :id
                       AND tenant_company_id = :tenant_company_id'
                  );
                  $upCustomer->execute(array_merge(['id' => $customerId, 'tenant_company_id' => $tenantCompanyId], $customerInput));
                  $flash['ok'] = 'Cliente actualizado correctamente.';
                } else {
                  $insCustomer = $pdo->prepare(
                    'INSERT INTO tenant_customers (
                      tenant_company_id, rut, razon_social, nombre_fantasia, direccion, comuna, ciudad, telefono, celular, email, contacto, notas_internas, estado
                     ) VALUES (
                      :tenant_company_id, :rut, :razon_social, :nombre_fantasia, :direccion, :comuna, :ciudad, :telefono, :celular, :email, :contacto, :notas_internas, 1
                     )'
                  );
                  $insCustomer->execute(array_merge(['tenant_company_id' => $tenantCompanyId], $customerInput));
                  $flash['ok'] = 'Cliente agregado correctamente.';
                }

                    $customerForm = [
                  'id' => '',
                      'rut' => '',
                      'razon_social' => '',
                      'nombre_fantasia' => '',
                      'direccion' => '',
                      'comuna' => '',
                      'ciudad' => '',
                      'telefono' => '',
                      'celular' => '',
                      'email' => '',
                      'contacto' => '',
                      'notas_internas' => '',
                    ];
                } catch (Throwable $e) {
                  $flash['error'] = 'No se pudo guardar el cliente. Verifica si el RUT ya existe.';
                    $openCustomerModal = true;
                }
                $module = 'clientes';
            }
        }

        if ($action === 'delete_customer') {
            $customerId = (int)($_POST['customer_id'] ?? 0);
            if ($customerId > 0) {
                $del = $pdo->prepare('DELETE FROM tenant_customers WHERE id = :id AND tenant_company_id = :tenant_company_id');
                $del->execute(['id' => $customerId, 'tenant_company_id' => $tenantCompanyId]);
                $flash['ok'] = 'Cliente eliminado correctamente.';
            }
            $module = 'clientes';
        }

        if ($action === 'delete_quote') {
          $module = 'cotizaciones';
          $quoteId = (int)($_POST['quote_id'] ?? 0);
          if ($quoteId > 0) {
            $stOwnQuote = $pdo->prepare(
              'SELECT id FROM tenant_quotes WHERE id = :id AND tenant_company_id = :tenant_company_id LIMIT 1'
            );
            $stOwnQuote->execute(['id' => $quoteId, 'tenant_company_id' => $tenantCompanyId]);
            if ($stOwnQuote->fetchColumn()) {
              $pdo->beginTransaction();
              try {
                $delItems = $pdo->prepare('DELETE FROM tenant_quote_items WHERE tenant_quote_id = :tenant_quote_id');
                $delItems->execute(['tenant_quote_id' => $quoteId]);

                $delQuote = $pdo->prepare('DELETE FROM tenant_quotes WHERE id = :id AND tenant_company_id = :tenant_company_id');
                $delQuote->execute(['id' => $quoteId, 'tenant_company_id' => $tenantCompanyId]);

                $pdo->commit();
                $flash['ok'] = 'Cotizacion eliminada correctamente.';
              } catch (Throwable $e) {
                $pdo->rollBack();
                $flash['error'] = 'No se pudo eliminar la cotizacion.';
              }
            } else {
              $flash['error'] = 'La cotizacion no pertenece a tu empresa.';
            }
          }
        }

        if ($action === 'quick_update_quote_status') {
          $module = 'cotizaciones';
          $quoteId = (int)($_POST['quote_id'] ?? 0);
          $estado = trim((string)($_POST['estado'] ?? ''));
          $quoteStatusCatalog = quote_statuses();

          if ($quoteId <= 0) {
            $flash['error'] = 'Cotizacion invalida para actualizar estado.';
          } elseif (!in_array($estado, $quoteStatusCatalog, true)) {
            $flash['error'] = 'El estado seleccionado no es valido.';
          } else {
            $stOwnQuote = $pdo->prepare(
              'SELECT id
               FROM tenant_quotes
               WHERE id = :id
                 AND tenant_company_id = :tenant_company_id
               LIMIT 1'
            );
            $stOwnQuote->execute(['id' => $quoteId, 'tenant_company_id' => $tenantCompanyId]);
            if (!$stOwnQuote->fetchColumn()) {
              $flash['error'] = 'La cotizacion no pertenece a tu empresa.';
            } else {
              $upState = $pdo->prepare(
                'UPDATE tenant_quotes
                 SET estado = :estado
                 WHERE id = :id
                   AND tenant_company_id = :tenant_company_id'
              );
              $upState->execute([
                'estado' => $estado,
                'id' => $quoteId,
                'tenant_company_id' => $tenantCompanyId,
              ]);
              $flash['ok'] = 'Estado de cotizacion actualizado.';
            }
          }
        }

        if ($action === 'add_quote' || $action === 'update_quote') {
          $isEditQuote = $action === 'update_quote';
          $quoteId = (int)($_POST['quote_id'] ?? 0);
          $module = 'cotizaciones';
          $quoteFormInput = [
            'id' => (string)$quoteId,
            'customer_id' => (string)((int)($_POST['customer_id'] ?? 0)),
            'numero_cotizacion' => trim((string)($_POST['numero_cotizacion'] ?? '')),
            'fecha_emision' => trim((string)($_POST['fecha_emision'] ?? '')),
            'validez_dias' => trim((string)($_POST['validez_dias'] ?? '15')),
            'estado' => trim((string)($_POST['estado'] ?? 'Pendiente')),
            'descuento_pct' => trim((string)($_POST['descuento_pct'] ?? '0')),
            'terminos_condiciones_adicionales' => trim((string)($_POST['terminos_condiciones_adicionales'] ?? '')),
            'observaciones' => trim((string)($_POST['observaciones'] ?? '')),
            'items' => [],
          ];

          $rawDesc = $_POST['item_descripcion'] ?? [];
          $rawQty = $_POST['item_cantidad'] ?? [];
          $rawPrice = $_POST['item_precio'] ?? [];
          if (!is_array($rawDesc)) {
            $rawDesc = [];
          }
          if (!is_array($rawQty)) {
            $rawQty = [];
          }
          if (!is_array($rawPrice)) {
            $rawPrice = [];
          }

          $rows = max(count($rawDesc), count($rawQty), count($rawPrice));
          $itemsToInsert = [];
          $subtotal = 0.0;

          for ($i = 0; $i < $rows; $i++) {
            $descripcion = trim((string)($rawDesc[$i] ?? ''));
            $cantidadRaw = str_replace(',', '.', trim((string)($rawQty[$i] ?? '0')));
            $precioRaw = str_replace(',', '.', trim((string)($rawPrice[$i] ?? '0')));
            $cantidad = (float)$cantidadRaw;
            $precio = (float)$precioRaw;

            if ($descripcion === '' && $cantidad <= 0 && $precio <= 0) {
              continue;
            }

            $quoteFormInput['items'][] = [
              'descripcion' => $descripcion,
              'cantidad' => ($cantidadRaw === '' ? '0' : $cantidadRaw),
              'precio' => ($precioRaw === '' ? '0' : $precioRaw),
            ];

            if ($descripcion === '' || $cantidad <= 0 || $precio < 0) {
              $flash['error'] = 'Cada item requiere descripcion, cantidad mayor a 0 y precio valido.';
              $openQuoteModal = true;
              break;
            }

            $totalLinea = round($cantidad * $precio, 2);
            $itemsToInsert[] = [
              'orden' => count($itemsToInsert) + 1,
              'descripcion' => $descripcion,
              'cantidad' => $cantidad,
              'precio_unitario' => $precio,
              'total_linea' => $totalLinea,
            ];
            $subtotal += $totalLinea;
          }

          if (empty($quoteFormInput['items'])) {
            $quoteFormInput['items'][] = ['descripcion' => '', 'cantidad' => '1', 'precio' => '0'];
          }

          $quoteForm = $quoteFormInput;

          if ($flash['error'] === '') {
            $customerId = (int)$quoteFormInput['customer_id'];
            $numeroCotizacion = strtoupper($quoteFormInput['numero_cotizacion']);
            $fechaEmision = $quoteFormInput['fecha_emision'];
            $validezDias = (int)$quoteFormInput['validez_dias'];
            $estado = $quoteFormInput['estado'];
            $descuentoPct = (float)str_replace(',', '.', $quoteFormInput['descuento_pct']);
            $quoteStatusCatalog = quote_statuses();

            if ($customerId <= 0 || $numeroCotizacion === '' || $fechaEmision === '') {
              $flash['error'] = 'Completa cliente, numero de cotizacion y fecha de emision.';
              $openQuoteModal = true;
            } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $fechaEmision)) {
              $flash['error'] = 'La fecha de emision debe tener formato YYYY-MM-DD.';
              $openQuoteModal = true;
            } elseif ($validezDias < 1 || $validezDias > 3650) {
              $flash['error'] = 'La validez debe estar entre 1 y 3650 dias.';
              $openQuoteModal = true;
            } elseif ($descuentoPct < 0 || $descuentoPct > 100) {
              $flash['error'] = 'El descuento debe estar entre 0 y 100.';
              $openQuoteModal = true;
            } elseif (!in_array($estado, $quoteStatusCatalog, true)) {
              $flash['error'] = 'El estado de la cotizacion no es valido.';
              $openQuoteModal = true;
            } elseif (empty($itemsToInsert)) {
              $flash['error'] = 'Debes ingresar al menos un item valido.';
              $openQuoteModal = true;
            } else {
              $stCustomerOwn = $pdo->prepare(
                'SELECT id
                 FROM tenant_customers
                 WHERE id = :id AND tenant_company_id = :tenant_company_id
                 LIMIT 1'
              );
              $stCustomerOwn->execute(['id' => $customerId, 'tenant_company_id' => $tenantCompanyId]);
              $customerOwn = $stCustomerOwn->fetchColumn();
              if (!$customerOwn) {
                $flash['error'] = 'El cliente seleccionado no pertenece a tu empresa.';
                $openQuoteModal = true;
              } else {
                $stDup = $pdo->prepare(
                  'SELECT id
                   FROM tenant_quotes
                   WHERE tenant_company_id = :tenant_company_id
                     AND numero_cotizacion = :numero_cotizacion
                     AND (:current_id_guard = 0 OR id <> :current_id)
                   LIMIT 1'
                );
                $stDup->execute([
                  'tenant_company_id' => $tenantCompanyId,
                  'numero_cotizacion' => $numeroCotizacion,
                  'current_id_guard' => ($isEditQuote ? $quoteId : 0),
                  'current_id' => ($isEditQuote ? $quoteId : 0),
                ]);

                if ($stDup->fetchColumn()) {
                  $flash['error'] = 'El numero de cotizacion ya existe para tu empresa.';
                  $openQuoteModal = true;
                } else {
                  $money = quote_money_breakdown($subtotal, $descuentoPct);
                  $total = (float)$money['total'];
                  $pdo->beginTransaction();
                  try {
                    if ($isEditQuote) {
                      if ($quoteId <= 0) {
                        throw new RuntimeException('Cotizacion invalida para editar.');
                      }
                      $stOwnQuote = $pdo->prepare(
                        'SELECT id, estado
                         FROM tenant_quotes
                         WHERE id = :id
                           AND tenant_company_id = :tenant_company_id
                         LIMIT 1'
                      );
                      $stOwnQuote->execute(['id' => $quoteId, 'tenant_company_id' => $tenantCompanyId]);
                      $ownedQuote = $stOwnQuote->fetch();
                      if (!$ownedQuote) {
                        throw new RuntimeException('La cotizacion no pertenece a tu empresa.');
                      }

                      $upQuote = $pdo->prepare(
                        'UPDATE tenant_quotes
                         SET customer_id = :customer_id,
                             numero_cotizacion = :numero_cotizacion,
                             fecha_emision = :fecha_emision,
                             validez_dias = :validez_dias,
                             descuento_pct = :descuento_pct,
                             subtotal = :subtotal,
                             total = :total,
                             estado = :estado,
                             terminos_condiciones_adicionales = :terminos_condiciones_adicionales,
                             observaciones = :observaciones
                         WHERE id = :id
                           AND tenant_company_id = :tenant_company_id'
                      );
                      $upQuote->execute([
                        'id' => $quoteId,
                        'tenant_company_id' => $tenantCompanyId,
                        'customer_id' => $customerId,
                        'numero_cotizacion' => $numeroCotizacion,
                        'fecha_emision' => $fechaEmision,
                        'validez_dias' => $validezDias,
                        'descuento_pct' => $descuentoPct,
                        'subtotal' => $subtotal,
                        'total' => $total,
                        'estado' => $estado,
                        'terminos_condiciones_adicionales' => $quoteFormInput['terminos_condiciones_adicionales'],
                        'observaciones' => $quoteFormInput['observaciones'],
                      ]);

                      $delOldItems = $pdo->prepare('DELETE FROM tenant_quote_items WHERE tenant_quote_id = :tenant_quote_id');
                      $delOldItems->execute(['tenant_quote_id' => $quoteId]);
                    } else {
                      $insQuote = $pdo->prepare(
                        'INSERT INTO tenant_quotes (
                          tenant_company_id, customer_id, numero_cotizacion,
                          fecha_emision, validez_dias, descuento_pct,
                          subtotal, total, estado, terminos_condiciones_adicionales, observaciones
                         ) VALUES (
                          :tenant_company_id, :customer_id, :numero_cotizacion,
                          :fecha_emision, :validez_dias, :descuento_pct,
                          :subtotal, :total, :estado, :terminos_condiciones_adicionales, :observaciones
                         )'
                      );
                      $insQuote->execute([
                        'tenant_company_id' => $tenantCompanyId,
                        'customer_id' => $customerId,
                        'numero_cotizacion' => $numeroCotizacion,
                        'fecha_emision' => $fechaEmision,
                        'validez_dias' => $validezDias,
                        'descuento_pct' => $descuentoPct,
                        'subtotal' => $subtotal,
                        'total' => $total,
                        'estado' => $estado,
                        'terminos_condiciones_adicionales' => $quoteFormInput['terminos_condiciones_adicionales'],
                        'observaciones' => $quoteFormInput['observaciones'],
                      ]);
                      $quoteId = (int)$pdo->lastInsertId();
                    }

                    $insItem = $pdo->prepare(
                      'INSERT INTO tenant_quote_items (
                        tenant_quote_id, orden, descripcion, cantidad, precio_unitario, total_linea
                       ) VALUES (
                        :tenant_quote_id, :orden, :descripcion, :cantidad, :precio_unitario, :total_linea
                       )'
                    );

                    foreach ($itemsToInsert as $itemRow) {
                      $insItem->execute([
                        'tenant_quote_id' => $quoteId,
                        'orden' => $itemRow['orden'],
                        'descripcion' => $itemRow['descripcion'],
                        'cantidad' => $itemRow['cantidad'],
                        'precio_unitario' => $itemRow['precio_unitario'],
                        'total_linea' => $itemRow['total_linea'],
                      ]);
                    }

                    $pdo->commit();
                    $flash['ok'] = $isEditQuote ? 'Cotizacion actualizada correctamente.' : 'Cotizacion creada correctamente.';
                    $quoteForm = [
                      'id' => '',
                      'customer_id' => '',
                      'numero_cotizacion' => next_quote_number($pdo, $tenantCompanyId),
                      'fecha_emision' => date('Y-m-d'),
                      'validez_dias' => '15',
                      'estado' => 'Pendiente',
                      'descuento_pct' => '0',
                      'terminos_condiciones_adicionales' => '',
                      'observaciones' => '',
                      'items' => [
                        ['descripcion' => '', 'cantidad' => '1', 'precio' => '0'],
                      ],
                    ];
                    $openQuoteModal = false;
                  } catch (Throwable $e) {
                    $pdo->rollBack();
                    $flash['error'] = 'No se pudo guardar la cotizacion.';
                    $openQuoteModal = true;
                  }
                }
              }
            }
          }
        }

        $_SESSION['hermes_company_postback'] = [
          'module' => $module,
          'flash' => $flash,
          'openCustomerModal' => $openCustomerModal,
          'openQuoteModal' => $openQuoteModal,
          'customerForm' => $customerForm,
          'quoteForm' => $quoteForm,
        ];
        header('Location: ' . dashboard_module_url($module));
        exit;
    }

    $stProfile = $pdo->prepare(
        'SELECT nombre, rut, direccion, telefono, celular, email_principal, condicion_de_pago, entrega, validez,
                moneda, sitio_web, contacto_principal_nombre, contacto_principal_cargo, notas_internas, logo_filename
         FROM tenant_company_profiles
         WHERE tenant_company_id = :tenant_company_id
         LIMIT 1'
    );
    $stProfile->execute(['tenant_company_id' => $tenantCompanyId]);
    $profileDb = $stProfile->fetch();
    if ($profileDb) {
        foreach ($profile as $k => $v) {
            if (array_key_exists($k, $profileDb)) {
                $profile[$k] = (string)$profileDb[$k];
            }
        }
    }

    $logoPublicUrl = logo_public_url($profile['logo_filename']);

    $seedUsage = $pdo->prepare(
        'INSERT INTO tenant_plan_usage (tenant_company_id, plan_code, storage_limit_mb, storage_used_mb)
         VALUES (:tenant_company_id, :plan_code, :storage_limit_mb, :storage_used_mb)
         ON DUPLICATE KEY UPDATE tenant_company_id = tenant_company_id'
    );
    $seedUsage->execute([
        'tenant_company_id' => $tenantCompanyId,
        'plan_code' => 'basico',
        'storage_limit_mb' => 1024,
        'storage_used_mb' => 0,
    ]);

    $stUsage = $pdo->prepare('SELECT plan_code, storage_limit_mb, storage_used_mb FROM tenant_plan_usage WHERE tenant_company_id = :tenant_company_id LIMIT 1');
    $stUsage->execute(['tenant_company_id' => $tenantCompanyId]);
    $usageRow = $stUsage->fetch();
    if ($usageRow) {
        $usage['plan_code'] = (string)$usageRow['plan_code'];
        $usage['storage_limit_mb'] = max(1, (int)$usageRow['storage_limit_mb']);
        $usage['storage_used_mb'] = max(0, (int)$usageRow['storage_used_mb']);
        if ($usage['storage_used_mb'] > $usage['storage_limit_mb']) {
            $usage['storage_used_mb'] = $usage['storage_limit_mb'];
        }
        $usage['percent'] = (int)round(($usage['storage_used_mb'] / $usage['storage_limit_mb']) * 100);
    }

    $isPaidAccount = ($planBilling['payment_status'] === 'paid') && ($planBilling['plan_status'] === 'paid');
    if ($isPaidAccount) {
      $planBilling['can_pay_renewal'] = false;
      if ($planBilling['days_left'] === null) {
        $planBilling['notice_tone'] = 'ok';
        $planBilling['notice_title'] = 'Plan pagado al dia';
        $planBilling['notice_text'] = 'Tu cuenta ' . strtolower($planBilling['billing_cycle_name']) . ' esta pagada. El pago de renovacion queda bloqueado para evitar cobros duplicados.';
      } elseif ($planBilling['days_left'] < 0) {
        $planBilling['notice_tone'] = 'danger';
        $planBilling['notice_title'] = 'Renovacion vencida';
        $planBilling['notice_text'] = 'Tu plan ' . strtolower($planBilling['billing_cycle_name']) . ' esta vencido hace ' . abs((int)$planBilling['days_left']) . ' dias. Regulariza para evitar suspension.';
      } elseif ($planBilling['days_left'] <= 7) {
        $planBilling['notice_tone'] = 'warn';
        $planBilling['notice_title'] = 'Renovacion proxima';
        $planBilling['notice_text'] = 'Quedan ' . (int)$planBilling['days_left'] . ' dias para renovar tu plan ' . strtolower($planBilling['billing_cycle_name']) . '.';
      } else {
        $planBilling['notice_tone'] = 'ok';
        $planBilling['notice_title'] = 'Plan pagado al dia';
        $planBilling['notice_text'] = 'Tu plan ' . strtolower($planBilling['billing_cycle_name']) . ' vence en ' . (int)$planBilling['days_left'] . ' dias.';
      }
    } else {
      $planBilling['notice_tone'] = 'warn';
      $planBilling['notice_title'] = 'Pago pendiente';
      if ($planBilling['can_pay_renewal']) {
        $planBilling['notice_text'] = 'Tu cuenta tiene pago pendiente. Usa el acceso de renovacion para reactivar el plan.';
      } else {
        $planBilling['notice_text'] = 'No hay un enlace de pago activo. Solicita uno nuevo a soporte.';
      }
    }

    $stCustomers = $pdo->prepare(
      'SELECT id, rut, razon_social, nombre_fantasia, direccion, comuna, ciudad, telefono, celular, email, contacto, notas_internas, estado
         FROM tenant_customers
         WHERE tenant_company_id = :tenant_company_id
         ORDER BY razon_social ASC, id DESC'
    );
    $stCustomers->execute(['tenant_company_id' => $tenantCompanyId]);
    $customers = $stCustomers->fetchAll();

    $stQuotes = $pdo->prepare(
      'SELECT q.id, q.customer_id, q.numero_cotizacion, q.fecha_emision, q.validez_dias,
          q.descuento_pct, q.subtotal, q.total, q.estado, q.terminos_condiciones_adicionales, q.observaciones,
          c.razon_social AS customer_name
       FROM tenant_quotes q
       INNER JOIN tenant_customers c
         ON c.id = q.customer_id
        AND c.tenant_company_id = q.tenant_company_id
       WHERE q.tenant_company_id = :tenant_company_id
       ORDER BY q.id DESC
       LIMIT 200'
    );
    $stQuotes->execute(['tenant_company_id' => $tenantCompanyId]);
    $quotes = $stQuotes->fetchAll();

    if (!empty($quotes)) {
      $quoteIds = array_map(static fn($row) => (int)$row['id'], $quotes);
      $quoteIds = array_values(array_filter($quoteIds, static fn($id) => $id > 0));
      if (!empty($quoteIds)) {
        $placeholders = implode(',', array_fill(0, count($quoteIds), '?'));
        $stItems = $pdo->prepare(
          "SELECT tenant_quote_id, descripcion, cantidad, precio_unitario, total_linea
           FROM tenant_quote_items
           WHERE tenant_quote_id IN ($placeholders)
           ORDER BY tenant_quote_id ASC, orden ASC, id ASC"
        );
        $stItems->execute($quoteIds);
        $itemRows = $stItems->fetchAll();
        foreach ($itemRows as $itemRow) {
          $quoteId = (int)$itemRow['tenant_quote_id'];
          if (!isset($quoteItemsByQuote[$quoteId])) {
            $quoteItemsByQuote[$quoteId] = [];
          }
          $quoteItemsByQuote[$quoteId][] = $itemRow;
        }
      }
    }

    $dashStatusCatalog = quote_statuses();
    $dashStatusTotals = [];
    foreach ($dashStatusCatalog as $dashStatusName) {
      $dashStatusTotals[$dashStatusName] = ['count' => 0, 'amount' => 0.0];
    }
    $dashTotalQuotes = 0;
    $dashTotalAmount = 0.0;
    $dashClientStats = [];
    foreach ($quotes as $dashQuoteRow) {
      $dashTotalQuotes += 1;
      $dashAmount = (float)$dashQuoteRow['total'];
      $dashTotalAmount += $dashAmount;
      $dashStatusName = (string)$dashQuoteRow['estado'];
      if (!isset($dashStatusTotals[$dashStatusName])) {
        $dashStatusTotals[$dashStatusName] = ['count' => 0, 'amount' => 0.0];
      }
      $dashStatusTotals[$dashStatusName]['count'] += 1;
      $dashStatusTotals[$dashStatusName]['amount'] += $dashAmount;

      $dashCustomerKey = (int)$dashQuoteRow['customer_id'];
      if (!isset($dashClientStats[$dashCustomerKey])) {
        $dashClientStats[$dashCustomerKey] = [
          'customer_id' => $dashCustomerKey,
          'customer_name' => (string)$dashQuoteRow['customer_name'],
          'count' => 0,
          'amount' => 0.0,
          'accepted_amount' => 0.0,
        ];
      }
      $dashClientStats[$dashCustomerKey]['count'] += 1;
      $dashClientStats[$dashCustomerKey]['amount'] += $dashAmount;
      if (in_array($dashStatusName, ['Aceptada', 'Pendiente OC', 'OC Recepcionada', 'Facturada', 'Pagada'], true)) {
        $dashClientStats[$dashCustomerKey]['accepted_amount'] += $dashAmount;
      }
    }

    $dashAcceptedStates = ['Aceptada', 'Pendiente OC', 'OC Recepcionada', 'Facturada', 'Pagada'];
    $dashAcceptedCount = 0;
    $dashAcceptedAmount = 0.0;
    foreach ($dashAcceptedStates as $dashAcceptedName) {
      if (isset($dashStatusTotals[$dashAcceptedName])) {
        $dashAcceptedCount += (int)$dashStatusTotals[$dashAcceptedName]['count'];
        $dashAcceptedAmount += (float)$dashStatusTotals[$dashAcceptedName]['amount'];
      }
    }
    $dashPendingAmount = isset($dashStatusTotals['Pendiente']) ? (float)$dashStatusTotals['Pendiente']['amount'] : 0.0;
    $dashRejectedAmount = isset($dashStatusTotals['Rechazada']) ? (float)$dashStatusTotals['Rechazada']['amount'] : 0.0;
    $dashConversionRate = $dashTotalQuotes > 0 ? (int)round(($dashAcceptedCount / $dashTotalQuotes) * 100) : 0;

    $dashMaxStatusAmount = 0.0;
    foreach ($dashStatusTotals as $dashStatusRow) {
      if ((float)$dashStatusRow['amount'] > $dashMaxStatusAmount) {
        $dashMaxStatusAmount = (float)$dashStatusRow['amount'];
      }
    }

    usort($dashClientStats, static function ($a, $b) {
      return ((float)$b['amount']) <=> ((float)$a['amount']);
    });
    $dashTopClients = array_slice($dashClientStats, 0, 5);
    $dashMaxClientAmount = 0.0;
    foreach ($dashTopClients as $dashClientRow) {
      if ((float)$dashClientRow['amount'] > $dashMaxClientAmount) {
        $dashMaxClientAmount = (float)$dashClientRow['amount'];
      }
    }

    $dashRecentQuotes = array_slice($quotes, 0, 5);
    $dashCustomersTotal = count($customers);
    $dashCurrencyCode = (string)($profile['moneda'] ?? 'CLP');

    if ($module === 'cotizaciones') {
      $previewQuoteId = (int)($_GET['view_quote_id'] ?? 0);
      if ($previewQuoteId > 0) {
        $stPreview = $pdo->prepare(
          'SELECT q.id, q.customer_id, q.numero_cotizacion, q.fecha_emision, q.validez_dias,
              q.descuento_pct, q.subtotal, q.total, q.estado, q.terminos_condiciones_adicionales, q.observaciones,
              c.razon_social AS customer_name, c.rut AS customer_rut,
              c.direccion AS customer_direccion, c.email AS customer_email,
              c.contacto AS customer_contacto
           FROM tenant_quotes q
           INNER JOIN tenant_customers c
             ON c.id = q.customer_id
            AND c.tenant_company_id = q.tenant_company_id
           WHERE q.id = :id
             AND q.tenant_company_id = :tenant_company_id
           LIMIT 1'
        );
        $stPreview->execute([
          'id' => $previewQuoteId,
          'tenant_company_id' => $tenantCompanyId,
        ]);
        $quotePreview = $stPreview->fetch();

        if ($quotePreview) {
          $stPreviewItems = $pdo->prepare(
            'SELECT descripcion, cantidad, precio_unitario, total_linea
             FROM tenant_quote_items
             WHERE tenant_quote_id = :tenant_quote_id
             ORDER BY orden ASC, id ASC'
          );
          $stPreviewItems->execute(['tenant_quote_id' => $previewQuoteId]);
          $quotePreviewItems = $stPreviewItems->fetchAll();
        }
      }
    }

    if ($quoteForm['numero_cotizacion'] === '') {
      $quoteForm['numero_cotizacion'] = next_quote_number($pdo, $tenantCompanyId);
    }
} catch (Throwable $e) {
    error_log('HERMES_COMPANY_DASHBOARD_ERROR: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    $flash['error'] = 'No fue posible cargar el panel de empresa por un error de base de datos.';
}

$bodyClass = 'module-' . $module;
$quoteEmbed = isset($_GET['quote_embed']) && (string)$_GET['quote_embed'] === '1';

if ($module === 'cotizaciones' && is_array($quotePreview) && !empty($quotePreview)) {
    ?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vista cotizacion <?= h((string)$quotePreview['numero_cotizacion']) ?></title>
  <style>
    @page { size: Letter; margin: 12mm; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Segoe UI, Arial, sans-serif;
      background: #e5e7eb;
      color: #111827;
      padding: 20px;
    }
    .tools {
      max-width: 8.5in;
      margin: 0 auto 12px;
      display: flex;
      gap: 8px;
      justify-content: flex-end;
    }
    .btn {
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      padding: 8px 12px;
      background: #fff;
      color: #111827;
      text-decoration: none;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
    }
    .btn.primary {
      background: #1d4ed8;
      border-color: #1d4ed8;
      color: #fff;
    }
    .page {
      width: 8.5in;
      min-height: 11in;
      margin: 0 auto;
      background: #fff;
      border: 1px solid #d1d5db;
      padding: 14mm;
      box-shadow: 0 10px 24px rgba(0,0,0,.12);
      display: flex;
      flex-direction: column;
    }
    .head {
      display: grid;
      grid-template-columns: 190px minmax(0, 1.55fr) minmax(180px, 1fr);
      gap: 12px;
      align-items: start;
      margin-bottom: 14px;
      border-bottom: 2px solid #0f172a;
      padding-bottom: 10px;
    }
    .head-logo {
      min-height: 96px;
      display: flex;
      align-items: flex-start;
      justify-content: flex-start;
    }
    .head-company {
      display: grid;
      gap: 4px;
      align-content: start;
      min-width: 0;
    }
    .head-quote {
      text-align: right;
      display: grid;
      gap: 4px;
      align-content: start;
    }
    .quote-logo-wrap {
      max-height: 92px;
      display: flex;
      align-items: center;
    }
    .quote-logo {
      max-height: 92px;
      max-width: 280px;
      width: auto;
      height: auto;
      object-fit: contain;
      display: block;
    }
    .head h1 {
      margin: 0;
      font-size: 18px;
      letter-spacing: .03em;
      line-height: 1.2;
    }
    .head-company .muted,
    .head-quote .muted { font-size: 12px; line-height: 1.25; }
    .quote-doc-label {
      font-size: 11px;
      color: #6b7280;
      text-transform: uppercase;
      letter-spacing: .08em;
      font-weight: 700;
    }
    .quote-doc-number {
      font-size: 18px;
      font-weight: 800;
      line-height: 1.15;
      color: #0f172a;
      word-break: break-word;
    }
    .muted { color: #4b5563; font-size: 13px; }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 14px;
    }
    .card {
      border: 1px solid #d1d5db;
      border-radius: 8px;
      padding: 10px;
    }
    .card h3 {
      margin: 0 0 8px;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: #374151;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      font-size: 13px;
    }
    th, td {
      border: 1px solid #bfdbfe;
      padding: 7px;
      vertical-align: top;
    }
    th {
      background: #dbeafe;
      color: #1e3a8a;
      text-align: left;
    }
    tbody tr:nth-child(even) td {
      background: #f8fbff;
    }
    .totals {
      margin: 0;
      width: 100%;
    }
    .totals td { font-weight: 600; }
    .totals tr:last-child td {
      font-size: 15px;
      background: #dbeafe;
      color: #1e3a8a;
    }
    .quote-items-section {
      margin-bottom: 0;
    }
    .quote-financials {
      margin-top: auto;
      padding-top: 14px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(280px, 340px);
      gap: 10px;
      align-items: stretch;
    }
    .quote-terms-box,
    .totals-box {
      border: 1px solid #d1d5db;
      border-radius: 8px;
      background: #fff;
      min-height: 156px;
    }
    .quote-terms-box {
      padding: 10px;
      display: grid;
      grid-template-rows: auto 1fr;
      gap: 6px;
    }
    .quote-terms-title {
      margin: 0;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: #374151;
    }
    .quote-terms-content {
      white-space: pre-line;
      font-size: 12px;
      line-height: 1.3;
      color: #374151;
    }
    .totals-box {
      overflow: hidden;
    }
    .totals-box .totals td {
      padding-top: 8px;
      padding-bottom: 8px;
    }
    .obs {
      margin-top: 14px;
      border: 1px solid #d1d5db;
      border-radius: 8px;
      padding: 10px;
      white-space: pre-line;
      font-size: 13px;
    }
    @media (max-width: 860px) {
      .head {
        grid-template-columns: 1fr;
      }
      .head-quote {
        text-align: left;
      }
      .head-logo {
        min-height: 64px;
      }
      .quote-logo {
        max-height: 64px;
      }
      .quote-financials {
        grid-template-columns: 1fr;
      }
    }
    @media print {
      html, body {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      body { background: #fff; padding: 0; }
      .tools { display: none; }
      .page {
        width: auto;
        min-height: 100vh;
        border: 0;
        box-shadow: none;
        margin: 0;
        padding: 0;
        display: flex;
        flex-direction: column;
      }
      .head {
        grid-template-columns: 190px minmax(0, 1.55fr) minmax(180px, 1fr) !important;
      }
      .head-quote {
        text-align: right !important;
      }
      .quote-financials {
        grid-template-columns: minmax(0, 1fr) minmax(280px, 340px) !important;
        margin-top: auto !important;
        padding-top: 12px !important;
        page-break-inside: avoid;
        break-inside: avoid;
      }
      th,
      .totals tr:last-child td {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      .quote-terms-box,
      .totals-box,
      .totals,
      .totals tbody,
      .totals tr {
        page-break-inside: avoid;
        break-inside: avoid;
      }
    }

    <?php if ($quoteEmbed): ?>
    body {
      background: #0b1734;
      padding: 0;
    }
    .tools {
      display: none;
    }
    .page {
      margin: 0 auto;
      box-shadow: none;
      border: 0;
    }
    <?php endif; ?>
  </style>
</head>
<body>
  <?php if (!$quoteEmbed): ?>
    <div class="tools">
      <a class="btn" href="/empresa/dashboard/?module=cotizaciones">Volver</a>
      <button class="btn primary" type="button" onclick="window.print()">Imprimir</button>
    </div>
  <?php endif; ?>

  <article class="page">
    <header class="head">
      <div class="head-logo">
        <?php if ($logoPublicUrl !== ''): ?>
          <div class="quote-logo-wrap">
            <img class="quote-logo" src="<?= h($logoPublicUrl) ?>" alt="Logo empresa">
          </div>
        <?php endif; ?>
      </div>
      <div class="head-company">
        <h1><?= h($profile['nombre'] !== '' ? $profile['nombre'] : 'Empresa') ?></h1>
        <div class="muted">RUT: <?= h($profile['rut']) ?></div>
        <div class="muted">Email: <?= h($profile['email_principal']) ?></div>
        <?php if (trim((string)$profile['direccion']) !== ''): ?>
          <div class="muted">Direccion: <?= h((string)$profile['direccion']) ?></div>
        <?php endif; ?>
        <?php if (trim((string)$profile['telefono']) !== ''): ?>
          <div class="muted">Telefono: <?= h((string)$profile['telefono']) ?></div>
        <?php endif; ?>
      </div>
      <div class="head-quote">
        <div class="quote-doc-label">Cotizacion</div>
        <div class="quote-doc-number"><?= h((string)$quotePreview['numero_cotizacion']) ?></div>
        <div class="muted">Fecha: <?= h((string)$quotePreview['fecha_emision']) ?></div>
        <div class="muted">Estado: <?= h((string)$quotePreview['estado']) ?></div>
      </div>
    </header>

    <section class="grid">
      <div class="card">
        <h3>Cliente</h3>
        <div><strong><?= h((string)$quotePreview['customer_name']) ?></strong></div>
        <div class="muted">RUT: <?= h((string)$quotePreview['customer_rut']) ?></div>
        <div class="muted">Contacto: <?= h((string)$quotePreview['customer_contacto']) ?></div>
        <div class="muted">Email: <?= h((string)$quotePreview['customer_email']) ?></div>
      </div>
      <div class="card">
        <h3>Condiciones</h3>
        <div class="muted">Validez: <?= h(trim((string)$profile['validez']) !== '' ? (string)$profile['validez'] : ((string)$quotePreview['validez_dias'] . ' dias')) ?></div>
        <div class="muted">Entrega: <?= h(trim((string)$profile['entrega']) !== '' ? (string)$profile['entrega'] : 'No definida') ?></div>
        <div class="muted">Condicion de pago: <?= h(trim((string)$profile['condicion_de_pago']) !== '' ? (string)$profile['condicion_de_pago'] : 'No definida') ?></div>
        <div class="muted">Moneda: <?= h(trim((string)$profile['moneda']) !== '' ? (string)$profile['moneda'] : 'CLP') ?></div>
      </div>
    </section>

    <section class="quote-items-section">
      <table>
        <thead>
          <tr>
            <th style="width:52%;">Descripcion</th>
            <th style="width:12%;">Cantidad</th>
            <th style="width:18%;">Precio unitario</th>
            <th style="width:18%;">Total linea</th>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($quotePreviewItems)): ?>
            <tr><td colspan="4">Sin items.</td></tr>
          <?php else: ?>
            <?php foreach ($quotePreviewItems as $it): ?>
              <tr>
                <td><?= h((string)$it['descripcion']) ?></td>
                <td><?= h((string)$it['cantidad']) ?></td>
                <td>$<?= h(money_clp((float)$it['precio_unitario'])) ?></td>
                <td>$<?= h(money_clp((float)$it['total_linea'])) ?></td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
        </tbody>
      </table>

    </section>

    <?php if (trim((string)$quotePreview['observaciones']) !== ''): ?>
      <section class="obs">
        <strong>Observaciones</strong>
        <div><?= h((string)$quotePreview['observaciones']) ?></div>
      </section>
    <?php endif; ?>

    <div class="quote-financials">
      <div class="quote-terms-box">
        <h4 class="quote-terms-title">Terminos y condiciones adicionales</h4>
        <div class="quote-terms-content"><?= h(trim((string)$quotePreview['terminos_condiciones_adicionales']) !== '' ? (string)$quotePreview['terminos_condiciones_adicionales'] : 'Sin terminos adicionales.') ?></div>
      </div>

      <div class="totals-box">
        <table class="totals">
          <?php
            $previewMoney = quote_money_breakdown((float)$quotePreview['subtotal'], (float)$quotePreview['descuento_pct']);
          ?>
          <tbody>
            <tr><td>Subtotal</td><td style="text-align:right;">$<?= h(money_clp((float)$previewMoney['subtotal'])) ?></td></tr>
            <tr><td>Descuento (<?= h(number_format((float)$previewMoney['descuento_pct'], 2, '.', '')) ?>%)</td><td style="text-align:right;">$<?= h(money_clp((float)$previewMoney['descuento_monto'])) ?></td></tr>
            <tr><td>IVA (19%)</td><td style="text-align:right;">$<?= h(money_clp((float)$previewMoney['iva_monto'])) ?></td></tr>
            <tr><td>Total</td><td style="text-align:right;">$<?= h(money_clp((float)$previewMoney['total'])) ?></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </article>
</body>
</html>
<?php
    exit;
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard empresa | GesMan HERMES</title>
  <meta name="description" content="Panel de empresa para plan basico de GesMan HERMES.">
  <link rel="icon" type="image/svg+xml" href="/assets/img/favicon-hermes.svg">
  <style>
    :root {
      --bg-1: #07112a;
      --bg-2: #101d40;
      --line: #2a3a62;
      --gold: #f4b400;
      --gold-2: #ffe38b;
      --txt: #f8fafc;
      --muted: #9fb0cf;
      --ok: #86efac;
      --danger: #fda4af;
      --panel: rgba(15,26,52,.84);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Segoe UI, Arial, sans-serif;
      color: var(--txt);
      background:
        radial-gradient(circle at 8% 0%, rgba(255,216,77,.19), transparent 38%),
        radial-gradient(circle at 90% 0%, rgba(91,192,190,.13), transparent 44%),
        linear-gradient(180deg, var(--bg-1), var(--bg-2));
      min-height: 100vh;
      overflow-y: scroll;
    }
    body.spa-loading .content {
      opacity: .62;
      filter: saturate(.92);
      transition: opacity .18s ease;
    }
    .spa-progress {
      position: fixed;
      top: 0;
      left: 0;
      height: 2px;
      width: 0;
      background: linear-gradient(90deg, #ffe38b, #f4b400);
      box-shadow: 0 0 12px rgba(244,180,0,.45);
      z-index: 120;
      opacity: 0;
      transition: width .22s ease, opacity .22s ease;
    }
    body.spa-loading .spa-progress {
      width: 72%;
      opacity: 1;
    }
    body.spa-done .spa-progress {
      width: 100%;
      opacity: 0;
    }
    .layout { display: grid; grid-template-columns: 280px 1fr; min-height: 100vh; }
    .side {
      border-right: 1px solid var(--line);
      background: rgba(7,17,42,.88);
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .brand svg { width: 210px; max-width: 100%; }
    .company-box {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: .7rem;
      background: rgba(15,26,52,.8);
      font-size: .86rem;
      color: var(--muted);
    }
    .menu { display: grid; gap: .45rem; }
    .menu a {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: .6rem;
      color: #d7e1f3;
      text-decoration: none;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: .62rem .68rem;
      font-size: .9rem;
      background: rgba(15,26,52,.62);
    }
    .menu a.active {
      border-color: #8b6500;
      background: linear-gradient(180deg, rgba(255,227,139,.2), rgba(244,180,0,.13));
      color: var(--gold-2);
    }
    .menu .nav-icon {
      width: 18px;
      height: 18px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      border: 1px solid #2d436f;
      background: rgba(11,23,52,.8);
      color: #8fa8d4;
      flex: 0 0 auto;
      transition: border-color .18s ease, color .18s ease, background .18s ease;
    }
    .menu a.active .nav-icon {
      border-color: #8b6500;
      color: #f4b400;
      background: rgba(255,227,139,.13);
    }
    .menu .nav-icon svg {
      width: 11px;
      height: 11px;
      stroke: currentColor;
      fill: none;
      stroke-width: 1.8;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .content { padding: 1.1rem; }
    .top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: .8rem;
      margin-bottom: .8rem;
      flex-wrap: wrap;
    }
    .top h1 { margin: 0; font-size: 1.28rem; color: #fff4b8; }
    .actions { display: flex; gap: .5rem; }
    .btn {
      border: 1px solid #4b5e8c;
      border-radius: 10px;
      background: linear-gradient(180deg, #152546, #0c1833);
      color: #d3dcef;
      font-weight: 600;
      padding: .55rem .8rem;
      font-size: .86rem;
      text-decoration: none;
      cursor: pointer;
      transition: border-color .18s ease, transform .18s ease, box-shadow .18s ease;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.07);
    }
    .btn:hover {
      border-color: #6d87c3;
      transform: translateY(-1px);
      box-shadow: 0 8px 20px rgba(2,10,30,.3), inset 0 1px 0 rgba(255,255,255,.08);
    }
    .btn:active { transform: translateY(0); }
    .btn.primary {
      border-color: #8b6500;
      background: linear-gradient(180deg, #ffe38b, #e3a900);
      color: #1f2937;
      font-weight: 700;
    }
    .btn.danger {
      border-color: #7f1d1d;
      background: linear-gradient(180deg, #7f1d1d, #5f1212);
      color: #fecaca;
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--panel);
      padding: 1rem;
      margin-bottom: .8rem;
    }
    .panel h2 { margin: .1rem 0 .6rem; color: #fff4b8; }
    .panel h3 { margin: .1rem 0 .5rem; color: #f3f4f6; }
    .msg-ok, .msg-err {
      border: 1px solid;
      border-radius: 10px;
      padding: .7rem;
      font-size: .92rem;
      margin-bottom: .7rem;
    }
    .msg-ok { border-color: #14532d; background: rgba(20,83,45,.2); color: var(--ok); }
    .msg-err { border-color: #7f1d1d; background: rgba(127,29,29,.2); color: var(--danger); }
    .muted { color: var(--muted); font-size: .9rem; }
    input[type="file"] {
      color: #bfd1f2;
      background: #0b1734;
      border: 1px solid #334a7f;
      border-radius: 9px;
      min-height: 36px;
      height: 36px;
      padding: 4px 6px;
      width: 100%;
      font-size: .78rem;
    }
    input[type="file"]::file-selector-button {
      border: 1px solid #8b6500;
      border-radius: 7px;
      padding: .3rem .6rem;
      margin-right: .55rem;
      background: linear-gradient(180deg, #ffe38b, #e3a900);
      color: #1f2937;
      font-weight: 700;
      cursor: pointer;
    }

    .module-dashboard,
    .module-dashboard body,
    .module-dashboard .layout { min-height: 100vh; }
    body.module-dashboard { height: 100vh; overflow: hidden; }
    body.module-dashboard .content {
      height: 100vh;
      display: flex;
      flex-direction: column;
      padding: .9rem 1.1rem 1rem;
      overflow: hidden;
    }
    body.module-dashboard #appMain {
      flex: 1 1 auto;
      min-height: 0;
      display: flex;
      flex-direction: column;
    }
    body.module-dashboard .top { margin-bottom: .55rem; }
    .dashboard-grid {
      flex: 1 1 auto;
      min-height: 0;
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr);
      grid-template-rows: auto minmax(0, 1.4fr) minmax(0, 1fr);
      grid-template-areas:
        "kpis kpis"
        "pipeline clients"
        "plan recent";
      gap: .7rem;
    }
    .dash-kpis {
      grid-area: kpis;
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: .7rem;
    }
    .dash-kpi {
      position: relative;
      border-radius: 14px;
      padding: .72rem .85rem;
      background: linear-gradient(150deg, rgba(20,33,68,.92), rgba(8,16,38,.92));
      border: 1px solid #28406f;
      display: flex;
      gap: .7rem;
      align-items: center;
      overflow: hidden;
      box-shadow: 0 10px 24px rgba(2,8,24,.35), inset 0 1px 0 rgba(255,255,255,.04);
    }
    .dash-kpi::after {
      content: "";
      position: absolute;
      inset: auto -30% -60% auto;
      width: 140px;
      height: 140px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(244,180,0,.18), transparent 70%);
      pointer-events: none;
    }
    .dash-kpi--quotes::after { background: radial-gradient(circle, rgba(96,165,250,.22), transparent 70%); }
    .dash-kpi--amount::after { background: radial-gradient(circle, rgba(244,180,0,.22), transparent 70%); }
    .dash-kpi--accepted::after { background: radial-gradient(circle, rgba(34,197,94,.22), transparent 70%); }
    .dash-kpi--conv::after { background: radial-gradient(circle, rgba(168,85,247,.22), transparent 70%); }
    .dash-kpi-icon {
      width: 38px;
      height: 38px;
      border-radius: 10px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 1.05rem;
      font-weight: 800;
      background: rgba(244,180,0,.14);
      color: #f4b400;
      border: 1px solid rgba(244,180,0,.35);
      flex-shrink: 0;
    }
    .dash-kpi--quotes .dash-kpi-icon { background: rgba(96,165,250,.14); color: #93c5fd; border-color: rgba(96,165,250,.35); }
    .dash-kpi--accepted .dash-kpi-icon { background: rgba(34,197,94,.14); color: #86efac; border-color: rgba(34,197,94,.35); }
    .dash-kpi--conv .dash-kpi-icon { background: rgba(168,85,247,.14); color: #d8b4fe; border-color: rgba(168,85,247,.35); }
    .dash-kpi-body { display: flex; flex-direction: column; gap: .12rem; min-width: 0; }
    .dash-kpi-label { font-size: .72rem; color: #9fb0cf; text-transform: uppercase; letter-spacing: .03em; }
    .dash-kpi-value { font-size: 1.32rem; font-weight: 800; color: #f8fafc; line-height: 1.05; overflow: hidden; text-overflow: ellipsis; }
    .dash-kpi-foot { font-size: .72rem; color: #cbd5e1; }

    .dash-panel {
      border: 1px solid #28406f;
      border-radius: 14px;
      background: linear-gradient(160deg, rgba(15,26,52,.94), rgba(7,16,40,.94));
      padding: .8rem .9rem;
      display: flex;
      flex-direction: column;
      gap: .55rem;
      min-height: 0;
      overflow: hidden;
      box-shadow: 0 10px 24px rgba(2,8,24,.32);
    }
    .dash-panel-head {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: .6rem;
      flex-wrap: wrap;
    }
    .dash-panel-head h2 { margin: 0; font-size: .98rem; color: #fff4b8; }
    .dash-panel-sub { font-size: .72rem; color: #9fb0cf; }
    .dash-panel-link {
      font-size: .76rem;
      color: #f4b400;
      text-decoration: none;
      border-bottom: 1px dashed rgba(244,180,0,.45);
    }
    .dash-panel-link:hover { color: #fff; border-color: #fff; }
    .dash-empty {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #9fb0cf;
      font-size: .85rem;
      text-align: center;
      padding: 1rem .5rem;
    }

    .dash-pipeline { grid-area: pipeline; }
    .dash-pipeline-list {
      list-style: none;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: .42rem;
      flex: 1;
      min-height: 0;
      overflow: hidden;
    }
    .dash-pipeline-item {
      display: grid;
      grid-template-columns: minmax(140px, 1.1fr) minmax(120px, 2fr) auto;
      align-items: center;
      gap: .65rem;
    }
    .dash-pipeline-meta { display: flex; align-items: center; gap: .42rem; min-width: 0; }
    .dash-pipeline-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
      background: #f4b400;
      box-shadow: 0 0 0 2px rgba(244,180,0,.18);
    }
    .dash-pipeline-name {
      font-size: .82rem;
      color: #e5e7eb;
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .dash-pipeline-count {
      font-size: .72rem;
      color: #cbd5e1;
      background: rgba(255,255,255,.05);
      border: 1px solid rgba(255,255,255,.08);
      border-radius: 999px;
      padding: 1px 8px;
      min-width: 22px;
      text-align: center;
    }
    .dash-pipeline-bar {
      background: rgba(255,255,255,.05);
      border: 1px solid rgba(255,255,255,.07);
      border-radius: 999px;
      height: 10px;
      overflow: hidden;
    }
    .dash-pipeline-bar span {
      display: block;
      height: 100%;
      width: 0;
      background: linear-gradient(90deg, #f4b400, #ffd864);
      border-radius: 999px;
      transition: width .3s ease;
    }
    .dash-pipeline-item[data-pipeline-state="aceptada"] .dash-pipeline-bar span,
    .dash-pipeline-item[data-pipeline-state="pagada"] .dash-pipeline-bar span { background: linear-gradient(90deg, #16a34a, #4ade80); }
    .dash-pipeline-item[data-pipeline-state="pendiente-oc"] .dash-pipeline-bar span,
    .dash-pipeline-item[data-pipeline-state="oc-recepcionada"] .dash-pipeline-bar span { background: linear-gradient(90deg, #2563eb, #60a5fa); }
    .dash-pipeline-item[data-pipeline-state="facturada"] .dash-pipeline-bar span { background: linear-gradient(90deg, #4f46e5, #818cf8); }
    .dash-pipeline-item[data-pipeline-state="rechazada"] .dash-pipeline-bar span { background: linear-gradient(90deg, #dc2626, #f87171); }
    .dash-pipeline-amount {
      font-size: .82rem;
      color: #f8fafc;
      font-weight: 700;
      white-space: nowrap;
      text-align: right;
    }
    [data-pipeline-tone="pendiente"] { background: #f59e0b; box-shadow: 0 0 0 2px rgba(245,158,11,.18); }
    [data-pipeline-tone="aceptada"],
    [data-pipeline-tone="pagada"] { background: #22c55e; box-shadow: 0 0 0 2px rgba(34,197,94,.18); }
    [data-pipeline-tone="pendiente-oc"],
    [data-pipeline-tone="oc-recepcionada"] { background: #3b82f6; box-shadow: 0 0 0 2px rgba(59,130,246,.18); }
    [data-pipeline-tone="facturada"] { background: #6366f1; box-shadow: 0 0 0 2px rgba(99,102,241,.18); }
    [data-pipeline-tone="rechazada"] { background: #ef4444; box-shadow: 0 0 0 2px rgba(239,68,68,.18); }

    .dash-top-clients { grid-area: clients; }
    .dash-clients-list {
      list-style: none;
      counter-reset: clients;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: .42rem;
      flex: 1;
      min-height: 0;
      overflow: hidden;
    }
    .dash-client {
      display: grid;
      grid-template-columns: 32px minmax(0, 1fr);
      gap: .55rem;
      align-items: center;
      background: rgba(11,23,52,.55);
      border: 1px solid rgba(255,255,255,.05);
      border-radius: 10px;
      padding: .42rem .55rem;
    }
    .dash-client-rank {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: .74rem;
      font-weight: 800;
      color: #1f2937;
      background: linear-gradient(180deg, #ffe38b, #e3a900);
      border: 1px solid #8b6500;
    }
    .dash-client-body { display: flex; flex-direction: column; gap: .22rem; min-width: 0; }
    .dash-client-row { display: flex; justify-content: space-between; align-items: baseline; gap: .5rem; }
    .dash-client-name {
      font-size: .85rem;
      color: #f8fafc;
      font-weight: 700;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .dash-client-total { font-size: .82rem; color: #f4b400; font-weight: 700; white-space: nowrap; }
    .dash-client-bar { background: rgba(255,255,255,.05); border-radius: 999px; height: 6px; overflow: hidden; }
    .dash-client-bar span {
      display: block;
      height: 100%;
      background: linear-gradient(90deg, #60a5fa, #c084fc);
      border-radius: 999px;
    }
    .dash-client-foot { display: flex; justify-content: space-between; gap: .5rem; font-size: .7rem; color: #9fb0cf; }

    .dash-plan { grid-area: plan; }
    .dash-plan-pills {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: .45rem;
    }
    .dash-pill {
      border: 1px solid rgba(255,255,255,.07);
      background: rgba(11,23,52,.55);
      border-radius: 10px;
      padding: .42rem .5rem;
      display: flex;
      flex-direction: column;
      gap: .15rem;
    }
    .dash-pill-k { font-size: .68rem; color: #9fb0cf; text-transform: uppercase; letter-spacing: .04em; }
    .dash-pill-v { font-size: .92rem; color: #f8fafc; font-weight: 700; }
    .dash-progress-wrap {
      border: 1px solid #334a7f;
      background: #0b1734;
      border-radius: 999px;
      height: 14px;
      overflow: hidden;
      margin-top: auto;
    }
    .dash-progress-bar {
      height: 100%;
      background: linear-gradient(90deg, #ffe38b, #f4b400);
      width: 0;
      transition: width .3s ease;
    }
    .dash-progress-foot { display: flex; justify-content: space-between; font-size: .74rem; color: #cbd5e1; }
    .dash-plan-renew {
      margin-top: .56rem;
      border: 1px solid rgba(255,255,255,.12);
      border-radius: 10px;
      padding: .5rem .6rem;
      display: grid;
      gap: .12rem;
      font-size: .78rem;
    }
    .dash-plan-renew strong { font-size: .82rem; }
    .dash-plan-renew--ok {
      background: rgba(34,197,94,.12);
      border-color: rgba(34,197,94,.45);
      color: #dcfce7;
    }
    .dash-plan-renew--warn {
      background: rgba(245,158,11,.12);
      border-color: rgba(245,158,11,.45);
      color: #fef3c7;
    }
    .dash-plan-renew--danger {
      background: rgba(239,68,68,.12);
      border-color: rgba(239,68,68,.45);
      color: #fecaca;
    }
    .dash-plan-actions {
      margin-top: .55rem;
      display: flex;
      align-items: center;
      gap: .45rem;
      flex-wrap: wrap;
    }
    .dash-plan-lock {
      font-size: .74rem;
      color: #cbd5e1;
      border: 1px dashed rgba(148,163,184,.55);
      border-radius: 999px;
      padding: .26rem .62rem;
      background: rgba(11,23,52,.45);
    }

    .dash-recent { grid-area: recent; }
    .dash-recent-table { width: 100%; border-collapse: collapse; font-size: .78rem; flex: 1; }
    .dash-recent-table thead th {
      text-align: left;
      font-size: .68rem;
      letter-spacing: .04em;
      text-transform: uppercase;
      color: #9fb0cf;
      padding: .35rem .4rem;
      border-bottom: 1px solid rgba(255,255,255,.08);
    }
    .dash-recent-table tbody td {
      padding: .42rem .4rem;
      border-bottom: 1px dashed rgba(255,255,255,.06);
      color: #e5e7eb;
      vertical-align: middle;
    }
    .dash-recent-table tbody tr:last-child td { border-bottom: 0; }
    .dash-recent-num { font-weight: 700; color: #f4b400; white-space: nowrap; }
    .dash-recent-customer { max-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .dash-recent-amount { text-align: right; font-weight: 700; color: #f8fafc; white-space: nowrap; }
    .dash-state-badge {
      display: inline-block;
      width: auto;
      padding: 2px 9px;
      border-radius: 999px;
      font-size: .7rem;
      font-weight: 700;
      color: #0b1734;
      background: #f4b400;
      box-shadow: none;
    }
    .dash-state-badge[data-pipeline-tone="aceptada"],
    .dash-state-badge[data-pipeline-tone="pagada"] { background: #22c55e; color: #052e16; }
    .dash-state-badge[data-pipeline-tone="pendiente-oc"],
    .dash-state-badge[data-pipeline-tone="oc-recepcionada"] { background: #3b82f6; color: #0b1734; }
    .dash-state-badge[data-pipeline-tone="facturada"] { background: #6366f1; color: #fff; }
    .dash-state-badge[data-pipeline-tone="rechazada"] { background: #ef4444; color: #450a0a; }
    .dash-state-badge[data-pipeline-tone="pendiente"] { background: #f59e0b; color: #1f1306; }

    @media (max-width: 1180px) {
      body.module-dashboard { height: auto; overflow: auto; }
      body.module-dashboard .content { height: auto; overflow: visible; }
      .dashboard-grid {
        grid-template-columns: 1fr;
        grid-template-rows: auto auto auto auto auto;
        grid-template-areas:
          "kpis"
          "pipeline"
          "clients"
          "plan"
          "recent";
      }
      .dash-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 640px) {
      .dash-kpis { grid-template-columns: 1fr; }
      .dash-plan-pills { grid-template-columns: 1fr; }
      .dash-pipeline-item { grid-template-columns: 1fr; }
      .dash-pipeline-amount { text-align: left; }
    }

    .module-empresa { min-height: 100vh; }
    .module-empresa .panel.compact {
      min-height: calc(100vh - 210px);
      height: auto;
      margin-bottom: 0;
      padding: .66rem .7rem;
    }
    .module-empresa .empresa-workspace {
      display: grid;
      grid-template-columns: minmax(280px, 33%) minmax(0, 1fr);
      gap: .62rem;
      min-height: 0;
      height: 100%;
    }
    .module-empresa .empresa-fields {
      min-height: 0;
      display: grid;
      grid-template-rows: 1fr auto;
      gap: .45rem;
    }
    .module-empresa .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: .4rem .52rem;
      align-content: start;
      min-height: 0;
    }
    .module-empresa .field { display: grid; gap: .2rem; }
    .module-empresa .field label { font-size: .72rem; color: #cbd5e1; }
    .module-empresa .field input,
    .module-empresa .field select,
    .module-empresa .field textarea {
      border: 1px solid #334a7f;
      border-radius: 8px;
      background: #0b1734;
      color: #e5e7eb;
      padding: .36rem .46rem;
      min-height: 31px;
      height: 31px;
      font-size: .79rem;
      width: 100%;
    }
    .module-empresa .field textarea.compact-line { resize: none; overflow: hidden; }
    .module-empresa .field.full { grid-column: span 3; }

    .module-empresa .empresa-logo-bar {
      border: 1px solid #2a3f6e;
      border-radius: 10px;
      background: rgba(8,18,40,.78);
      padding: .56rem;
      display: grid;
      grid-template-rows: auto 1fr auto;
      gap: .45rem;
      align-items: stretch;
      min-height: 0;
    }
    .module-empresa .logo-thumb {
      width: 100%;
      height: clamp(180px, 35vh, 320px);
      border-radius: 8px;
      border: 1px solid #38548b;
      background: #0b1734;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #b0bdd8;
      font-size: .72rem;
      text-align: center;
      overflow: hidden;
    }
    .module-empresa .logo-thumb img { width: 100%; height: 100%; object-fit: contain; display: block; }
    .module-empresa .logo-meta {
      border: 1px solid #243a69;
      border-radius: 8px;
      padding: .42rem .46rem;
      background: rgba(10,22,49,.72);
    }
    .module-empresa .logo-title { margin: 0 0 .18rem; font-size: .82rem; color: #e5e7eb; font-weight: 700; }
    .module-empresa .logo-help { margin: 0; font-size: .73rem; color: #9fb0cf; }
    .module-empresa .logo-tools { display: grid; gap: .34rem; }
    .module-empresa .logo-tools input[type="file"] {
      min-height: 34px;
      height: 34px;
    }
    .module-empresa .btn.logo-upload-btn { padding: .42rem .64rem; font-size: .75rem; white-space: nowrap; }
    .module-empresa .compact-actions {
      margin-top: 0;
      display: flex;
      justify-content: flex-end;
      align-items: center;
      gap: .5rem;
      border-top: 1px solid #243a69;
      padding-top: .45rem;
    }
    .module-empresa .compact-actions .btn { padding: .46rem .72rem; font-size: .8rem; }

    .progress-wrap {
      border: 1px solid #334a7f;
      background: #0b1734;
      border-radius: 999px;
      height: 16px;
      overflow: hidden;
    }
    .progress-bar {
      height: 100%;
      background: linear-gradient(90deg, #ffe38b, #f4b400);
      width: 0;
    }
    .cards {
      display: grid;
      grid-template-columns: repeat(3, minmax(180px, 1fr));
      gap: .7rem;
      margin: .8rem 0;
    }
    .card {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: rgba(10,20,44,.7);
      padding: .68rem;
    }
    .card .k { color: var(--muted); font-size: .8rem; margin-bottom: .24rem; }
    .card .v { color: #fff; font-size: 1.02rem; font-weight: 700; }

    table {
      width: 100%;
      border-collapse: collapse;
      border: 1px solid #334a7f;
      border-radius: 10px;
      overflow: hidden;
      background: #0b1734;
    }
    th, td {
      padding: .55rem .5rem;
      border-bottom: 1px solid #1f315a;
      text-align: left;
      font-size: .85rem;
      vertical-align: top;
    }
    th { color: #cbd5e1; font-weight: 700; }
    td { color: #e2e8f0; }

    .clientes-toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: .7rem;
      margin-bottom: .85rem;
      flex-wrap: wrap;
    }
    .clientes-count {
      border: 1px solid #334a7f;
      border-radius: 999px;
      padding: .26rem .68rem;
      color: #c3d1ea;
      font-size: .82rem;
      background: rgba(11,23,52,.68);
    }
    .clientes-table-wrap {
      border: 1px solid #334a7f;
      border-radius: 12px;
      overflow: hidden;
      background: #0b1734;
    }
    .clientes-table-wrap table { border: 0; border-radius: 0; }
    .clientes-table-wrap tbody tr:nth-child(odd) { background: rgba(15,30,62,.44); }
    .clientes-table-wrap tbody tr:hover { background: rgba(34,64,116,.33); }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(3,8,19,.74);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 90;
      padding: 1rem;
      backdrop-filter: blur(2px);
    }
    .modal-backdrop.open { display: flex; }
    .modal-card {
      width: min(980px, 100%);
      max-height: calc(100vh - 2rem);
      overflow: auto;
      border: 1px solid #33528f;
      border-radius: 14px;
      background: linear-gradient(180deg, #0f1f41, #0a1732);
      box-shadow: 0 26px 60px rgba(2,8,23,.55);
    }
    .modal-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: .75rem;
      padding: .8rem .92rem;
      border-bottom: 1px solid #2f4678;
      position: sticky;
      top: 0;
      background: rgba(12,25,54,.94);
      z-index: 2;
    }
    .modal-head h3 { margin: 0; color: #fff4b8; }
    .modal-body { padding: .9rem; }
    .clientes-form-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(240px, 1fr));
      gap: .72rem;
    }
    .clientes-form-grid .field {
      display: grid;
      gap: .28rem;
    }
    .clientes-form-grid .field label {
      font-size: .8rem;
      color: #c8d7ef;
    }
    .clientes-form-grid .field input,
    .clientes-form-grid .field textarea {
      border: 1px solid #33528f;
      border-radius: 9px;
      background: #0b1734;
      color: #e5e7eb;
      min-height: 38px;
      padding: .45rem .52rem;
      font-size: .86rem;
      width: 100%;
    }
    .clientes-form-grid .field.full {
      grid-column: 1 / -1;
    }
    .clientes-form-grid textarea {
      min-height: 96px;
      resize: vertical;
    }
    .modal-actions {
      display: flex;
      justify-content: flex-end;
      align-items: center;
      gap: .6rem;
      margin-top: .9rem;
      border-top: 1px solid #2f4678;
      padding-top: .75rem;
    }

    .cotizaciones-toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: .7rem;
      flex-wrap: wrap;
      margin-bottom: .8rem;
    }
    .cotizaciones-toolbar-right {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: .5rem;
      flex-wrap: wrap;
    }
    .cotizaciones-filters {
      display: inline-flex;
      align-items: center;
      justify-content: flex-end;
      gap: .4rem;
      flex-wrap: wrap;
      padding: .34rem;
      border: 1px solid #2f4678;
      border-radius: 11px;
      background: linear-gradient(180deg, rgba(11,23,52,.92), rgba(8,18,41,.92));
      box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
    }
    .cotizaciones-filters input,
    .cotizaciones-filters select {
      border: 1px solid #33528f;
      border-radius: 8px;
      background: #0b1734;
      color: #e5e7eb;
      min-height: 34px;
      padding: .35rem .48rem;
      font-size: .82rem;
      transition: border-color .15s ease, box-shadow .15s ease, background .15s ease;
    }
    .cotizaciones-filters input::placeholder {
      color: #9fb0cf;
    }
    .cotizaciones-filters input:focus,
    .cotizaciones-filters select:focus {
      border-color: #ffdf7c;
      box-shadow: 0 0 0 2px rgba(255,223,124,.2);
      background: #0e1d42;
      outline: none;
    }
    .cotizaciones-filters input {
      width: min(250px, 45vw);
      min-width: 170px;
    }
    .cotizaciones-filters select {
      min-width: 145px;
      max-width: 220px;
    }
    .cotizaciones-visible-count {
      font-size: .76rem;
      color: #9fb0cf;
      white-space: nowrap;
    }
    .quote-filter-empty {
      text-align: center;
      color: #9fb0cf;
      font-style: italic;
      background: rgba(11, 23, 52, .35);
    }
    .quote-state-form {
      margin: 0;
    }
    .quote-state-select {
      min-height: 30px;
      border-radius: 999px;
      border: 1px solid #35558f;
      padding: .18rem .62rem;
      font-size: .77rem;
      font-weight: 700;
      letter-spacing: .01em;
      cursor: pointer;
      outline: none;
    }
    .quote-state-select[data-state-tone="pendiente"] {
      background: #fff7ed;
      border-color: #fdba74;
      color: #9a3412;
    }
    .quote-state-select[data-state-tone="aceptada"],
    .quote-state-select[data-state-tone="pagada"] {
      background: #ecfdf3;
      border-color: #86efac;
      color: #166534;
    }
    .quote-state-select[data-state-tone="pendiente-oc"],
    .quote-state-select[data-state-tone="oc-recepcionada"] {
      background: #eff6ff;
      border-color: #93c5fd;
      color: #1e40af;
    }
    .quote-state-select[data-state-tone="facturada"] {
      background: #eef2ff;
      border-color: #a5b4fc;
      color: #4338ca;
    }
    .quote-state-select[data-state-tone="rechazada"] {
      background: #fef2f2;
      border-color: #fca5a5;
      color: #b91c1c;
    }
    .quote-action-cell {
      white-space: nowrap;
      text-align: center;
      vertical-align: middle;
      padding-top: .45rem;
      padding-bottom: .45rem;
    }
    .action-icons {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: .36rem;
      flex-wrap: nowrap;
    }
    .icon-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 33px;
      height: 33px;
      border-radius: 9px;
      border: 1px solid #35558f;
      background: linear-gradient(180deg, #163166, #11264f);
      color: #eaf2ff;
      line-height: 1;
      padding: 0;
      cursor: pointer;
      transition: transform .15s ease, border-color .15s ease, background .15s ease;
      text-decoration: none;
    }
    .icon-btn svg {
      width: 16px;
      height: 16px;
      stroke: currentColor;
      fill: none;
      stroke-width: 1.9;
      stroke-linecap: round;
      stroke-linejoin: round;
      pointer-events: none;
    }
    .icon-btn:hover {
      border-color: #ffdf7c;
      transform: translateY(-1px);
    }
    .icon-btn:active {
      transform: translateY(0);
    }
    .icon-btn.danger {
      background: linear-gradient(180deg, #5b1a2a, #3b101b);
      border-color: #8f3450;
      color: #ffd6de;
    }
    .icon-btn.danger:hover {
      border-color: #ff8fab;
    }
    .icon-btn.pdf {
      background: linear-gradient(180deg, #254676, #17345f);
    }
    .icon-btn.edit {
      background: linear-gradient(180deg, #1f4d5a, #153a44);
    }
    .delete-confirm-card {
      width: min(460px, 100%);
      border: 1px solid #33528f;
      border-radius: 14px;
      background: linear-gradient(180deg, #0f1f41, #0a1732);
      box-shadow: 0 26px 60px rgba(2,8,23,.55);
    }
    .delete-confirm-body {
      padding: .95rem;
      display: grid;
      gap: .72rem;
    }
    .delete-confirm-text {
      margin: 0;
      color: #d8e3f8;
      font-size: .88rem;
      line-height: 1.35;
    }
    .delete-confirm-code {
      border: 1px solid #33528f;
      border-radius: 9px;
      background: #0b1734;
      color: #e5e7eb;
      min-height: 38px;
      padding: .45rem .52rem;
      font-size: .86rem;
      width: 100%;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .quote-preview-card {
      width: min(980px, 100%);
      max-height: calc(100vh - 2rem);
      overflow: hidden;
      border: 1px solid #33528f;
      border-radius: 14px;
      background: linear-gradient(180deg, #0f1f41, #0a1732);
      box-shadow: 0 26px 60px rgba(2,8,23,.55);
      display: grid;
      grid-template-rows: auto 1fr;
    }
    .quote-preview-body {
      padding: .9rem;
      min-height: min(78vh, 820px);
    }
    .quote-preview-frame {
      width: 100%;
      height: 100%;
      border: 1px solid #2f4678;
      border-radius: 10px;
      background: #0b1734;
    }
    .quote-preview-empty {
      margin: 0;
      color: #c8d7ef;
      font-size: .84rem;
    }
    .quote-form-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(130px, 1fr));
      gap: .7rem;
    }
    .quote-form-grid .field {
      display: grid;
      gap: .28rem;
    }
    .quote-form-grid .field label {
      font-size: .8rem;
      color: #c8d7ef;
    }
    .quote-form-grid .field input,
    .quote-form-grid .field select,
    .quote-form-grid .field textarea {
      border: 1px solid #33528f;
      border-radius: 9px;
      background: #0b1734;
      color: #e5e7eb;
      min-height: 38px;
      padding: .45rem .52rem;
      font-size: .86rem;
      width: 100%;
    }
    .quote-form-grid .field.full {
      grid-column: 1 / -1;
    }
    .quote-form-grid textarea {
      min-height: 90px;
      resize: vertical;
    }
    .quote-items-wrap {
      border: 1px solid #334a7f;
      border-radius: 10px;
      overflow: hidden;
      background: #0b1734;
      margin-top: .7rem;
    }
    .quote-items-wrap table { border: 0; border-radius: 0; }
    .quote-items-wrap td { vertical-align: middle; }
    .quote-items-wrap input[type="text"],
    .quote-items-wrap input[type="number"] {
      border: 1px solid #34528c;
      border-radius: 8px;
      background: #081229;
      color: #e5e7eb;
      width: 100%;
      min-height: 34px;
      padding: .34rem .42rem;
      font-size: .83rem;
    }
    .quote-items-wrap .line-total {
      font-weight: 700;
      white-space: nowrap;
    }
    .quote-summary {
      margin-top: .65rem;
      display: flex;
      justify-content: flex-end;
      gap: .9rem;
      flex-wrap: wrap;
      color: #d8e3f8;
    }
    .quote-summary strong { color: #fff4b8; }

    @media (max-width: 980px) {
      .module-empresa { height: auto; overflow: auto; }
      .module-empresa .content { height: auto; overflow: visible; padding: 1.1rem; }
      .module-empresa .panel.compact { height: auto; }
      .module-empresa .empresa-workspace { display: block; height: auto; }
      .module-empresa .empresa-logo-bar { margin-bottom: .68rem; }
      .module-empresa .empresa-fields { display: block; }
      .module-empresa .grid { grid-template-columns: 1fr; }
      .module-empresa .field.full { grid-column: 1 / -1; }
      .module-empresa .field textarea.compact-line { min-height: 86px; height: auto; overflow: auto; resize: vertical; }
      .module-empresa .compact-actions { border-top: 0; padding-top: .7rem; justify-content: flex-start; }

      .layout { grid-template-columns: 1fr; }
      .side { border-right: 0; border-bottom: 1px solid var(--line); }
      .cards { grid-template-columns: 1fr; }
      .clientes-form-grid { grid-template-columns: 1fr; }
      .quote-form-grid { grid-template-columns: 1fr; }
      .modal-actions { justify-content: flex-start; }
      .cotizaciones-toolbar-right { width: 100%; justify-content: flex-start; }
      .cotizaciones-filters { justify-content: flex-start; }
    }
  </style>
</head>
<body class="<?= h($bodyClass) ?>">
  <div class="layout">
    <aside class="side">
      <div class="brand"><?php readfile(__DIR__ . '/assets/img/logo-hermes-page.svg'); ?></div>
      <nav class="menu" aria-label="Modulos empresa">
        <a class="<?= $module === 'dashboard' ? 'active' : '' ?>" href="/empresa/dashboard/?module=dashboard">
          <span>Dashboard</span>
          <span class="nav-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16"><path d="M2.5 2.5h4.5v4.5H2.5zM9 2.5h4.5v2.5H9zM9 7h4.5V13.5H9zM2.5 9h4.5v4.5H2.5z"/></svg>
          </span>
        </a>
        <a class="<?= $module === 'empresa' ? 'active' : '' ?>" href="/empresa/dashboard/?module=empresa">
          <span>Empresa</span>
          <span class="nav-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16"><path d="M2.5 13.5h11M3.5 13.5V4.5l4.5-2 4.5 2v9M6 6.5h.01M10 6.5h.01M6 9h.01M10 9h.01"/></svg>
          </span>
        </a>
        <a class="<?= $module === 'clientes' ? 'active' : '' ?>" href="/empresa/dashboard/?module=clientes">
          <span>Clientes</span>
          <span class="nav-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16"><path d="M5.2 7a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM10.8 7a1.7 1.7 0 1 0 0-3.4 1.7 1.7 0 0 0 0 3.4ZM2.5 13.5v-1c0-1.5 1.2-2.7 2.7-2.7h0c1.5 0 2.8 1.2 2.8 2.7v1M8.8 13.5v-.8c0-1.2 1-2.2 2.2-2.2h0c1.2 0 2.2 1 2.2 2.2v.8"/></svg>
          </span>
        </a>
        <a class="<?= $module === 'cotizaciones' ? 'active' : '' ?>" href="/empresa/dashboard/?module=cotizaciones">
          <span>Cotizaciones</span>
          <span class="nav-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16"><path d="M4 2.5h6l2 2V13.5H4zM10 2.5V5h2M6 7h4M6 9.5h4M6 12h3"/></svg>
          </span>
        </a>
      </nav>
    </aside>

    <main class="content">
      <div class="top">
        <h1>Panel empresa - Plan Basico</h1>
        <div class="actions">
          <a class="btn" href="/">Ir a HERMES</a>
          <form method="post" style="margin:0;">
            <input type="hidden" name="logout" value="1">
            <button class="btn" type="submit">Cerrar sesion</button>
          </form>
        </div>
      </div>

      <div id="appMain">

      <?php if ($flash['ok'] !== ''): ?>
        <div class="msg-ok"><?= h($flash['ok']) ?></div>
      <?php endif; ?>
      <?php if ($flash['error'] !== ''): ?>
        <div class="msg-err"><?= h($flash['error']) ?></div>
      <?php endif; ?>

      <?php if ($module === 'dashboard'): ?>
        <section class="dashboard-grid" aria-label="Resumen ejecutivo">
          <div class="dash-kpis">
            <div class="dash-kpi dash-kpi--quotes">
              <span class="dash-kpi-icon" aria-hidden="true">&#9776;</span>
              <div class="dash-kpi-body">
                <div class="dash-kpi-label">Cotizaciones emitidas</div>
                <div class="dash-kpi-value"><?= h((string)$dashTotalQuotes) ?></div>
                <div class="dash-kpi-foot"><?= h((string)$dashCustomersTotal) ?> clientes activos</div>
              </div>
            </div>
            <div class="dash-kpi dash-kpi--amount">
              <span class="dash-kpi-icon" aria-hidden="true">&#36;</span>
              <div class="dash-kpi-body">
                <div class="dash-kpi-label">Monto cotizado (<?= h($dashCurrencyCode) ?>)</div>
                <div class="dash-kpi-value">$<?= h(money_clp($dashTotalAmount)) ?></div>
                <div class="dash-kpi-foot">Suma de todas las cotizaciones</div>
              </div>
            </div>
            <div class="dash-kpi dash-kpi--accepted">
              <span class="dash-kpi-icon" aria-hidden="true">&#10003;</span>
              <div class="dash-kpi-body">
                <div class="dash-kpi-label">Aceptado / en proceso</div>
                <div class="dash-kpi-value">$<?= h(money_clp($dashAcceptedAmount)) ?></div>
                <div class="dash-kpi-foot"><?= h((string)$dashAcceptedCount) ?> cotizaciones avanzando</div>
              </div>
            </div>
            <div class="dash-kpi dash-kpi--conv">
              <span class="dash-kpi-icon" aria-hidden="true">&#8593;</span>
              <div class="dash-kpi-body">
                <div class="dash-kpi-label">Tasa de conversion</div>
                <div class="dash-kpi-value"><?= h((string)$dashConversionRate) ?>%</div>
                <div class="dash-kpi-foot">Pendiente: $<?= h(money_clp($dashPendingAmount)) ?></div>
              </div>
            </div>
          </div>

          <section class="dash-panel dash-pipeline">
            <header class="dash-panel-head">
              <h2>Pipeline por estado</h2>
              <span class="dash-panel-sub">Distribucion en CLP del flujo comercial</span>
            </header>
            <ul class="dash-pipeline-list">
              <?php foreach ($dashStatusCatalog as $pipeStatus): ?>
                <?php
                  $pipeRow = $dashStatusTotals[$pipeStatus] ?? ['count' => 0, 'amount' => 0.0];
                  $pipeAmount = (float)$pipeRow['amount'];
                  $pipeCount = (int)$pipeRow['count'];
                  $pipePct = ($dashMaxStatusAmount > 0) ? max(2, (int)round(($pipeAmount / $dashMaxStatusAmount) * 100)) : 0;
                  $pipeToken = strtolower(str_replace(' ', '-', $pipeStatus));
                ?>
                <li class="dash-pipeline-item" data-pipeline-state="<?= h($pipeToken) ?>">
                  <div class="dash-pipeline-meta">
                    <span class="dash-pipeline-dot" data-pipeline-tone="<?= h($pipeToken) ?>"></span>
                    <span class="dash-pipeline-name"><?= h($pipeStatus) ?></span>
                    <span class="dash-pipeline-count"><?= h((string)$pipeCount) ?></span>
                  </div>
                  <div class="dash-pipeline-bar"><span style="width: <?= h((string)$pipePct) ?>%;"></span></div>
                  <div class="dash-pipeline-amount">$<?= h(money_clp($pipeAmount)) ?></div>
                </li>
              <?php endforeach; ?>
            </ul>
          </section>

          <section class="dash-panel dash-top-clients">
            <header class="dash-panel-head">
              <h2>Top clientes</h2>
              <span class="dash-panel-sub">Por monto cotizado acumulado</span>
            </header>
            <?php if (empty($dashTopClients)): ?>
              <div class="dash-empty">Aun no hay cotizaciones cargadas para mostrar el ranking de clientes.</div>
            <?php else: ?>
              <ol class="dash-clients-list">
                <?php foreach ($dashTopClients as $ix => $clientRow): ?>
                  <?php
                    $clientPct = ($dashMaxClientAmount > 0) ? max(2, (int)round(((float)$clientRow['amount'] / $dashMaxClientAmount) * 100)) : 0;
                  ?>
                  <li class="dash-client">
                    <div class="dash-client-rank">#<?= h((string)($ix + 1)) ?></div>
                    <div class="dash-client-body">
                      <div class="dash-client-row">
                        <span class="dash-client-name"><?= h($clientRow['customer_name']) ?></span>
                        <span class="dash-client-total">$<?= h(money_clp((float)$clientRow['amount'])) ?></span>
                      </div>
                      <div class="dash-client-bar"><span style="width: <?= h((string)$clientPct) ?>%;"></span></div>
                      <div class="dash-client-foot">
                        <span><?= h((string)$clientRow['count']) ?> cotizaciones</span>
                        <span>Aceptado: $<?= h(money_clp((float)$clientRow['accepted_amount'])) ?></span>
                      </div>
                    </div>
                  </li>
                <?php endforeach; ?>
              </ol>
            <?php endif; ?>
          </section>

          <section class="dash-panel dash-plan">
            <header class="dash-panel-head">
              <h2>Plan y almacenamiento</h2>
              <span class="dash-panel-sub">Consumo del plan activo de HERMES</span>
            </header>
            <div class="dash-plan-pills">
              <div class="dash-pill">
                <span class="dash-pill-k">Plan</span>
                <span class="dash-pill-v"><?= h(ucwords(str_replace('_', ' ', $usage['plan_code']))) ?></span>
              </div>
              <div class="dash-pill">
                <span class="dash-pill-k">Usado</span>
                <span class="dash-pill-v"><?= h((string)$usage['storage_used_mb']) ?> MB</span>
              </div>
              <div class="dash-pill">
                <span class="dash-pill-k">Limite</span>
                <span class="dash-pill-v"><?= h((string)$usage['storage_limit_mb']) ?> MB</span>
              </div>
              <div class="dash-pill">
                <span class="dash-pill-k">Estado pago</span>
                <span class="dash-pill-v"><?= h($planBilling['payment_status'] === 'paid' ? 'Pagado' : 'Pendiente') ?></span>
              </div>
              <div class="dash-pill">
                <span class="dash-pill-k">Modalidad</span>
                <span class="dash-pill-v"><?= h($planBilling['billing_cycle_name']) ?></span>
              </div>
              <div class="dash-pill">
                <span class="dash-pill-k">Renovacion</span>
                <span class="dash-pill-v"><?= h($planBilling['next_renewal_label']) ?></span>
              </div>
            </div>
            <div class="dash-progress-wrap">
              <div class="dash-progress-bar" style="width: <?= h((string)$usage['percent']) ?>%;"></div>
            </div>
            <div class="dash-progress-foot">
              <span><strong><?= h((string)$usage['percent']) ?>%</strong> consumido</span>
              <span>Disponible: <?= h((string)max(0, (int)$usage['storage_limit_mb'] - (int)$usage['storage_used_mb'])) ?> MB</span>
            </div>
            <div class="dash-plan-renew dash-plan-renew--<?= h($planBilling['notice_tone']) ?>">
              <strong><?= h($planBilling['notice_title']) ?></strong>
              <span><?= h($planBilling['notice_text']) ?></span>
            </div>
            <div class="dash-plan-actions">
              <?php if ($planBilling['can_pay_renewal']): ?>
                <a class="dash-panel-link" href="<?= h($planBilling['payment_url']) ?>">Pagar renovacion</a>
              <?php else: ?>
                <span class="dash-plan-lock">Pago bloqueado para evitar duplicidad mientras la cuenta este al dia.</span>
              <?php endif; ?>
            </div>
          </section>

          <section class="dash-panel dash-recent">
            <header class="dash-panel-head">
              <h2>Ultimas cotizaciones</h2>
              <a class="dash-panel-link" href="<?= h(dashboard_module_url('cotizaciones')) ?>">Ver todas</a>
            </header>
            <?php if (empty($dashRecentQuotes)): ?>
              <div class="dash-empty">Aun no hay cotizaciones registradas.</div>
            <?php else: ?>
              <table class="dash-recent-table">
                <thead>
                  <tr>
                    <th>Numero</th>
                    <th>Cliente</th>
                    <th>Estado</th>
                    <th class="dash-recent-amount">Total</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($dashRecentQuotes as $recentRow): ?>
                    <?php $recentToken = strtolower(str_replace(' ', '-', (string)$recentRow['estado'])); ?>
                    <tr>
                      <td class="dash-recent-num"><?= h($recentRow['numero_cotizacion']) ?></td>
                      <td class="dash-recent-customer"><?= h($recentRow['customer_name']) ?></td>
                      <td><span class="dash-state-badge" data-pipeline-tone="<?= h($recentToken) ?>"><?= h($recentRow['estado']) ?></span></td>
                      <td class="dash-recent-amount">$<?= h(money_clp((float)$recentRow['total'])) ?></td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            <?php endif; ?>
          </section>
        </section>
      <?php endif; ?>

      <?php if ($module === 'empresa'): ?>
        <section class="panel compact">
          <form method="post" enctype="multipart/form-data">
            <div class="empresa-workspace">
              <div class="empresa-logo-bar">
                <div class="logo-thumb">
                  <?php if ($logoPublicUrl !== ''): ?>
                    <img src="<?= h($logoPublicUrl) ?>" alt="Logo de empresa">
                  <?php else: ?>
                    Sin logo
                  <?php endif; ?>
                </div>
                <div class="logo-meta">
                  <p class="logo-title">Logo de empresa</p>
                  <p class="logo-help">Carga JPG, PNG o WEBP (max 4MB). Se usa en cotizaciones y documentos.</p>
                </div>
                <div class="logo-tools">
                  <input type="file" name="logo" accept="image/jpeg,image/png,image/webp">
                  <button class="btn logo-upload-btn" type="submit" name="action" value="save_company_logo" formnovalidate>Subir logo</button>
                </div>
              </div>

              <div class="empresa-fields">
                <div class="grid">
                  <div class="field">
                    <label>Nombre empresa</label>
                    <input type="text" name="nombre" value="<?= h($profile['nombre']) ?>" required>
                  </div>
                  <div class="field">
                    <label>RUT</label>
                    <input type="text" name="rut" value="<?= h($profile['rut']) ?>" required>
                  </div>
                  <div class="field">
                    <label>Email principal</label>
                    <input type="email" name="email_principal" value="<?= h($profile['email_principal']) ?>" required>
                  </div>
                  <div class="field full">
                    <label>Direccion</label>
                    <input type="text" name="direccion" value="<?= h($profile['direccion']) ?>" required>
                  </div>
                  <div class="field">
                    <label>Telefono principal</label>
                    <input type="text" name="telefono" value="<?= h($profile['telefono']) ?>">
                  </div>
                  <div class="field">
                    <label>Celular</label>
                    <input type="text" name="celular" value="<?= h($profile['celular']) ?>">
                  </div>
                  <div class="field">
                    <label>Sitio web</label>
                    <input type="text" name="sitio_web" value="<?= h($profile['sitio_web']) ?>">
                  </div>
                  <div class="field">
                    <label>Moneda</label>
                    <select name="moneda">
                      <option value="CLP" <?= $profile['moneda'] === 'CLP' ? 'selected' : '' ?>>CLP</option>
                      <option value="USD" <?= $profile['moneda'] === 'USD' ? 'selected' : '' ?>>USD</option>
                      <option value="EUR" <?= $profile['moneda'] === 'EUR' ? 'selected' : '' ?>>EUR</option>
                    </select>
                  </div>
                  <div class="field">
                    <label>Contacto principal</label>
                    <input type="text" name="contacto_principal_nombre" value="<?= h($profile['contacto_principal_nombre']) ?>">
                  </div>
                  <div class="field">
                    <label>Cargo contacto</label>
                    <input type="text" name="contacto_principal_cargo" value="<?= h($profile['contacto_principal_cargo']) ?>">
                  </div>
                  <div class="field full">
                    <label>Condicion de pago</label>
                    <textarea class="compact-line" name="condicion_de_pago"><?= h($profile['condicion_de_pago']) ?></textarea>
                  </div>
                  <div class="field full">
                    <label>Entrega</label>
                    <textarea class="compact-line" name="entrega"><?= h($profile['entrega']) ?></textarea>
                  </div>
                  <div class="field full">
                    <label>Validez</label>
                    <textarea class="compact-line" name="validez"><?= h($profile['validez']) ?></textarea>
                  </div>
                  <div class="field full">
                    <label>Notas internas</label>
                    <textarea class="compact-line" name="notas_internas"><?= h($profile['notas_internas']) ?></textarea>
                  </div>
                </div>
                <div class="compact-actions">
                  <button class="btn" type="submit" name="action" value="save_company_profile">Guardar datos de empresa</button>
                </div>
              </div>
            </div>
          </form>
        </section>
      <?php endif; ?>

      <?php if ($module === 'clientes'): ?>
        <?php $isCustomerEdit = (int)($customerForm['id'] ?? 0) > 0; ?>
        <section class="panel">
          <div class="clientes-toolbar">
            <h2 style="margin:0;">Clientes</h2>
            <div style="display:flex; gap:.5rem; align-items:center;">
              <span class="clientes-count">Total: <?= h((string)count($customers)) ?></span>
              <button class="btn primary" type="button" data-open-customer-modal="1">Nuevo cliente</button>
            </div>
          </div>
          <p class="muted" style="margin:0;">Cada nuevo cliente se guarda inmediatamente y aparece en la lista al cerrar el modal.</p>
        </section>

        <section class="panel">
          <h3>Listado de clientes</h3>
          <?php if (empty($customers)): ?>
            <p class="muted">Aun no tienes clientes registrados.</p>
          <?php else: ?>
            <div class="clientes-table-wrap" style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>RUT</th><th>Razon social</th><th>Contacto</th><th>Email</th><th>Ciudad</th><th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($customers as $customer): ?>
                    <tr>
                      <td><?= h($customer['rut']) ?></td>
                      <td><?= h($customer['razon_social']) ?><?php if ((string)$customer['nombre_fantasia'] !== ''): ?><div class="muted"><?= h($customer['nombre_fantasia']) ?></div><?php endif; ?></td>
                      <td><?= h($customer['contacto']) ?></td>
                      <td><?= h($customer['email']) ?></td>
                      <td><?= h(trim((string)$customer['comuna'] . ' ' . (string)$customer['ciudad'])) ?></td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Editar cliente"
                            aria-label="Editar cliente"
                            data-edit-customer="1"
                            data-customer-id="<?= h((string)$customer['id']) ?>"
                            data-customer-rut="<?= h((string)$customer['rut']) ?>"
                            data-customer-razon-social="<?= h((string)$customer['razon_social']) ?>"
                            data-customer-nombre-fantasia="<?= h((string)$customer['nombre_fantasia']) ?>"
                            data-customer-direccion="<?= h((string)$customer['direccion']) ?>"
                            data-customer-comuna="<?= h((string)$customer['comuna']) ?>"
                            data-customer-ciudad="<?= h((string)$customer['ciudad']) ?>"
                            data-customer-telefono="<?= h((string)$customer['telefono']) ?>"
                            data-customer-celular="<?= h((string)$customer['celular']) ?>"
                            data-customer-email="<?= h((string)$customer['email']) ?>"
                            data-customer-contacto="<?= h((string)$customer['contacto']) ?>"
                            data-customer-notas="<?= h((string)$customer['notas_internas']) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M13.5 3.5l3 3M4 16h3l9-9-3-3-9 9v3z"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Eliminar cliente"
                            aria-label="Eliminar cliente"
                            data-open-delete-confirm="1"
                            data-delete-action="delete_customer"
                            data-delete-id-field="customer_id"
                            data-delete-id-value="<?= h((string)$customer['id']) ?>"
                            data-delete-entity="cliente"
                            data-delete-description="<?= h((string)$customer['razon_social']) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3.5 5.5h13M8 5.5V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M6 5.5l.7 10.5h6.6L14 5.5M8.7 8v5.5M11.3 8v5.5"/></svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php endif; ?>
        </section>

        <div class="modal-backdrop<?= $openCustomerModal ? ' open' : '' ?>" id="customerModal" aria-hidden="<?= $openCustomerModal ? 'false' : 'true' ?>">
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="customerModalTitle">
            <div class="modal-head">
              <h3 id="customerModalTitle"><?= $isCustomerEdit ? 'Editar cliente' : 'Nuevo cliente' ?></h3>
              <button class="btn" type="button" data-close-customer-modal="1">Cerrar</button>
            </div>
            <div class="modal-body">
              <form method="post" id="customerModalForm">
                <input type="hidden" name="action" value="<?= $isCustomerEdit ? 'update_customer' : 'add_customer' ?>" data-customer-action="1">
                <input type="hidden" name="customer_id" value="<?= h((string)($customerForm['id'] ?? '')) ?>" data-customer-id="1">
                <div class="clientes-form-grid">
                  <div class="field"><label>RUT cliente</label><input type="text" name="rut" value="<?= h($customerForm['rut']) ?>" required></div>
                  <div class="field"><label>Razon social</label><input type="text" name="razon_social" value="<?= h($customerForm['razon_social']) ?>" required></div>
                  <div class="field"><label>Nombre fantasia</label><input type="text" name="nombre_fantasia" value="<?= h($customerForm['nombre_fantasia']) ?>"></div>
                  <div class="field"><label>Direccion</label><input type="text" name="direccion" value="<?= h($customerForm['direccion']) ?>" required></div>
                  <div class="field"><label>Comuna</label><input type="text" name="comuna" value="<?= h($customerForm['comuna']) ?>"></div>
                  <div class="field"><label>Ciudad</label><input type="text" name="ciudad" value="<?= h($customerForm['ciudad']) ?>"></div>
                  <div class="field"><label>Telefono</label><input type="text" name="telefono" value="<?= h($customerForm['telefono']) ?>"></div>
                  <div class="field"><label>Celular</label><input type="text" name="celular" value="<?= h($customerForm['celular']) ?>"></div>
                  <div class="field"><label>Email</label><input type="email" name="email" value="<?= h($customerForm['email']) ?>"></div>
                  <div class="field"><label>Contacto</label><input type="text" name="contacto" value="<?= h($customerForm['contacto']) ?>"></div>
                  <div class="field full"><label>Notas internas</label><textarea name="notas_internas"><?= h($customerForm['notas_internas']) ?></textarea></div>
                </div>
                <div class="modal-actions">
                  <button class="btn" type="button" data-close-customer-modal="1">Cancelar</button>
                  <button class="btn primary" type="submit" data-customer-submit-label="1"><?= $isCustomerEdit ? 'Actualizar cliente' : 'Guardar cliente' ?></button>
                </div>
              </form>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($module === 'cotizaciones'): ?>
        <?php
          $isQuoteEdit = (int)($quoteForm['id'] ?? 0) > 0;
          $quoteStatuses = quote_statuses();
          $quoteModalSubtotal = 0.0;
          foreach ($quoteForm['items'] as $modalItem) {
              $q = (float)str_replace(',', '.', (string)($modalItem['cantidad'] ?? 0));
              $p = (float)str_replace(',', '.', (string)($modalItem['precio'] ?? 0));
              if ($q > 0 && $p >= 0) {
                  $quoteModalSubtotal += $q * $p;
              }
          }
          $quoteModalDiscount = (float)str_replace(',', '.', (string)$quoteForm['descuento_pct']);
          if ($quoteModalDiscount < 0) {
              $quoteModalDiscount = 0;
          }
          if ($quoteModalDiscount > 100) {
              $quoteModalDiscount = 100;
          }
          $quoteModalMoney = quote_money_breakdown($quoteModalSubtotal, $quoteModalDiscount);
          $quoteModalDiscountAmount = (float)$quoteModalMoney['descuento_monto'];
          $quoteModalIva = (float)$quoteModalMoney['iva_monto'];
          $quoteModalTotal = (float)$quoteModalMoney['total'];
          $canCreateQuote = !empty($customers);
        ?>

        <section class="panel">
          <div class="cotizaciones-toolbar">
            <h2 style="margin:0;">Cotizaciones</h2>
            <div class="cotizaciones-toolbar-right">
              <div class="cotizaciones-filters" data-quote-filter-root="1">
                <input
                  type="search"
                  placeholder="Buscar Nro, fecha, cliente o estado"
                  autocomplete="off"
                  spellcheck="false"
                  data-quote-filter-search="1"
                >
                <select data-quote-filter-state="1">
                  <option value="">Todos los estados</option>
                  <?php foreach ($quoteStatuses as $quoteStatus): ?>
                    <option value="<?= h($quoteStatus) ?>"><?= h($quoteStatus) ?></option>
                  <?php endforeach; ?>
                </select>
                <select data-quote-filter-customer="1">
                  <option value="">Todos los clientes</option>
                  <?php foreach ($customers as $customer): ?>
                    <option value="<?= h((string)$customer['id']) ?>"><?= h((string)$customer['razon_social']) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <span class="clientes-count">Total: <?= h((string)count($quotes)) ?></span>
              <span class="cotizaciones-visible-count" data-quote-visible-count="1"></span>
              <button class="btn primary" type="button" data-open-quote-modal="1" <?= $canCreateQuote ? '' : 'disabled' ?>>Nueva cotizacion</button>
            </div>
          </div>
          <?php if (!$canCreateQuote): ?>
            <p class="muted" style="margin:0;">Primero crea al menos un cliente en el modulo Clientes para poder emitir cotizaciones.</p>
          <?php else: ?>
            <p class="muted" style="margin:0;">Cada cotizacion se guarda con su cabecera e items asociados, usando solo clientes de tu empresa.</p>
          <?php endif; ?>
        </section>

        <section class="panel">
          <h3>Listado de cotizaciones</h3>
          <?php if (empty($quotes)): ?>
            <p class="muted">Aun no tienes cotizaciones registradas.</p>
          <?php else: ?>
            <div class="clientes-table-wrap" style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>Nro</th><th>Fecha</th><th>Cliente</th><th>Subtotal</th><th>Desc.</th><th>Total</th><th>Estado</th><th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($quotes as $quote): ?>
                    <?php
                      $qid = (int)$quote['id'];
                      $items = $quoteItemsByQuote[$qid] ?? [];
                      $quoteEditPayload = [
                        'id' => $qid,
                        'customer_id' => (int)$quote['customer_id'],
                        'numero_cotizacion' => (string)$quote['numero_cotizacion'],
                        'fecha_emision' => (string)$quote['fecha_emision'],
                        'validez_dias' => (string)$quote['validez_dias'],
                        'estado' => (string)$quote['estado'],
                        'descuento_pct' => (string)$quote['descuento_pct'],
                        'terminos_condiciones_adicionales' => (string)$quote['terminos_condiciones_adicionales'],
                        'observaciones' => (string)$quote['observaciones'],
                        'items' => array_map(static function ($item) {
                          return [
                            'descripcion' => (string)$item['descripcion'],
                            'cantidad' => (string)$item['cantidad'],
                            'precio' => (string)$item['precio_unitario'],
                          ];
                        }, $items),
                      ];
                    ?>
                    <?php
                      $quoteSearchText = implode(' ', [
                        (string)$quote['numero_cotizacion'],
                        (string)$quote['fecha_emision'],
                        (string)$quote['customer_name'],
                        (string)$quote['estado'],
                      ]);
                    ?>
                    <tr
                      data-quote-row="1"
                      data-quote-search="<?= h($quoteSearchText) ?>"
                      data-quote-state="<?= h((string)$quote['estado']) ?>"
                      data-quote-customer-id="<?= h((string)$quote['customer_id']) ?>"
                    >
                      <td><strong><?= h($quote['numero_cotizacion']) ?></strong></td>
                      <td><?= h((string)$quote['fecha_emision']) ?></td>
                      <td><?= h($quote['customer_name']) ?></td>
                      <td>$<?= h(money_clp($quote['subtotal'])) ?></td>
                      <td><?= h((string)$quote['descuento_pct']) ?>%</td>
                      <td><strong>$<?= h(money_clp($quote['total'])) ?></strong></td>
                      <td>
                        <form method="post" class="quote-state-form">
                          <input type="hidden" name="action" value="quick_update_quote_status">
                          <input type="hidden" name="quote_id" value="<?= h((string)$quote['id']) ?>">
                          <select name="estado" class="quote-state-select" data-quote-state-quick="1" aria-label="Estado de cotizacion <?= h((string)$quote['numero_cotizacion']) ?>">
                            <?php foreach ($quoteStatuses as $quoteStatus): ?>
                              <option value="<?= h($quoteStatus) ?>" <?= (string)$quote['estado'] === (string)$quoteStatus ? 'selected' : '' ?>><?= h($quoteStatus) ?></option>
                            <?php endforeach; ?>
                          </select>
                        </form>
                      </td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn pdf"
                            type="button"
                            title="Ver PDF"
                            aria-label="Ver PDF"
                            data-open-quote-preview="1"
                            data-quote-number="<?= h((string)$quote['numero_cotizacion']) ?>"
                            data-preview-url="/empresa/dashboard/?module=cotizaciones&amp;view_quote_id=<?= h((string)$quote['id']) ?>&amp;quote_embed=1"
                            data-print-url="/empresa/dashboard/?module=cotizaciones&amp;view_quote_id=<?= h((string)$quote['id']) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M2.5 10c1.6-3 4.2-4.5 7.5-4.5s5.9 1.5 7.5 4.5c-1.6 3-4.2 4.5-7.5 4.5S4.1 13 2.5 10zM10 12.7a2.7 2.7 0 1 0 0-5.4 2.7 2.7 0 0 0 0 5.4z"/></svg>
                          </button>
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Editar cotizacion"
                            aria-label="Editar cotizacion"
                            data-edit-quote="1"
                            data-quote-payload="<?= h((string)json_encode($quoteEditPayload, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M13.5 3.5l3 3M4 16h3l9-9-3-3-9 9v3z"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Eliminar cotizacion"
                            aria-label="Eliminar cotizacion"
                            data-open-delete-confirm="1"
                            data-delete-action="delete_quote"
                            data-delete-id-field="quote_id"
                            data-delete-id-value="<?= h((string)$quote['id']) ?>"
                            data-delete-entity="cotizacion"
                            data-delete-description="<?= h((string)$quote['numero_cotizacion']) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3.5 5.5h13M8 5.5V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M6 5.5l.7 10.5h6.6L14 5.5M8.7 8v5.5M11.3 8v5.5"/></svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                  <tr data-quote-filter-empty="1" style="display:none;">
                    <td colspan="8" class="quote-filter-empty">No hay cotizaciones que coincidan con los filtros.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          <?php endif; ?>
        </section>

        <div class="modal-backdrop<?= $openQuoteModal ? ' open' : '' ?>" id="quoteModal" aria-hidden="<?= $openQuoteModal ? 'false' : 'true' ?>">
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="quoteModalTitle">
            <div class="modal-head">
              <h3 id="quoteModalTitle"><?= $isQuoteEdit ? 'Editar cotizacion' : 'Nueva cotizacion' ?></h3>
              <button class="btn" type="button" data-close-quote-modal="1">Cerrar</button>
            </div>
            <div class="modal-body">
              <form method="post" id="quoteModalForm">
                <input type="hidden" name="action" value="<?= $isQuoteEdit ? 'update_quote' : 'add_quote' ?>" data-quote-action="1">
                <input type="hidden" name="quote_id" value="<?= h((string)($quoteForm['id'] ?? '')) ?>" data-quote-id="1">

                <div class="quote-form-grid">
                  <div class="field">
                    <label>Numero de cotizacion</label>
                    <input type="text" name="numero_cotizacion" value="<?= h($quoteForm['numero_cotizacion']) ?>" required>
                  </div>
                  <div class="field">
                    <label>Fecha emision</label>
                    <input type="date" name="fecha_emision" value="<?= h($quoteForm['fecha_emision']) ?>" required>
                  </div>
                  <div class="field">
                    <label>Validez (dias)</label>
                    <input type="number" min="1" max="3650" step="1" name="validez_dias" value="<?= h($quoteForm['validez_dias']) ?>" required>
                  </div>
                  <div class="field">
                    <label>Estado</label>
                    <select name="estado" required>
                      <?php foreach ($quoteStatuses as $quoteStatus): ?>
                        <option value="<?= h($quoteStatus) ?>" <?= (string)$quoteForm['estado'] === (string)$quoteStatus ? 'selected' : '' ?>><?= h($quoteStatus) ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="field">
                    <label>Descuento (%)</label>
                    <input type="number" min="0" max="100" step="0.01" name="descuento_pct" value="<?= h($quoteForm['descuento_pct']) ?>">
                  </div>
                  <div class="field full">
                    <label>Cliente de tu empresa</label>
                    <select name="customer_id" required>
                      <option value="">Selecciona un cliente</option>
                      <?php foreach ($customers as $customer): ?>
                        <option value="<?= h((string)$customer['id']) ?>" <?= (string)$quoteForm['customer_id'] === (string)$customer['id'] ? 'selected' : '' ?>>
                          <?= h($customer['razon_social']) ?><?php if ((string)$customer['rut'] !== ''): ?> - <?= h($customer['rut']) ?><?php endif; ?>
                        </option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="field full">
                    <label>Terminos y condiciones adicionales</label>
                    <textarea name="terminos_condiciones_adicionales"><?= h($quoteForm['terminos_condiciones_adicionales']) ?></textarea>
                  </div>
                  <div class="field full">
                    <label>Observaciones</label>
                    <textarea name="observaciones"><?= h($quoteForm['observaciones']) ?></textarea>
                  </div>
                </div>

                <div class="quote-items-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th style="width:50%;">Descripcion</th>
                        <th style="width:14%;">Cantidad</th>
                        <th style="width:16%;">Precio unitario</th>
                        <th style="width:14%;">Total linea</th>
                        <th style="width:6%;">Accion</th>
                      </tr>
                    </thead>
                    <tbody data-quote-items-body="1">
                      <?php foreach ($quoteForm['items'] as $item): ?>
                        <?php
                          $itemQty = (float)str_replace(',', '.', (string)($item['cantidad'] ?? 0));
                          $itemPrice = (float)str_replace(',', '.', (string)($item['precio'] ?? 0));
                          $itemTotal = $itemQty > 0 ? ($itemQty * $itemPrice) : 0;
                        ?>
                        <tr>
                          <td><input type="text" name="item_descripcion[]" value="<?= h($item['descripcion']) ?>" required></td>
                          <td><input type="number" name="item_cantidad[]" value="<?= h((string)$item['cantidad']) ?>" min="0.01" step="0.01" data-item-cantidad="1" required></td>
                          <td><input type="number" name="item_precio[]" value="<?= h((string)$item['precio']) ?>" min="0" step="0.01" data-item-precio="1" required></td>
                          <td><span class="line-total" data-line-total="1">$<?= h(money_clp($itemTotal)) ?></span></td>
                          <td><button class="btn danger" type="button" data-quote-remove-item="1">X</button></td>
                        </tr>
                      <?php endforeach; ?>
                    </tbody>
                  </table>
                </div>

                <div style="margin-top:.65rem; display:flex; justify-content:flex-start;">
                  <button class="btn" type="button" data-quote-add-item="1">Agregar item</button>
                </div>

                <div class="quote-summary">
                  <span>Subtotal: <strong data-quote-subtotal="1">$<?= h(money_clp($quoteModalSubtotal)) ?></strong></span>
                  <span>Descuento: <strong data-quote-discount="1">$<?= h(money_clp($quoteModalDiscountAmount)) ?></strong></span>
                  <span>IVA (19%): <strong data-quote-iva="1">$<?= h(money_clp($quoteModalIva)) ?></strong></span>
                  <span>Total final: <strong data-quote-total="1">$<?= h(money_clp($quoteModalTotal)) ?></strong></span>
                </div>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-quote-modal="1">Cancelar</button>
                  <button class="btn primary" type="submit" data-quote-submit-label="1"><?= $isQuoteEdit ? 'Actualizar cotizacion' : 'Guardar cotizacion' ?></button>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div class="modal-backdrop" id="quotePreviewModal" aria-hidden="true">
          <div class="quote-preview-card" role="dialog" aria-modal="true" aria-labelledby="quotePreviewModalTitle">
            <div class="modal-head">
              <h3 id="quotePreviewModalTitle">Previsualizacion PDF</h3>
              <div style="display:flex; gap:.5rem; align-items:center;">
                <button class="btn" type="button" data-quote-preview-print="1">Imprimir</button>
                <button class="btn" type="button" data-close-quote-preview="1">Cerrar</button>
              </div>
            </div>
            <div class="quote-preview-body">
              <iframe class="quote-preview-frame" title="Previsualizacion de cotizacion" data-quote-preview-frame="1" loading="lazy"></iframe>
              <p class="quote-preview-empty" data-quote-preview-empty="1" style="display:none;">No fue posible cargar la previsualizacion.</p>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($module === 'clientes' || $module === 'cotizaciones'): ?>
        <div class="modal-backdrop" id="deleteConfirmModal" aria-hidden="true">
          <div class="delete-confirm-card" role="dialog" aria-modal="true" aria-labelledby="deleteConfirmTitle">
            <div class="modal-head">
              <h3 id="deleteConfirmTitle">Confirmar eliminacion</h3>
              <button class="btn" type="button" data-close-delete-confirm="1">Cerrar</button>
            </div>
            <div class="delete-confirm-body">
              <p class="delete-confirm-text" data-delete-confirm-description="1"></p>
              <div data-delete-step-one="1">
                <p class="delete-confirm-text">Primer paso: confirma que quieres continuar con la eliminacion.</p>
                <div class="modal-actions" style="margin-top:.5rem;">
                  <button class="btn" type="button" data-close-delete-confirm="1">Cancelar</button>
                  <button class="btn danger" type="button" data-delete-go-step-two="1">Continuar</button>
                </div>
              </div>
              <div data-delete-step-two="1" style="display:none;">
                <p class="delete-confirm-text">Segundo paso: escribe ELIMINAR para habilitar el boton final.</p>
                <input class="delete-confirm-code" type="text" autocomplete="off" spellcheck="false" placeholder="Escribe ELIMINAR" data-delete-confirm-input="1">
                <div class="modal-actions" style="margin-top:.5rem;">
                  <button class="btn" type="button" data-delete-back-step-one="1">Volver</button>
                  <button class="btn danger" type="button" data-delete-submit="1" disabled>Eliminar definitivamente</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      <?php endif; ?>
      </div>
    </main>
  </div>
  <div class="spa-progress" aria-hidden="true"></div>
  <script>
    (function () {
      var appMain = document.getElementById('appMain');
      var sideMenu = document.querySelector('.menu');
      var isNavigating = false;
      var customerModalCleanup = null;
      var quoteModalCleanup = null;
      var quotePreviewCleanup = null;
      var deleteConfirmCleanup = null;
      var quoteFiltersCleanup = null;
      var quoteQuickStateCleanup = null;

      function stripDiacritics(value) {
        var text = String(value || '');
        if (typeof text.normalize === 'function') {
          return text.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        }
        return text;
      }

      function normalizeForFilter(value) {
        return stripDiacritics(value).toLowerCase().trim();
      }

      function bindQuoteFilters() {
        if (typeof quoteFiltersCleanup === 'function') {
          quoteFiltersCleanup();
          quoteFiltersCleanup = null;
        }

        var root = document.querySelector('[data-quote-filter-root="1"]');
        if (!root) {
          return;
        }

        var searchInput = root.querySelector('[data-quote-filter-search="1"]');
        var stateSelect = root.querySelector('[data-quote-filter-state="1"]');
        var customerSelect = root.querySelector('[data-quote-filter-customer="1"]');
        var rows = Array.prototype.slice.call(document.querySelectorAll('[data-quote-row="1"]'));
        var emptyRow = document.querySelector('[data-quote-filter-empty="1"]');
        var visibleCount = document.querySelector('[data-quote-visible-count="1"]');

        if (!searchInput || !stateSelect || !customerSelect || rows.length === 0) {
          if (visibleCount) {
            visibleCount.textContent = '';
          }
          return;
        }

        function applyFilters() {
          var query = normalizeForFilter(searchInput.value);
          var selectedState = normalizeForFilter(stateSelect.value);
          var selectedCustomer = String(customerSelect.value || '');
          var shown = 0;

          rows.forEach(function (row) {
            var haystack = normalizeForFilter(row.textContent || row.getAttribute('data-quote-search') || '');
            var stateSelectInRow = row.querySelector('[data-quote-state-quick="1"]');
            var rowState = normalizeForFilter(stateSelectInRow ? stateSelectInRow.value : row.getAttribute('data-quote-state'));
            var rowCustomerId = String(row.getAttribute('data-quote-customer-id') || '');

            var matchesQuery = query === '' || haystack.indexOf(query) !== -1;
            var matchesState = selectedState === '' || rowState === selectedState;
            var matchesCustomer = selectedCustomer === '' || rowCustomerId === selectedCustomer;
            var show = matchesQuery && matchesState && matchesCustomer;

            row.style.display = show ? '' : 'none';
            if (show) {
              shown += 1;
            }
          });

          if (emptyRow) {
            emptyRow.style.display = shown === 0 ? '' : 'none';
          }
          if (visibleCount) {
            visibleCount.textContent = 'Mostrando: ' + shown;
          }
        }

        searchInput.addEventListener('input', applyFilters);
        stateSelect.addEventListener('change', applyFilters);
        customerSelect.addEventListener('change', applyFilters);

        applyFilters();

        quoteFiltersCleanup = function () {
          searchInput.removeEventListener('input', applyFilters);
          stateSelect.removeEventListener('change', applyFilters);
          customerSelect.removeEventListener('change', applyFilters);
        };
      }

      function stateToneToken(value) {
        return stripDiacritics(String(value || '').toLowerCase())
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '');
      }

      function bindQuoteQuickState() {
        if (typeof quoteQuickStateCleanup === 'function') {
          quoteQuickStateCleanup();
          quoteQuickStateCleanup = null;
        }

        var selects = Array.prototype.slice.call(document.querySelectorAll('[data-quote-state-quick="1"]'));
        if (selects.length === 0) {
          return;
        }

        function paintSelect(select) {
          select.setAttribute('data-state-tone', stateToneToken(select.value));
        }

        function onStateChange(event) {
          var select = event.currentTarget;
          paintSelect(select);
          var form = select.closest('form');
          if (form) {
            form.submit();
          }
        }

        selects.forEach(function (select) {
          paintSelect(select);
          select.addEventListener('change', onStateChange);
        });

        quoteQuickStateCleanup = function () {
          selects.forEach(function (select) {
            select.removeEventListener('change', onStateChange);
          });
        };
      }

      function bindCustomerModal() {
        if (typeof customerModalCleanup === 'function') {
          customerModalCleanup();
          customerModalCleanup = null;
        }

        var customerModal = document.getElementById('customerModal');
        if (!customerModal) {
          return;
        }

        var openButtons = document.querySelectorAll('[data-open-customer-modal="1"]');
        var editButtons = document.querySelectorAll('[data-edit-customer="1"]');
        var closeButtons = document.querySelectorAll('[data-close-customer-modal="1"]');
        var form = customerModal.querySelector('#customerModalForm');
        var title = customerModal.querySelector('#customerModalTitle');
        var actionInput = customerModal.querySelector('[data-customer-action="1"]');
        var idInput = customerModal.querySelector('[data-customer-id="1"]');
        var submitLabel = customerModal.querySelector('[data-customer-submit-label="1"]');
        var customerInitialValues = {};

        if (form) {
          [
            'rut', 'razon_social', 'nombre_fantasia', 'direccion', 'comuna', 'ciudad',
            'telefono', 'celular', 'email', 'contacto', 'notas_internas'
          ].forEach(function (fieldName) {
            var field = form.querySelector('[name="' + fieldName + '"]');
            customerInitialValues[fieldName] = field ? field.value : '';
          });
        }

        function setCustomerMode(isEdit) {
          if (actionInput) {
            actionInput.value = isEdit ? 'update_customer' : 'add_customer';
          }
          if (title) {
            title.textContent = isEdit ? 'Editar cliente' : 'Nuevo cliente';
          }
          if (submitLabel) {
            submitLabel.textContent = isEdit ? 'Actualizar cliente' : 'Guardar cliente';
          }
          if (!isEdit && idInput) {
            idInput.value = '';
          }
        }

        function fillCustomerFormFromButton(button) {
          if (!form) {
            return;
          }
          var map = [
            ['customer-rut', 'rut'],
            ['customer-razon-social', 'razon_social'],
            ['customer-nombre-fantasia', 'nombre_fantasia'],
            ['customer-direccion', 'direccion'],
            ['customer-comuna', 'comuna'],
            ['customer-ciudad', 'ciudad'],
            ['customer-telefono', 'telefono'],
            ['customer-celular', 'celular'],
            ['customer-email', 'email'],
            ['customer-contacto', 'contacto'],
            ['customer-notas', 'notas_internas']
          ];
          map.forEach(function (pair) {
            var dataName = pair[0];
            var fieldName = pair[1];
            var field = form.querySelector('[name="' + fieldName + '"]');
            if (field) {
              field.value = button.getAttribute('data-' + dataName) || '';
            }
          });
        }

        function openModal() {
          if (form) {
            Object.keys(customerInitialValues).forEach(function (fieldName) {
              var field = form.querySelector('[name="' + fieldName + '"]');
              if (field) {
                field.value = customerInitialValues[fieldName] || '';
              }
            });
          }
          setCustomerMode(false);
          customerModal.classList.add('open');
          customerModal.setAttribute('aria-hidden', 'false');
          var firstInput = customerModal.querySelector('input[name="rut"]');
          if (firstInput) {
            firstInput.focus();
          }
        }

        function closeModal() {
          customerModal.classList.remove('open');
          customerModal.setAttribute('aria-hidden', 'true');
        }

        function onBackdropClick(event) {
          if (event.target === customerModal) {
            closeModal();
          }
        }

        function onEsc(event) {
          if (event.key === 'Escape' && customerModal.classList.contains('open')) {
            closeModal();
          }
        }

        function onEditClick(event) {
          var button = event.currentTarget;
          if (idInput) {
            idInput.value = button.getAttribute('data-customer-id') || '';
          }
          fillCustomerFormFromButton(button);
          setCustomerMode(true);
          customerModal.classList.add('open');
          customerModal.setAttribute('aria-hidden', 'false');
          var firstInput = customerModal.querySelector('input[name="rut"]');
          if (firstInput) {
            firstInput.focus();
          }
        }

        openButtons.forEach(function (btn) {
          btn.addEventListener('click', openModal);
        });
        editButtons.forEach(function (btn) {
          btn.addEventListener('click', onEditClick);
        });

        closeButtons.forEach(function (btn) {
          btn.addEventListener('click', closeModal);
        });

        customerModal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);

        customerModalCleanup = function () {
          openButtons.forEach(function (btn) {
            btn.removeEventListener('click', openModal);
          });
          editButtons.forEach(function (btn) {
            btn.removeEventListener('click', onEditClick);
          });
          closeButtons.forEach(function (btn) {
            btn.removeEventListener('click', closeModal);
          });
          customerModal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
        };
      }

      function formatMoney(value) {
        var n = Number(value);
        if (!isFinite(n)) {
          n = 0;
        }
        return '$' + Math.round(n).toLocaleString('es-CL');
      }

      function bindQuoteModal() {
        if (typeof quoteModalCleanup === 'function') {
          quoteModalCleanup();
          quoteModalCleanup = null;
        }

        var quoteModal = document.getElementById('quoteModal');
        if (!quoteModal) {
          return;
        }

        var openButtons = document.querySelectorAll('[data-open-quote-modal="1"]');
        var editButtons = document.querySelectorAll('[data-edit-quote="1"]');
        var closeButtons = document.querySelectorAll('[data-close-quote-modal="1"]');
        var itemsBody = quoteModal.querySelector('[data-quote-items-body="1"]');
        var addItemButton = quoteModal.querySelector('[data-quote-add-item="1"]');
        var discountInput = quoteModal.querySelector('input[name="descuento_pct"]');
        var form = quoteModal.querySelector('#quoteModalForm');
        var title = quoteModal.querySelector('#quoteModalTitle');
        var actionInput = quoteModal.querySelector('[data-quote-action="1"]');
        var quoteIdInput = quoteModal.querySelector('[data-quote-id="1"]');
        var submitLabel = quoteModal.querySelector('[data-quote-submit-label="1"]');
        var subtotalLabel = quoteModal.querySelector('[data-quote-subtotal="1"]');
        var discountLabel = quoteModal.querySelector('[data-quote-discount="1"]');
        var ivaLabel = quoteModal.querySelector('[data-quote-iva="1"]');
        var totalLabel = quoteModal.querySelector('[data-quote-total="1"]');
        var quoteInitialValues = {};
        var quoteInitialItemsHtml = itemsBody ? itemsBody.innerHTML : '';

        if (form) {
          [
            'customer_id', 'numero_cotizacion', 'fecha_emision', 'validez_dias', 'estado',
            'descuento_pct', 'terminos_condiciones_adicionales', 'observaciones'
          ].forEach(function (fieldName) {
            var field = form.querySelector('[name="' + fieldName + '"]');
            quoteInitialValues[fieldName] = field ? field.value : '';
          });
        }

        function setQuoteMode(isEdit) {
          if (actionInput) {
            actionInput.value = isEdit ? 'update_quote' : 'add_quote';
          }
          if (title) {
            title.textContent = isEdit ? 'Editar cotizacion' : 'Nueva cotizacion';
          }
          if (submitLabel) {
            submitLabel.textContent = isEdit ? 'Actualizar cotizacion' : 'Guardar cotizacion';
          }
          if (!isEdit && quoteIdInput) {
            quoteIdInput.value = '';
          }
        }

        function openModal() {
          if (form) {
            Object.keys(quoteInitialValues).forEach(function (fieldName) {
              var field = form.querySelector('[name="' + fieldName + '"]');
              if (field) {
                field.value = quoteInitialValues[fieldName] || '';
              }
            });
          }
          if (itemsBody) {
            itemsBody.innerHTML = quoteInitialItemsHtml;
          }
          setQuoteMode(false);
          quoteModal.classList.add('open');
          quoteModal.setAttribute('aria-hidden', 'false');
          var focusInput = quoteModal.querySelector('input[name="numero_cotizacion"]');
          if (focusInput) {
            focusInput.focus();
          }
          refreshTotals();
        }

        function closeModal() {
          quoteModal.classList.remove('open');
          quoteModal.setAttribute('aria-hidden', 'true');
        }

        function onBackdropClick(event) {
          if (event.target === quoteModal) {
            closeModal();
          }
        }

        function onEsc(event) {
          if (event.key === 'Escape' && quoteModal.classList.contains('open')) {
            closeModal();
          }
        }

        function createItemRow(itemData) {
          var data = itemData || {};
          var desc = String(data.descripcion || '');
          var qty = String(data.cantidad || '1');
          var price = String(data.precio || '0');
          var tr = document.createElement('tr');
          tr.innerHTML = [
            '<td><input type="text" name="item_descripcion[]" value="' + escapeHtml(desc) + '" required></td>',
            '<td><input type="number" name="item_cantidad[]" value="' + escapeHtml(qty) + '" min="0.01" step="0.01" data-item-cantidad="1" required></td>',
            '<td><input type="number" name="item_precio[]" value="' + escapeHtml(price) + '" min="0" step="0.01" data-item-precio="1" required></td>',
            '<td><span class="line-total" data-line-total="1">$0</span></td>',
            '<td><button class="btn danger" type="button" data-quote-remove-item="1">X</button></td>'
          ].join('');
          return tr;
        }

        function escapeHtml(value) {
          return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
        }

        function fillQuoteFormFromPayload(payload) {
          if (!form || !payload) {
            return;
          }

          var fieldNames = [
            'customer_id',
            'numero_cotizacion',
            'fecha_emision',
            'validez_dias',
            'estado',
            'descuento_pct',
            'terminos_condiciones_adicionales',
            'observaciones'
          ];

          fieldNames.forEach(function (fieldName) {
            var field = form.querySelector('[name="' + fieldName + '"]');
            if (field && Object.prototype.hasOwnProperty.call(payload, fieldName)) {
              field.value = payload[fieldName] == null ? '' : String(payload[fieldName]);
            }
          });

          if (quoteIdInput) {
            quoteIdInput.value = payload.id == null ? '' : String(payload.id);
          }

          if (itemsBody) {
            itemsBody.innerHTML = '';
            var items = Array.isArray(payload.items) ? payload.items : [];
            if (items.length === 0) {
              itemsBody.appendChild(createItemRow());
            } else {
              items.forEach(function (item) {
                itemsBody.appendChild(createItemRow(item));
              });
            }
          }
        }

        function ensureOneRow() {
          if (!itemsBody) {
            return;
          }
          if (itemsBody.querySelectorAll('tr').length === 0) {
            itemsBody.appendChild(createItemRow());
          }
        }

        function refreshTotals() {
          if (!itemsBody) {
            return;
          }
          var subtotal = 0;
          var rows = itemsBody.querySelectorAll('tr');
          rows.forEach(function (row) {
            var qtyInput = row.querySelector('[data-item-cantidad="1"]');
            var priceInput = row.querySelector('[data-item-precio="1"]');
            var lineLabel = row.querySelector('[data-line-total="1"]');
            var qty = qtyInput ? Number(qtyInput.value) : 0;
            var price = priceInput ? Number(priceInput.value) : 0;
            if (!isFinite(qty) || qty < 0) {
              qty = 0;
            }
            if (!isFinite(price) || price < 0) {
              price = 0;
            }
            var lineTotal = qty * price;
            subtotal += lineTotal;
            if (lineLabel) {
              lineLabel.textContent = formatMoney(lineTotal);
            }
          });

          var discount = discountInput ? Number(discountInput.value) : 0;
          if (!isFinite(discount) || discount < 0) {
            discount = 0;
          }
          if (discount > 100) {
            discount = 100;
          }
          var discountAmount = subtotal * (discount / 100);
          var net = subtotal - discountAmount;
          var iva = net * 0.19;
          var total = net + iva;
          if (subtotalLabel) {
            subtotalLabel.textContent = formatMoney(subtotal);
          }
          if (discountLabel) {
            discountLabel.textContent = formatMoney(discountAmount);
          }
          if (ivaLabel) {
            ivaLabel.textContent = formatMoney(iva);
          }
          if (totalLabel) {
            totalLabel.textContent = formatMoney(total);
          }
        }

        function onItemsInput(event) {
          if (!event.target.closest('[data-quote-items-body="1"]')) {
            return;
          }
          if (event.target.matches('input[name="item_cantidad[]"], input[name="item_precio[]"]')) {
            refreshTotals();
          }
        }

        function onItemsClick(event) {
          var removeBtn = event.target.closest('[data-quote-remove-item="1"]');
          if (!removeBtn || !itemsBody) {
            return;
          }
          var row = removeBtn.closest('tr');
          if (row) {
            row.remove();
          }
          ensureOneRow();
          refreshTotals();
        }

        function onAddItem() {
          if (!itemsBody) {
            return;
          }
          itemsBody.appendChild(createItemRow());
          refreshTotals();
        }

        function onEditClick(event) {
          var button = event.currentTarget;
          var payloadRaw = button.getAttribute('data-quote-payload') || '';
          var payload = null;
          try {
            payload = JSON.parse(payloadRaw);
          } catch (error) {
            payload = null;
          }
          if (!payload) {
            return;
          }

          fillQuoteFormFromPayload(payload);
          setQuoteMode(true);
          quoteModal.classList.add('open');
          quoteModal.setAttribute('aria-hidden', 'false');
          refreshTotals();
        }

        openButtons.forEach(function (btn) {
          btn.addEventListener('click', openModal);
        });
        editButtons.forEach(function (btn) {
          btn.addEventListener('click', onEditClick);
        });

        closeButtons.forEach(function (btn) {
          btn.addEventListener('click', closeModal);
        });

        quoteModal.addEventListener('click', onBackdropClick);
        quoteModal.addEventListener('click', onItemsClick);
        quoteModal.addEventListener('input', onItemsInput);
        document.addEventListener('keydown', onEsc);
        if (discountInput) {
          discountInput.addEventListener('input', refreshTotals);
        }
        if (addItemButton) {
          addItemButton.addEventListener('click', onAddItem);
        }

        ensureOneRow();
        refreshTotals();

        quoteModalCleanup = function () {
          openButtons.forEach(function (btn) {
            btn.removeEventListener('click', openModal);
          });
          editButtons.forEach(function (btn) {
            btn.removeEventListener('click', onEditClick);
          });
          closeButtons.forEach(function (btn) {
            btn.removeEventListener('click', closeModal);
          });
          quoteModal.removeEventListener('click', onBackdropClick);
          quoteModal.removeEventListener('click', onItemsClick);
          quoteModal.removeEventListener('input', onItemsInput);
          document.removeEventListener('keydown', onEsc);
          if (discountInput) {
            discountInput.removeEventListener('input', refreshTotals);
          }
          if (addItemButton) {
            addItemButton.removeEventListener('click', onAddItem);
          }
        };
      }

      function bindQuotePreview() {
        if (typeof quotePreviewCleanup === 'function') {
          quotePreviewCleanup();
          quotePreviewCleanup = null;
        }

        var previewModal = document.getElementById('quotePreviewModal');
        if (!previewModal) {
          return;
        }

        var triggerButtons = document.querySelectorAll('[data-open-quote-preview="1"]');
        var closeButtons = previewModal.querySelectorAll('[data-close-quote-preview="1"]');
        var printButton = previewModal.querySelector('[data-quote-preview-print="1"]');
        var frame = previewModal.querySelector('[data-quote-preview-frame="1"]');
        var emptyState = previewModal.querySelector('[data-quote-preview-empty="1"]');
        var title = previewModal.querySelector('#quotePreviewModalTitle');
        var currentPrintUrl = '';

        function setFrameErrorState(hasError) {
          if (!frame || !emptyState) {
            return;
          }
          if (hasError) {
            frame.style.display = 'none';
            emptyState.style.display = 'block';
            return;
          }
          frame.style.display = 'block';
          emptyState.style.display = 'none';
        }

        function openModal(previewUrl, printUrl, quoteNumber) {
          currentPrintUrl = printUrl || '';
          if (title) {
            title.textContent = quoteNumber ? ('Previsualizacion PDF - ' + quoteNumber) : 'Previsualizacion PDF';
          }
          previewModal.classList.add('open');
          previewModal.setAttribute('aria-hidden', 'false');
          setFrameErrorState(false);
          if (frame) {
            frame.src = previewUrl || 'about:blank';
          }
        }

        function closeModal() {
          previewModal.classList.remove('open');
          previewModal.setAttribute('aria-hidden', 'true');
          currentPrintUrl = '';
          if (frame) {
            frame.src = 'about:blank';
          }
          setFrameErrorState(false);
        }

        function onEsc(event) {
          if (event.key === 'Escape' && previewModal.classList.contains('open')) {
            closeModal();
          }
        }

        function onBackdropClick(event) {
          if (event.target === previewModal) {
            closeModal();
          }
        }

        function onTriggerClick(event) {
          var button = event.currentTarget;
          openModal(
            button.getAttribute('data-preview-url') || '',
            button.getAttribute('data-print-url') || '',
            button.getAttribute('data-quote-number') || ''
          );
        }

        function onPrintClick() {
          if (!currentPrintUrl) {
            return;
          }
          window.open(currentPrintUrl, '_blank', 'noopener');
        }

        function onFrameError() {
          setFrameErrorState(true);
        }

        triggerButtons.forEach(function (button) {
          button.addEventListener('click', onTriggerClick);
        });
        closeButtons.forEach(function (button) {
          button.addEventListener('click', closeModal);
        });
        previewModal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);
        if (printButton) {
          printButton.addEventListener('click', onPrintClick);
        }
        if (frame) {
          frame.addEventListener('error', onFrameError);
        }

        quotePreviewCleanup = function () {
          triggerButtons.forEach(function (button) {
            button.removeEventListener('click', onTriggerClick);
          });
          closeButtons.forEach(function (button) {
            button.removeEventListener('click', closeModal);
          });
          previewModal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
          if (printButton) {
            printButton.removeEventListener('click', onPrintClick);
          }
          if (frame) {
            frame.removeEventListener('error', onFrameError);
          }
        };
      }

      function bindDeleteConfirmModal() {
        if (typeof deleteConfirmCleanup === 'function') {
          deleteConfirmCleanup();
          deleteConfirmCleanup = null;
        }

        var modal = document.getElementById('deleteConfirmModal');
        if (!modal) {
          return;
        }

        var openButtons = document.querySelectorAll('[data-open-delete-confirm="1"]');
        var closeButtons = modal.querySelectorAll('[data-close-delete-confirm="1"]');
        var description = modal.querySelector('[data-delete-confirm-description="1"]');
        var stepOne = modal.querySelector('[data-delete-step-one="1"]');
        var stepTwo = modal.querySelector('[data-delete-step-two="1"]');
        var goStepTwoButton = modal.querySelector('[data-delete-go-step-two="1"]');
        var backStepOneButton = modal.querySelector('[data-delete-back-step-one="1"]');
        var input = modal.querySelector('[data-delete-confirm-input="1"]');
        var submitButton = modal.querySelector('[data-delete-submit="1"]');

        var pendingAction = '';
        var pendingIdField = '';
        var pendingIdValue = '';

        function resetState() {
          pendingAction = '';
          pendingIdField = '';
          pendingIdValue = '';
          if (input) {
            input.value = '';
          }
          if (submitButton) {
            submitButton.disabled = true;
          }
          if (stepOne) {
            stepOne.style.display = 'block';
          }
          if (stepTwo) {
            stepTwo.style.display = 'none';
          }
        }

        function openModal(button) {
          pendingAction = button.getAttribute('data-delete-action') || '';
          pendingIdField = button.getAttribute('data-delete-id-field') || '';
          pendingIdValue = button.getAttribute('data-delete-id-value') || '';

          var entity = button.getAttribute('data-delete-entity') || 'registro';
          var desc = button.getAttribute('data-delete-description') || '';
          if (description) {
            description.textContent = desc !== ''
              ? 'Se eliminara el ' + entity + ': ' + desc + '. Esta accion no se puede deshacer.'
              : 'Se eliminara este ' + entity + '. Esta accion no se puede deshacer.';
          }

          resetState();
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }

        function closeModal() {
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
          resetState();
        }

        function submitDelete() {
          if (!pendingAction || !pendingIdField || !pendingIdValue) {
            return;
          }
          var form = document.createElement('form');
          form.method = 'post';
          form.style.display = 'none';

          var actionField = document.createElement('input');
          actionField.type = 'hidden';
          actionField.name = 'action';
          actionField.value = pendingAction;
          form.appendChild(actionField);

          var idField = document.createElement('input');
          idField.type = 'hidden';
          idField.name = pendingIdField;
          idField.value = pendingIdValue;
          form.appendChild(idField);

          document.body.appendChild(form);
          form.submit();
        }

        function onBackdropClick(event) {
          if (event.target === modal) {
            closeModal();
          }
        }

        function onEsc(event) {
          if (event.key === 'Escape' && modal.classList.contains('open')) {
            closeModal();
          }
        }

        function onInputChange() {
          if (!submitButton || !input) {
            return;
          }
          submitButton.disabled = input.value.trim().toUpperCase() !== 'ELIMINAR';
        }

        function onOpenClick(event) {
          openModal(event.currentTarget);
        }

        function goStepTwo() {
          if (stepOne) {
            stepOne.style.display = 'none';
          }
          if (stepTwo) {
            stepTwo.style.display = 'block';
          }
          if (input) {
            input.focus();
          }
        }

        function goStepOne() {
          if (stepOne) {
            stepOne.style.display = 'block';
          }
          if (stepTwo) {
            stepTwo.style.display = 'none';
          }
          if (input) {
            input.value = '';
          }
          if (submitButton) {
            submitButton.disabled = true;
          }
        }

        openButtons.forEach(function (button) {
          button.addEventListener('click', onOpenClick);
        });
        closeButtons.forEach(function (button) {
          button.addEventListener('click', closeModal);
        });
        if (goStepTwoButton) {
          goStepTwoButton.addEventListener('click', goStepTwo);
        }
        if (backStepOneButton) {
          backStepOneButton.addEventListener('click', goStepOne);
        }
        if (submitButton) {
          submitButton.addEventListener('click', submitDelete);
        }
        if (input) {
          input.addEventListener('input', onInputChange);
        }
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);

        deleteConfirmCleanup = function () {
          openButtons.forEach(function (button) {
            button.removeEventListener('click', onOpenClick);
          });
          closeButtons.forEach(function (button) {
            button.removeEventListener('click', closeModal);
          });
          if (goStepTwoButton) {
            goStepTwoButton.removeEventListener('click', goStepTwo);
          }
          if (backStepOneButton) {
            backStepOneButton.removeEventListener('click', goStepOne);
          }
          if (submitButton) {
            submitButton.removeEventListener('click', submitDelete);
          }
          if (input) {
            input.removeEventListener('input', onInputChange);
          }
          modal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
        };
      }

      function shouldHandleAsSpa(url) {
        if (!url || url.origin !== window.location.origin) {
          return false;
        }
        if (!url.pathname.startsWith('/empresa/dashboard/')) {
          return false;
        }
        return url.searchParams.has('module');
      }

      function setLoadingState(active) {
        if (active) {
          document.body.classList.add('spa-loading');
          document.body.classList.remove('spa-done');
          return;
        }
        document.body.classList.remove('spa-loading');
        document.body.classList.add('spa-done');
        setTimeout(function () {
          document.body.classList.remove('spa-done');
        }, 260);
      }

      function updateActiveMenuFromDoc(nextDoc) {
        if (!sideMenu) {
          return;
        }
        var currentLinks = sideMenu.querySelectorAll('a');
        var nextLinks = nextDoc.querySelectorAll('.menu a');
        currentLinks.forEach(function (link, index) {
          var next = nextLinks[index];
          if (!next) {
            return;
          }
          if (next.classList.contains('active')) {
            link.classList.add('active');
          } else {
            link.classList.remove('active');
          }
          var href = next.getAttribute('href');
          if (href) {
            link.setAttribute('href', href);
          }
        });
      }

      async function navigateSpa(targetUrl, pushState) {
        if (isNavigating) {
          return;
        }
        isNavigating = true;
        setLoadingState(true);

        try {
          var response = await fetch(targetUrl.toString(), {
            credentials: 'same-origin',
            headers: {
              'X-Requested-With': 'fetch-spa',
            },
          });

          if (!response.ok) {
            window.location.href = targetUrl.toString();
            return;
          }

          var html = await response.text();
          var parser = new DOMParser();
          var nextDoc = parser.parseFromString(html, 'text/html');
          var nextMain = nextDoc.getElementById('appMain');

          if (!nextMain || !appMain) {
            window.location.href = targetUrl.toString();
            return;
          }

          appMain.innerHTML = nextMain.innerHTML;
          document.title = nextDoc.title || document.title;
          document.body.className = nextDoc.body.className;
          updateActiveMenuFromDoc(nextDoc);
          bindCustomerModal();
          bindQuoteModal();
          bindQuotePreview();
          bindDeleteConfirmModal();
          bindQuoteFilters();
          bindQuoteQuickState();

          if (pushState) {
            history.pushState({ moduleUrl: targetUrl.toString() }, '', targetUrl.toString());
          }
        } catch (error) {
          window.location.href = targetUrl.toString();
          return;
        } finally {
          setLoadingState(false);
          isNavigating = false;
        }
      }

      document.addEventListener('click', function (event) {
        var link = event.target.closest('.menu a');
        if (!link) {
          return;
        }
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
          return;
        }
        if (link.target && link.target !== '_self') {
          return;
        }

        var targetUrl = new URL(link.href, window.location.origin);
        if (!shouldHandleAsSpa(targetUrl)) {
          return;
        }

        event.preventDefault();
        if (targetUrl.toString() === window.location.href) {
          return;
        }
        navigateSpa(targetUrl, true);
      });

      window.addEventListener('popstate', function () {
        var targetUrl = new URL(window.location.href);
        if (!shouldHandleAsSpa(targetUrl)) {
          return;
        }
        navigateSpa(targetUrl, false);
      });

      bindCustomerModal();
      bindQuoteModal();
      bindQuotePreview();
      bindDeleteConfirmModal();
      bindQuoteFilters();
      bindQuoteQuickState();
    })();
  </script>
</body>
</html>
