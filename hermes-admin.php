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

$currentRole = (string)($_SESSION['hermes_role'] ?? '');
$normalizedRole = strtolower(trim($currentRole));
if (!in_array($normalizedRole, ['adm_master', 'master_admin'], true)) {
    http_response_code(403);
    echo 'Acceso denegado.';
    exit;
}

function h($value)
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function normalize_slug($name)
{
    $slug = strtolower(trim($name));
    $slug = preg_replace('/[^a-z0-9]+/', '-', $slug);
    $slug = trim((string)$slug, '-');
    if ($slug === '') {
        $slug = 'tenant';
    }
    return substr($slug, 0, 80);
}

function signup_status_label($status)
{
    $s = strtolower(trim((string)$status));
    if ($s === 'pending_email_verification') {
        return 'Pendiente verificacion email';
    }
  if ($s === 'email_verified') {
    return 'Email verificado';
  }
    if ($s === 'pending_payment') {
        return 'Pendiente pago';
    }
    if ($s === 'payment_confirmed') {
        return 'Pago confirmado';
    }
    if ($s === 'active') {
        return 'Activo';
    }
    if ($s === 'suspended') {
        return 'Suspendido';
    }
    return $status;
}

function plan_name($plan)
{
    $p = strtolower(trim((string)$plan));
    if ($p === 'pro') {
        return 'Pro';
    }
    if ($p === 'enterprise') {
        return 'Enterprise';
    }
    return 'Basico';
}

  function default_plan_prices_clp()
  {
    return [
      'basico' => 350,
      'pro' => 990,
      'enterprise' => 1990,
    ];
  }

function load_secure_mp_credentials()
{
  $path = __DIR__ . '/.flow_credentials.php';
  if (!is_file($path) || !is_readable($path)) {
    return null;
  }

  $cfg = @include $path;
  if (!is_array($cfg)) {
    return null;
  }

  return $cfg;
}

function load_mp_db_crypto_key()
{
  $path = __DIR__ . '/.mp_secrets_key.php';
  if (!is_file($path) || !is_readable($path)) {
    return null;
  }

  $cfg = @include $path;
  if (!is_array($cfg)) {
    return null;
  }

  $key = (string)($cfg['db_crypto_key'] ?? '');
  if (strlen($key) < 32) {
    return null;
  }

  return hash('sha256', $key, true);
}

function mp_encrypt_value($plainText, $binaryKey)
{
  $iv = random_bytes(16);
  $cipher = openssl_encrypt((string)$plainText, 'AES-256-CBC', $binaryKey, OPENSSL_RAW_DATA, $iv);
  if ($cipher === false) {
    return null;
  }
  return base64_encode($iv . $cipher);
}

function mp_decrypt_value($encodedCipher, $binaryKey)
{
  $raw = base64_decode((string)$encodedCipher, true);
  if ($raw === false || strlen($raw) <= 16) {
    return null;
  }
  $iv = substr($raw, 0, 16);
  $cipher = substr($raw, 16);
  $plain = openssl_decrypt($cipher, 'AES-256-CBC', $binaryKey, OPENSSL_RAW_DATA, $iv);
  if ($plain === false) {
    return null;
  }
  return $plain;
}

  function column_exists(PDO $pdo, $tableName, $columnName)
  {
    $st = $pdo->prepare(
      'SELECT 1
       FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = :table_name
         AND COLUMN_NAME = :column_name
       LIMIT 1'
    );
    $st->execute([
      'table_name' => $tableName,
      'column_name' => $columnName,
    ]);
    return (bool)$st->fetchColumn();
  }

  function ensure_column(PDO $pdo, $tableName, $columnName, $definitionSql)
  {
    if (!column_exists($pdo, $tableName, $columnName)) {
      $pdo->exec('ALTER TABLE `' . $tableName . '` ADD COLUMN `' . $columnName . '` ' . $definitionSql);
    }
  }

$allowedModules = ['dashboard', 'onboarding', 'tenants', 'planes', 'pasarela'];
$module = (string)($_GET['module'] ?? 'dashboard');
if (!in_array($module, $allowedModules, true)) {
    $module = 'dashboard';
}

$planCatalog = [
    'basico' => [
        'name' => 'Basico',
        'features' => [
            'Clientes y tecnicos base',
            'Ordenes operativas esenciales',
            '1 usuario administrador de empresa',
        ],
    ],
    'pro' => [
        'name' => 'Pro',
        'features' => [
            'Todo Basico + reportes ampliados',
            'Multiples usuarios operativos',
            'Dashboard de productividad',
        ],
    ],
    'enterprise' => [
        'name' => 'Enterprise',
        'features' => [
            'Todo Pro + personalizacion',
            'SLA y soporte prioritario',
            'Politicas avanzadas y auditoria',
        ],
    ],
];

$flash = ['type' => '', 'message' => ''];
$planPricing = default_plan_prices_clp();
$stats = [
    'signups_total' => 0,
    'email_ok' => 0,
    'pending_payment' => 0,
    'paid' => 0,
    'active_tenants' => 0,
    'suspended_tenants' => 0,
    'pasarela_activa' => 0,
];

$signups = [];
$tenants = [];

$paymentConfig = [
    'is_enabled' => 0,
    'environment' => 'sandbox',
    'public_key' => '',
    'public_key_masked' => '',
    'has_public_key' => 0,
  'access_token' => '',
  'access_token_masked' => '',
  'has_access_token' => 0,
    'storage_mode' => 'db',
    'webhook_url' => '',
];

try {
    $cfg = require __DIR__ . '/.db_credentials.php';
    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $cfg['host'], (int)$cfg['port'], $cfg['dbname'], $cfg['charset']);
    $pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS account_signups (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(190) NOT NULL,
            company_name VARCHAR(190) NOT NULL,
            contact_name VARCHAR(190) NOT NULL,
            phone VARCHAR(40) NULL,
            password_hash VARCHAR(255) NOT NULL,
            status VARCHAR(40) NOT NULL DEFAULT "pending_email_verification",
            payment_status VARCHAR(20) NOT NULL DEFAULT "unpaid",
            plan_code VARCHAR(40) NOT NULL DEFAULT "basico",
            tenant_company_id BIGINT UNSIGNED NULL,
            verification_token_hash CHAR(64) NULL,
            verification_expires_at DATETIME NULL,
            email_verified_at DATETIME NULL,
            activated_at DATETIME NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_account_signups_email (email),
            KEY idx_account_signups_status (status),
            KEY idx_account_signups_payment (payment_status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS tenant_companies (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            signup_id BIGINT UNSIGNED NULL,
            company_name VARCHAR(190) NOT NULL,
            company_slug VARCHAR(90) NOT NULL,
            owner_email VARCHAR(190) NOT NULL,
            contact_name VARCHAR(190) NULL,
            phone VARCHAR(40) NULL,
            plan_code VARCHAR(40) NOT NULL DEFAULT "basico",
            plan_status VARCHAR(40) NOT NULL DEFAULT "pending_payment",
            is_enabled TINYINT(1) NOT NULL DEFAULT 0,
            status VARCHAR(40) NOT NULL DEFAULT "pending_payment",
            created_by VARCHAR(190) NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_tenant_companies_slug (company_slug),
            UNIQUE KEY uq_tenant_companies_email (owner_email),
            UNIQUE KEY uq_tenant_companies_signup (signup_id),
            KEY idx_tenant_companies_plan (plan_code),
            KEY idx_tenant_companies_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );

      $pdo->exec(
        'CREATE TABLE IF NOT EXISTS plan_pricing (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          plan_code VARCHAR(40) NOT NULL,
          amount_clp INT UNSIGNED NOT NULL DEFAULT 350,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY uq_plan_pricing_code (plan_code)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
      );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS payment_method_settings (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            method_code VARCHAR(50) NOT NULL,
            is_enabled TINYINT(1) NOT NULL DEFAULT 0,
            environment VARCHAR(20) NOT NULL DEFAULT "sandbox",
            public_key VARCHAR(255) NULL,
            access_token VARCHAR(255) NULL,
            webhook_url VARCHAR(255) NULL,
            updated_by VARCHAR(190) NULL,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_payment_method_code (method_code)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );

      // Compatibilidad con instalaciones anteriores del esquema.
      ensure_column($pdo, 'account_signups', 'payment_status', 'VARCHAR(20) NOT NULL DEFAULT "unpaid"');
      ensure_column($pdo, 'account_signups', 'plan_code', 'VARCHAR(40) NOT NULL DEFAULT "basico"');
      ensure_column($pdo, 'account_signups', 'tenant_company_id', 'BIGINT UNSIGNED NULL');
      ensure_column($pdo, 'account_signups', 'activated_at', 'DATETIME NULL');

      ensure_column($pdo, 'tenant_companies', 'signup_id', 'BIGINT UNSIGNED NULL');
      ensure_column($pdo, 'tenant_companies', 'owner_email', 'VARCHAR(190) NULL');
      ensure_column($pdo, 'tenant_companies', 'contact_name', 'VARCHAR(190) NULL');
      ensure_column($pdo, 'tenant_companies', 'plan_status', 'VARCHAR(40) NOT NULL DEFAULT "pending_payment"');
      ensure_column($pdo, 'tenant_companies', 'is_enabled', 'TINYINT(1) NOT NULL DEFAULT 0');
      ensure_column($pdo, 'payment_method_settings', 'public_key_enc', 'TEXT NULL');
      ensure_column($pdo, 'payment_method_settings', 'access_token_enc', 'TEXT NULL');

      if (column_exists($pdo, 'tenant_companies', 'business_email') && column_exists($pdo, 'tenant_companies', 'owner_email')) {
        $pdo->exec(
          'UPDATE tenant_companies
           SET owner_email = business_email
           WHERE (owner_email IS NULL OR owner_email = "")
             AND business_email IS NOT NULL
             AND business_email <> ""'
        );

        // Algunas instalaciones legacy tienen business_email NOT NULL sin default.
        // Esto rompe INSERTs nuevos que usan owner_email. Normalizamos el esquema.
        try {
          $pdo->exec('ALTER TABLE tenant_companies MODIFY business_email VARCHAR(190) NULL');
        } catch (Throwable $ignored) {
          // Si la definición ya está correcta o el motor no permite la modificación, continuamos.
        }

        $pdo->exec(
          'UPDATE tenant_companies
           SET business_email = owner_email
           WHERE (business_email IS NULL OR business_email = "")
             AND owner_email IS NOT NULL
             AND owner_email <> ""'
        );
      }

      $pdo->exec(
        'UPDATE tenant_companies
         SET is_enabled = 1
         WHERE status = "active"
           AND is_enabled = 0'
      );

      $pdo->exec(
        'UPDATE tenant_companies
         SET plan_status = "paid"
         WHERE status = "active"
           AND plan_status = "pending_payment"'
      );

      $seedPlanPrice = $pdo->prepare(
        'INSERT INTO plan_pricing (plan_code, amount_clp)
         VALUES (:plan_code, :amount_clp)
         ON DUPLICATE KEY UPDATE plan_code = plan_code'
      );
      foreach (default_plan_prices_clp() as $seedPlanCode => $seedAmount) {
        $seedPlanPrice->execute([
          'plan_code' => $seedPlanCode,
          'amount_clp' => (int)$seedAmount,
        ]);
      }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
        $action = (string)$_POST['action'];

        if ($action === 'mark_paid_signup') {
            $signupId = (int)($_POST['signup_id'] ?? 0);
            if ($signupId > 0) {
                $up = $pdo->prepare(
                    'UPDATE account_signups
                     SET payment_status = :payment_status,
                         status = CASE WHEN status = "pending_payment" THEN "payment_confirmed" ELSE status END
                     WHERE id = :id'
                );
                $up->execute([
                    'payment_status' => 'paid',
                    'id' => $signupId,
                ]);
                $flash = ['type' => 'ok', 'message' => 'Pago marcado como confirmado.'];
            } else {
                $flash = ['type' => 'err', 'message' => 'No se pudo identificar la cuenta a actualizar.'];
            }
            $module = 'onboarding';
        }

        if ($action === 'activate_signup') {
            $signupId = (int)($_POST['signup_id'] ?? 0);
            if ($signupId <= 0) {
                $flash = ['type' => 'err', 'message' => 'Cuenta invalida para activar.'];
            } else {
                $st = $pdo->prepare(
                    'SELECT id, email, company_name, contact_name, phone, plan_code, status, payment_status, email_verified_at, tenant_company_id
                     FROM account_signups
                     WHERE id = :id
                     LIMIT 1'
                );
                $st->execute(['id' => $signupId]);
                $signup = $st->fetch();

                if (!$signup) {
                    $flash = ['type' => 'err', 'message' => 'No se encontro la cuenta a activar.'];
                } elseif (empty($signup['email_verified_at'])) {
                    $flash = ['type' => 'err', 'message' => 'No se puede activar: el correo aun no esta verificado.'];
                } elseif ((string)$signup['payment_status'] !== 'paid') {
                    $flash = ['type' => 'err', 'message' => 'No se puede activar: el plan aun no tiene pago confirmado.'];
                } else {
                    $companyId = (int)($signup['tenant_company_id'] ?? 0);
                    $planCode = strtolower(trim((string)($signup['plan_code'] ?? 'basico')));
                    if (!isset($planCatalog[$planCode])) {
                        $planCode = 'basico';
                    }

                    if ($companyId > 0) {
                        $upTenant = $pdo->prepare(
                            'UPDATE tenant_companies
                             SET company_name = :company_name,
                                 owner_email = :owner_email,
                                 contact_name = :contact_name,
                                 phone = :phone,
                                 plan_code = :plan_code,
                                 plan_status = :plan_status,
                                 status = :status,
                                 is_enabled = :is_enabled
                             WHERE id = :id'
                        );
                        $upTenant->execute([
                            'company_name' => (string)$signup['company_name'],
                            'owner_email' => (string)$signup['email'],
                            'contact_name' => (string)$signup['contact_name'],
                            'phone' => ((string)$signup['phone'] !== '' ? (string)$signup['phone'] : null),
                            'plan_code' => $planCode,
                            'plan_status' => 'paid',
                            'status' => 'active',
                            'is_enabled' => 1,
                            'id' => $companyId,
                        ]);
                    } else {
                        $baseSlug = normalize_slug((string)$signup['company_name']);
                        $slug = $baseSlug;
                        $suffix = 1;
                        while (true) {
                            $stSlug = $pdo->prepare('SELECT id FROM tenant_companies WHERE company_slug = :slug LIMIT 1');
                            $stSlug->execute(['slug' => $slug]);
                            if (!$stSlug->fetch()) {
                                break;
                            }
                            $suffix++;
                            $slug = substr($baseSlug, 0, 75) . '-' . $suffix;
                        }

                        $insTenant = $pdo->prepare(
                            'INSERT INTO tenant_companies (signup_id, company_name, company_slug, owner_email, contact_name, phone, plan_code, plan_status, is_enabled, status, created_by)
                             VALUES (:signup_id, :company_name, :company_slug, :owner_email, :contact_name, :phone, :plan_code, :plan_status, :is_enabled, :status, :created_by)'
                        );
                        $insTenant->execute([
                            'signup_id' => (int)$signup['id'],
                            'company_name' => (string)$signup['company_name'],
                            'company_slug' => $slug,
                            'owner_email' => (string)$signup['email'],
                            'contact_name' => (string)$signup['contact_name'],
                            'phone' => ((string)$signup['phone'] !== '' ? (string)$signup['phone'] : null),
                            'plan_code' => $planCode,
                            'plan_status' => 'paid',
                            'is_enabled' => 1,
                            'status' => 'active',
                            'created_by' => (string)$_SESSION['hermes_user'],
                        ]);
                        $companyId = (int)$pdo->lastInsertId();
                    }

                    $upSignup = $pdo->prepare(
                        'UPDATE account_signups
                         SET status = :status,
                             payment_status = :payment_status,
                             tenant_company_id = :tenant_company_id,
                             activated_at = NOW()
                         WHERE id = :id'
                    );
                    $upSignup->execute([
                        'status' => 'active',
                        'payment_status' => 'paid',
                        'tenant_company_id' => $companyId,
                        'id' => (int)$signup['id'],
                    ]);

                    $flash = ['type' => 'ok', 'message' => 'Cuenta activada como tenant y lista para uso segun plan.'];
                }
            }
            $module = 'onboarding';
        }

        if ($action === 'set_tenant_access') {
            $tenantId = (int)($_POST['tenant_id'] ?? 0);
            $planCode = strtolower(trim((string)($_POST['plan_code'] ?? 'basico')));
            $planStatus = strtolower(trim((string)($_POST['plan_status'] ?? 'pending_payment')));
            $isEnabled = isset($_POST['is_enabled']) ? 1 : 0;

            if (!isset($planCatalog[$planCode])) {
                $planCode = 'basico';
            }
            if (!in_array($planStatus, ['pending_payment', 'paid', 'suspended'], true)) {
                $planStatus = 'pending_payment';
            }

            if ($tenantId > 0) {
                $status = 'pending_payment';
                if ($planStatus === 'paid' && $isEnabled === 1) {
                    $status = 'active';
                }
                if ($planStatus === 'suspended' || $isEnabled === 0) {
                    $status = 'suspended';
                }

                $upTenant = $pdo->prepare(
                    'UPDATE tenant_companies
                     SET plan_code = :plan_code,
                         plan_status = :plan_status,
                         is_enabled = :is_enabled,
                         status = :status
                     WHERE id = :id'
                );
                $upTenant->execute([
                    'plan_code' => $planCode,
                    'plan_status' => $planStatus,
                    'is_enabled' => $isEnabled,
                    'status' => $status,
                    'id' => $tenantId,
                ]);

                $upSignup = $pdo->prepare(
                    'UPDATE account_signups
                     SET plan_code = :plan_code,
                         payment_status = CASE WHEN :plan_status = "paid" THEN "paid" ELSE payment_status END,
                         status = CASE WHEN :status = "active" THEN "active" WHEN :status = "suspended" THEN "suspended" ELSE status END
                     WHERE tenant_company_id = :tenant_company_id'
                );
                $upSignup->execute([
                    'plan_code' => $planCode,
                    'plan_status' => $planStatus,
                    'status' => $status,
                    'tenant_company_id' => $tenantId,
                ]);

                $flash = ['type' => 'ok', 'message' => 'Acceso y plan del tenant actualizados.'];
            } else {
                $flash = ['type' => 'err', 'message' => 'No se pudo identificar el tenant a actualizar.'];
            }
            $module = 'planes';
        }

          if ($action === 'save_plan_pricing') {
            $upPrice = $pdo->prepare(
              'INSERT INTO plan_pricing (plan_code, amount_clp)
               VALUES (:plan_code, :amount_clp)
               ON DUPLICATE KEY UPDATE amount_clp = VALUES(amount_clp)'
            );

            foreach (array_keys($planCatalog) as $planCode) {
              $raw = (string)($_POST['price_' . $planCode] ?? '');
              $amount = (int)preg_replace('/[^0-9]/', '', $raw);
              if ($amount < 350) {
                $amount = 350;
              }
              $upPrice->execute([
                'plan_code' => $planCode,
                'amount_clp' => $amount,
              ]);
            }

            $flash = ['type' => 'ok', 'message' => 'Valores de planes actualizados correctamente.'];
            $module = 'planes';
          }

        if ($action === 'save_flow') {
            $isEnabled = isset($_POST['is_enabled']) ? 1 : 0;
            $environment = (string)($_POST['environment'] ?? 'sandbox');
            $publicKey = trim((string)($_POST['public_key'] ?? ''));
            $accessToken = trim((string)($_POST['access_token'] ?? ''));
            $webhookUrl = trim((string)($_POST['webhook_url'] ?? ''));
          $currentPublicKey = '';
          $currentAccessToken = '';
          $currentPublicKeyEnc = '';
          $currentAccessTokenEnc = '';
          $cryptoKey = load_mp_db_crypto_key();

          $stCurrentCfg = $pdo->prepare(
            'SELECT public_key, access_token, public_key_enc, access_token_enc
             FROM payment_method_settings
             WHERE method_code = :method_code
             LIMIT 1'
          );
          $stCurrentCfg->execute(['method_code' => 'flow']);
          $rowCurrentCfg = $stCurrentCfg->fetch();
          if ($rowCurrentCfg) {
            $currentPublicKey = (string)($rowCurrentCfg['public_key'] ?? '');
            $currentAccessToken = (string)($rowCurrentCfg['access_token'] ?? '');
            $currentPublicKeyEnc = (string)($rowCurrentCfg['public_key_enc'] ?? '');
            $currentAccessTokenEnc = (string)($rowCurrentCfg['access_token_enc'] ?? '');
          }

          $savePublicKey = ($publicKey !== '' ? $publicKey : $currentPublicKey);
          $saveAccessToken = ($accessToken !== '' ? $accessToken : $currentAccessToken);
          $savePublicKeyEnc = ($publicKey !== '' ? '' : $currentPublicKeyEnc);
          $saveAccessTokenEnc = ($accessToken !== '' ? '' : $currentAccessTokenEnc);

          if ($cryptoKey !== null) {
            if ($publicKey !== '') {
              $enc = mp_encrypt_value($publicKey, $cryptoKey);
              if ($enc !== null) {
                $savePublicKeyEnc = $enc;
                $savePublicKey = '';
              }
            }
            if ($accessToken !== '') {
              $enc = mp_encrypt_value($accessToken, $cryptoKey);
              if ($enc !== null) {
                $saveAccessTokenEnc = $enc;
                $saveAccessToken = '';
              }
            }
          }

            if ($environment !== 'sandbox' && $environment !== 'production') {
                $environment = 'sandbox';
            }

            $up = $pdo->prepare(
              'INSERT INTO payment_method_settings (method_code, is_enabled, environment, public_key, access_token, public_key_enc, access_token_enc, webhook_url, updated_by)
               VALUES (:method_code, :is_enabled, :environment, :public_key, :access_token, :public_key_enc, :access_token_enc, :webhook_url, :updated_by)
                 ON DUPLICATE KEY UPDATE
                    is_enabled = VALUES(is_enabled),
                    environment = VALUES(environment),
                    public_key = VALUES(public_key),
                    access_token = VALUES(access_token),
                public_key_enc = VALUES(public_key_enc),
                access_token_enc = VALUES(access_token_enc),
                    webhook_url = VALUES(webhook_url),
                    updated_by = VALUES(updated_by)'
            );
            $up->execute([
                'method_code' => 'flow',
                'is_enabled' => $isEnabled,
                'environment' => $environment,
              'public_key' => ($savePublicKey !== '' ? $savePublicKey : null),
              'access_token' => ($saveAccessToken !== '' ? $saveAccessToken : null),
              'public_key_enc' => ($savePublicKeyEnc !== '' ? $savePublicKeyEnc : null),
              'access_token_enc' => ($saveAccessTokenEnc !== '' ? $saveAccessTokenEnc : null),
                'webhook_url' => ($webhookUrl !== '' ? $webhookUrl : null),
                'updated_by' => (string)$_SESSION['hermes_user'],
            ]);

            $flash = ['type' => 'ok', 'message' => 'Configuracion de Flow actualizada.'];
            $module = 'pasarela';
        }
    }

    $stats['signups_total'] = (int)$pdo->query('SELECT COUNT(*) FROM account_signups')->fetchColumn();
    $stats['email_ok'] = (int)$pdo->query('SELECT COUNT(*) FROM account_signups WHERE email_verified_at IS NOT NULL')->fetchColumn();
    $stats['pending_payment'] = (int)$pdo->query('SELECT COUNT(*) FROM account_signups WHERE status = "pending_payment" OR payment_status = "unpaid"')->fetchColumn();
    $stats['paid'] = (int)$pdo->query('SELECT COUNT(*) FROM account_signups WHERE payment_status = "paid"')->fetchColumn();
    $stats['active_tenants'] = (int)$pdo->query('SELECT COUNT(*) FROM tenant_companies WHERE status = "active" AND is_enabled = 1')->fetchColumn();
    $stats['suspended_tenants'] = (int)$pdo->query('SELECT COUNT(*) FROM tenant_companies WHERE status = "suspended" OR is_enabled = 0')->fetchColumn();

    $signups = $pdo->query(
        'SELECT id, email, company_name, contact_name, phone, plan_code, status, payment_status, email_verified_at, activated_at, created_at
         FROM account_signups
         ORDER BY id DESC
         LIMIT 120'
    )->fetchAll();

    $tenants = $pdo->query(
        'SELECT id, signup_id, company_name, company_slug, owner_email, contact_name, phone, plan_code, plan_status, is_enabled, status, created_at
         FROM tenant_companies
         ORDER BY id DESC
         LIMIT 120'
    )->fetchAll();

    $priceRows = $pdo->query('SELECT plan_code, amount_clp FROM plan_pricing')->fetchAll();
    foreach ($priceRows as $rowPrice) {
      $code = strtolower(trim((string)($rowPrice['plan_code'] ?? '')));
      if (isset($planCatalog[$code])) {
        $planPricing[$code] = max(350, (int)($rowPrice['amount_clp'] ?? 350));
      }
    }

    $stPayment = $pdo->prepare(
      'SELECT is_enabled, environment, public_key, access_token, public_key_enc, access_token_enc, webhook_url
         FROM payment_method_settings
         WHERE method_code = :method_code
         LIMIT 1'
    );
    $stPayment->execute(['method_code' => 'flow']);
    $rowPayment = $stPayment->fetch();
    if ($rowPayment) {
        $cryptoKey = load_mp_db_crypto_key();
        $paymentConfig['is_enabled'] = (int)$rowPayment['is_enabled'];
        $paymentConfig['environment'] = (string)$rowPayment['environment'];
      $storedPublicKey = (string)($rowPayment['public_key'] ?? '');
      $storedPublicKeyEnc = (string)($rowPayment['public_key_enc'] ?? '');
      if ($storedPublicKeyEnc !== '' && $cryptoKey !== null) {
        $decrypted = mp_decrypt_value($storedPublicKeyEnc, $cryptoKey);
        if (is_string($decrypted) && $decrypted !== '') {
          $storedPublicKey = $decrypted;
        }
      }
      $paymentConfig['has_public_key'] = ($storedPublicKey !== '' ? 1 : 0);
      if ($storedPublicKey !== '') {
        $publicKeyTail = substr($storedPublicKey, -4);
        $paymentConfig['public_key_masked'] = '********' . $publicKeyTail;
      }
      $storedAccessToken = (string)($rowPayment['access_token'] ?? '');
      $storedAccessTokenEnc = (string)($rowPayment['access_token_enc'] ?? '');
      if ($storedAccessTokenEnc !== '' && $cryptoKey !== null) {
        $decrypted = mp_decrypt_value($storedAccessTokenEnc, $cryptoKey);
        if (is_string($decrypted) && $decrypted !== '') {
          $storedAccessToken = $decrypted;
        }
      }
      $paymentConfig['has_access_token'] = ($storedAccessToken !== '' ? 1 : 0);
      if ($storedAccessToken !== '') {
        $tokenTail = substr($storedAccessToken, -4);
        $paymentConfig['access_token_masked'] = '********' . $tokenTail;
      }
        $paymentConfig['webhook_url'] = (string)($rowPayment['webhook_url'] ?? '');
    }

    $stats['pasarela_activa'] = (int)$paymentConfig['is_enabled'];
} catch (Throwable $e) {
    $flash = ['type' => 'err', 'message' => 'No fue posible cargar la informacion del panel maestro.'];
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Panel maestro SaaS | GesMan HERMES</title>
  <meta name="description" content="Control multitenancy para onboarding, pagos y acceso por plan.">
  <link rel="icon" type="image/svg+xml" href="/assets/img/favicon-hermes.svg">
  <style>
    :root {
      --bg-1: #07112a;
      --bg-2: #101d40;
      --card: #0f1a34;
      --line: #2a3a62;
      --gold: #f4b400;
      --gold-2: #ffe38b;
      --txt: #f8fafc;
      --muted: #9fb0cf;
      --ok: #86efac;
      --danger: #fda4af;
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
    }
    .layout { display: grid; grid-template-columns: 290px 1fr; min-height: 100vh; }
    .side {
      border-right: 1px solid var(--line);
      background: rgba(7,17,42,.88);
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .brand svg { width: 220px; max-width: 100%; height: auto; }
    .user-box {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: .7rem;
      background: rgba(15,26,52,.8);
      font-size: .88rem;
      color: var(--muted);
    }
    .menu { display: grid; gap: .45rem; }
    .menu a {
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
    .content { padding: 1.1rem; }
    .top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: .8rem;
      margin-bottom: .8rem;
      flex-wrap: wrap;
    }
    .top h1 { margin: 0; font-size: 1.32rem; color: #fff4b8; }
    .actions { display: flex; gap: .5rem; flex-wrap: wrap; }
    .btn {
      border: 1px solid #8b6500;
      border-radius: 10px;
      background: linear-gradient(180deg, #ffe38b, #f4b400);
      color: #1f2937;
      font-weight: 700;
      letter-spacing: .02em;
      padding: .58rem .84rem;
      font-size: .86rem;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
    }
    .btn.ghost { border-color: #4b5e8c; background: #0f172a; color: #d3dcef; }
    .btn.small { padding: .38rem .56rem; font-size: .78rem; }
    .flash {
      border: 1px solid;
      border-radius: 10px;
      padding: .62rem .72rem;
      margin-bottom: .85rem;
      font-size: .9rem;
    }
    .flash.ok { color: var(--ok); border-color: #14532d; background: rgba(20,83,45,.2); }
    .flash.err { color: var(--danger); border-color: #7f1d1d; background: rgba(127,29,29,.2); }

    .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .65rem; margin-bottom: .9rem; }
    .card {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(15,26,52,.82);
      padding: .78rem;
    }
    .kpi { font-size: 1.42rem; font-weight: 700; margin: .2rem 0 0; color: var(--gold-2); }
    .label { font-size: .83rem; color: var(--muted); }

    .panel {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(15,26,52,.82);
      padding: .82rem;
      margin-bottom: .8rem;
    }
    .panel h2 { margin: .2rem 0 .8rem; font-size: 1.03rem; color: #fff4b8; }
    .muted { color: var(--muted); font-size: .84rem; }

    table { width: 100%; border-collapse: collapse; font-size: .86rem; }
    th, td {
      border-bottom: 1px solid rgba(75,94,140,.5);
      text-align: left;
      padding: .49rem .41rem;
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 600; }

    .tag {
      display: inline-block;
      border: 1px solid rgba(255,227,139,.35);
      color: #ffe38b;
      border-radius: 999px;
      padding: .12rem .5rem;
      font-size: .75rem;
    }

    .status {
      font-size: .77rem;
      border-radius: 999px;
      padding: .12rem .45rem;
      border: 1px solid;
      display: inline-block;
    }
    .status.ok { color: #86efac; border-color: #166534; }
    .status.warn { color: #fef08a; border-color: #a16207; }
    .status.bad { color: #fecaca; border-color: #991b1b; }

    .stack { display: grid; gap: .45rem; }
    .stack li { color: var(--muted); font-size: .86rem; }

    .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: .68rem; }
    .row { display: grid; gap: .3rem; }
    .row.full { grid-column: 1 / -1; }
    label { color: var(--muted); font-size: .85rem; }
    input, select {
      border: 1px solid #475569;
      border-radius: 10px;
      background: #0f172a;
      color: var(--txt);
      padding: .63rem .72rem;
      font-size: .88rem;
      outline: none;
    }
    input:focus, select:focus { border-color: var(--gold-2); box-shadow: 0 0 0 3px rgba(255,216,77,.2); }
    .check {
      display: flex;
      align-items: center;
      gap: .45rem;
      color: var(--muted);
      font-size: .84rem;
      margin-top: .2rem;
    }

    @media (max-width: 1120px) {
      .cards { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 940px) {
      .layout { grid-template-columns: 1fr; }
      .side { border-right: 0; border-bottom: 1px solid var(--line); }
      .form-grid { grid-template-columns: 1fr; }
      .cards { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <aside class="side">
      <div class="brand"><?php readfile(__DIR__ . '/assets/img/logo-hermes-page.svg'); ?></div>
      <div class="user-box">
        Usuario: <strong><?= h((string)$_SESSION['hermes_user']) ?></strong><br>
        Rol: <strong><?= h($currentRole) ?></strong>
      </div>
      <nav class="menu" aria-label="Modulos admin">
        <a class="<?= $module === 'dashboard' ? 'active' : '' ?>" href="/admin/?module=dashboard">Dashboard</a>
        <a class="<?= $module === 'onboarding' ? 'active' : '' ?>" href="/admin/?module=onboarding">Onboarding y pagos</a>
        <a class="<?= $module === 'tenants' ? 'active' : '' ?>" href="/admin/?module=tenants">Tenants activos</a>
        <a class="<?= $module === 'planes' ? 'active' : '' ?>" href="/admin/?module=planes">Planes y acceso</a>
        <a class="<?= $module === 'pasarela' ? 'active' : '' ?>" href="/admin/?module=pasarela">Pasarela de pago</a>
      </nav>
    </aside>

    <main class="content">
      <div class="top">
        <h1>Panel maestro multitenancy</h1>
        <div class="actions">
          <a class="btn ghost" href="/">Ir a HERMES</a>
          <form method="post" style="margin:0;">
            <input type="hidden" name="logout" value="1">
            <button class="btn ghost" type="submit">Cerrar sesion</button>
          </form>
        </div>
      </div>

      <?php if ($flash['message'] !== ''): ?>
        <div class="flash <?= $flash['type'] === 'ok' ? 'ok' : 'err' ?>"><?= h($flash['message']) ?></div>
      <?php endif; ?>

      <?php if ($module === 'dashboard'): ?>
        <section class="cards">
          <article class="card"><div class="label">Registros</div><div class="kpi"><?= h((string)$stats['signups_total']) ?></div></article>
          <article class="card"><div class="label">Email verificado</div><div class="kpi"><?= h((string)$stats['email_ok']) ?></div></article>
          <article class="card"><div class="label">Pago confirmado</div><div class="kpi"><?= h((string)$stats['paid']) ?></div></article>
          <article class="card"><div class="label">Pendiente pago</div><div class="kpi"><?= h((string)$stats['pending_payment']) ?></div></article>
        </section>
        <section class="cards">
          <article class="card"><div class="label">Tenants activos</div><div class="kpi"><?= h((string)$stats['active_tenants']) ?></div></article>
          <article class="card"><div class="label">Tenants suspendidos</div><div class="kpi"><?= h((string)$stats['suspended_tenants']) ?></div></article>
          <article class="card"><div class="label">Flow</div><div class="kpi"><?= $stats['pasarela_activa'] === 1 ? 'Activo' : 'Inactivo' ?></div></article>
          <article class="card"><div class="label">Modelo</div><div class="kpi">SaaS B2B</div></article>
        </section>
        <section class="panel">
          <h2>Enfoque correcto para tu negocio</h2>
          <ul class="stack">
            <li>El admin maestro valida ciclo comercial: registro, email, pago y activacion.</li>
            <li>Cada empresa gestiona sus propios clientes, tecnicos y operacion interna.</li>
            <li>El acceso del tenant se habilita segun plan pagado y estado activo.</li>
          </ul>
        </section>
      <?php endif; ?>

      <?php if ($module === 'onboarding'): ?>
        <section class="panel">
          <h2>Onboarding: verificacion y cobro</h2>
          <p class="muted">Aqui controlas cuentas registradas, estado de email, pago y activacion de tenant.</p>
          <p class="muted">El boton <strong>Activar tenant</strong> crea (o actualiza) el tenant productivo de la empresa, habilita acceso e integra el plan pagado en su cuenta.</p>
          <table>
            <thead>
              <tr>
                <th>Empresa</th>
                <th>Contacto</th>
                <th>Email</th>
                <th>Plan</th>
                <th>Email OK</th>
                <th>Pago</th>
                <th>Estado</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              <?php if (count($signups) === 0): ?>
                <tr><td colspan="8">No hay registros de onboarding.</td></tr>
              <?php else: ?>
                <?php foreach ($signups as $s): ?>
                  <tr>
                    <td><?= h($s['company_name']) ?></td>
                    <td><?= h($s['contact_name']) ?></td>
                    <td><?= h($s['email']) ?></td>
                    <td><span class="tag"><?= h(plan_name($s['plan_code'])) ?></span></td>
                    <td>
                      <?php if (!empty($s['email_verified_at'])): ?>
                        <span class="status ok">Verificado</span>
                      <?php else: ?>
                        <span class="status warn">Pendiente</span>
                      <?php endif; ?>
                    </td>
                    <td>
                      <?php if ((string)$s['payment_status'] === 'paid'): ?>
                        <span class="status ok">Pagado</span>
                      <?php else: ?>
                        <span class="status warn">No pagado</span>
                      <?php endif; ?>
                    </td>
                    <td><span class="status <?= ((string)$s['status'] === 'active' ? 'ok' : (((string)$s['status'] === 'suspended') ? 'bad' : 'warn')) ?>"><?= h(signup_status_label($s['status'])) ?></span></td>
                    <td>
                      <div style="display:grid; gap:.35rem;">
                        <?php if ((string)$s['payment_status'] !== 'paid'): ?>
                          <form method="post">
                            <input type="hidden" name="action" value="mark_paid_signup">
                            <input type="hidden" name="signup_id" value="<?= (int)$s['id'] ?>">
                            <button class="btn small" type="submit">Marcar pago</button>
                          </form>
                        <?php endif; ?>
                        <?php if ((string)$s['status'] !== 'active'): ?>
                          <form method="post">
                            <input type="hidden" name="action" value="activate_signup">
                            <input type="hidden" name="signup_id" value="<?= (int)$s['id'] ?>">
                            <button class="btn small" type="submit" title="Crea/actualiza tenant, habilita acceso y marca la cuenta lista para uso">Activar tenant</button>
                          </form>
                        <?php endif; ?>
                      </div>
                    </td>
                  </tr>
                <?php endforeach; ?>
              <?php endif; ?>
            </tbody>
          </table>
        </section>
      <?php endif; ?>

      <?php if ($module === 'tenants'): ?>
        <section class="panel">
          <h2>Tenants activos y estado operacional</h2>
          <table>
            <thead>
              <tr>
                <th>Empresa</th>
                <th>Slug</th>
                <th>Owner email</th>
                <th>Plan</th>
                <th>Plan status</th>
                <th>Acceso</th>
                <th>Estado</th>
                <th>Fecha alta</th>
              </tr>
            </thead>
            <tbody>
              <?php if (count($tenants) === 0): ?>
                <tr><td colspan="8">No hay tenants activados aun.</td></tr>
              <?php else: ?>
                <?php foreach ($tenants as $t): ?>
                  <tr>
                    <td><?= h($t['company_name']) ?></td>
                    <td><?= h($t['company_slug']) ?></td>
                    <td><?= h($t['owner_email']) ?></td>
                    <td><span class="tag"><?= h(plan_name($t['plan_code'])) ?></span></td>
                    <td><span class="status <?= ((string)$t['plan_status'] === 'paid' ? 'ok' : (((string)$t['plan_status'] === 'suspended') ? 'bad' : 'warn')) ?>"><?= h($t['plan_status']) ?></span></td>
                    <td><span class="status <?= ((int)$t['is_enabled'] === 1 ? 'ok' : 'bad') ?>"><?= ((int)$t['is_enabled'] === 1 ? 'Habilitado' : 'Bloqueado') ?></span></td>
                    <td><span class="status <?= ((string)$t['status'] === 'active' ? 'ok' : (((string)$t['status'] === 'suspended') ? 'bad' : 'warn')) ?>"><?= h($t['status']) ?></span></td>
                    <td><?= h($t['created_at']) ?></td>
                  </tr>
                <?php endforeach; ?>
              <?php endif; ?>
            </tbody>
          </table>
        </section>
      <?php endif; ?>

      <?php if ($module === 'planes'): ?>
        <section class="panel">
          <h2>Catalogo de planes</h2>
          <div class="cards" style="margin-bottom:0;">
            <?php foreach ($planCatalog as $key => $plan): ?>
              <article class="card">
                <div class="label">Plan <?= h($plan['name']) ?></div>
                <div class="kpi" style="font-size:1.05rem;">$<?= h(number_format((int)($planPricing[$key] ?? 350), 0, ',', '.')) ?> CLP</div>
                <ul class="stack">
                  <?php foreach ($plan['features'] as $feature): ?>
                    <li><?= h($feature) ?></li>
                  <?php endforeach; ?>
                </ul>
              </article>
            <?php endforeach; ?>
          </div>
        </section>

        <section class="panel">
          <h2>Valores comerciales por plan</h2>
          <p class="muted">Define aqui el monto base en CLP que se usara para checkout de onboarding/renovacion segun plan. Minimo permitido: $350 CLP.</p>
          <form method="post" autocomplete="off">
            <input type="hidden" name="action" value="save_plan_pricing">
            <table>
              <thead>
                <tr>
                  <th>Plan</th>
                  <th>Valor (CLP)</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($planCatalog as $key => $plan): ?>
                  <tr>
                    <td><?= h($plan['name']) ?></td>
                    <td>
                      <input
                        type="number"
                        min="350"
                        step="1"
                        name="price_<?= h($key) ?>"
                        value="<?= h((string)((int)($planPricing[$key] ?? 350))) ?>"
                        style="max-width:180px;"
                        required>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
            <div class="actions" style="margin-top:.75rem;">
              <button class="btn" type="submit">Guardar valores</button>
            </div>
          </form>
        </section>

        <section class="panel">
          <h2>Asignacion de plan y acceso por tenant</h2>
          <table>
            <thead>
              <tr>
                <th>Empresa</th>
                <th>Email owner</th>
                <th>Plan</th>
                <th>Plan status</th>
                <th>Habilitado</th>
                <th>Guardar</th>
              </tr>
            </thead>
            <tbody>
              <?php if (count($tenants) === 0): ?>
                <tr><td colspan="6">No hay tenants para configurar.</td></tr>
              <?php else: ?>
                <?php foreach ($tenants as $t): ?>
                  <tr>
                    <td><?= h($t['company_name']) ?></td>
                    <td><?= h($t['owner_email']) ?></td>
                    <td>
                      <form method="post" style="display:flex; gap:.4rem; align-items:center; flex-wrap:wrap;">
                        <input type="hidden" name="action" value="set_tenant_access">
                        <input type="hidden" name="tenant_id" value="<?= (int)$t['id'] ?>">
                        <select name="plan_code">
                          <option value="basico" <?= ((string)$t['plan_code'] === 'basico' ? 'selected' : '') ?>>Basico</option>
                          <option value="pro" <?= ((string)$t['plan_code'] === 'pro' ? 'selected' : '') ?>>Pro</option>
                          <option value="enterprise" <?= ((string)$t['plan_code'] === 'enterprise' ? 'selected' : '') ?>>Enterprise</option>
                        </select>
                    </td>
                    <td>
                        <select name="plan_status">
                          <option value="pending_payment" <?= ((string)$t['plan_status'] === 'pending_payment' ? 'selected' : '') ?>>pending_payment</option>
                          <option value="paid" <?= ((string)$t['plan_status'] === 'paid' ? 'selected' : '') ?>>paid</option>
                          <option value="suspended" <?= ((string)$t['plan_status'] === 'suspended' ? 'selected' : '') ?>>suspended</option>
                        </select>
                    </td>
                    <td>
                        <label class="check" style="margin:0;">
                          <input type="checkbox" name="is_enabled" value="1" <?= ((int)$t['is_enabled'] === 1 ? 'checked' : '') ?>>
                          Acceso
                        </label>
                    </td>
                    <td>
                        <button class="btn small" type="submit">Guardar</button>
                      </form>
                    </td>
                  </tr>
                <?php endforeach; ?>
              <?php endif; ?>
            </tbody>
          </table>
        </section>
      <?php endif; ?>

      <?php if ($module === 'pasarela'): ?>
        <section class="panel">
          <h2>Configuracion de pasarela de pago</h2>
          <p class="muted">Metodo actual: Flow. Este modulo soporta el ciclo comercial de onboarding.</p>
          <form method="post" autocomplete="off">
            <input type="hidden" name="action" value="save_flow">
            <div class="form-grid">
              <div class="row">
                <label for="environment">Ambiente</label>
                <select id="environment" name="environment">
                  <option value="sandbox" <?= $paymentConfig['environment'] === 'sandbox' ? 'selected' : '' ?>>Sandbox</option>
                  <option value="production" <?= $paymentConfig['environment'] === 'production' ? 'selected' : '' ?>>Produccion</option>
                </select>
              </div>
              <div class="row">
                <label for="webhook_url">Webhook URL</label>
                <input id="webhook_url" name="webhook_url" type="text" value="<?= h($paymentConfig['webhook_url']) ?>" placeholder="https://tudominio.com/webhook/flow/">
              </div>
              <div class="row full">
                <label for="public_key">API Key</label>
                <input id="public_key" name="public_key" type="password" value="" placeholder="<?= $paymentConfig['has_public_key'] === 1 ? 'API Key guardada: ' . h($paymentConfig['public_key_masked']) . ' (deja vacio para mantenerla)' : 'flow_api_key...' ?>" autocomplete="new-password" spellcheck="false">
                <small class="muted">La API Key se mantiene oculta. Si dejas este campo vacio, se conserva la key actual.</small>
              </div>
              <div class="row full">
                <label for="access_token">Secret Key</label>
                <input id="access_token" name="access_token" type="password" value="" placeholder="<?= $paymentConfig['has_access_token'] === 1 ? 'Secret Key guardada: ' . h($paymentConfig['access_token_masked']) . ' (deja vacio para mantenerla)' : 'flow_secret_key...' ?>" autocomplete="new-password" spellcheck="false">
                <small class="muted">La Secret Key se mantiene oculta. Si dejas este campo vacio, se conserva la key actual.</small>
              </div>
              <div class="row full">
                <label class="check" for="is_enabled">
                  <input id="is_enabled" name="is_enabled" type="checkbox" value="1" <?= (int)$paymentConfig['is_enabled'] === 1 ? 'checked' : '' ?>>
                  Habilitar Flow para onboarding comercial
                </label>
              </div>
              <div class="row full">
                <button class="btn" type="submit">Guardar configuracion</button>
              </div>
            </div>
          </form>
        </section>
      <?php endif; ?>
    </main>
  </div>
</body>
</html>
