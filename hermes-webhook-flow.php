<?php
function respond_json($statusCode, $payload)
{
    http_response_code((int)$statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function ensure_column(PDO $pdo, $tableName, $columnName, $definitionSql)
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
    if (!$st->fetchColumn()) {
        $pdo->exec('ALTER TABLE `' . $tableName . '` ADD COLUMN `' . $columnName . '` ' . $definitionSql);
    }
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

function normalize_slug($name)
{
    $slug = strtolower(trim((string)$name));
    $slug = preg_replace('/[^a-z0-9]+/', '-', $slug);
    $slug = trim((string)$slug, '-');
    if ($slug === '') {
        $slug = 'tenant';
    }
    return substr($slug, 0, 80);
}

function load_secure_flow_credentials()
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

function flow_sign(array $params, $secretKey)
{
    unset($params['s']);
    ksort($params, SORT_STRING);
    $toSign = '';
    foreach ($params as $k => $v) {
        $toSign .= (string)$k . (string)$v;
    }
    return hash_hmac('sha256', $toSign, (string)$secretKey);
}

function flow_request($method, $endpoint, $apiKey, $secretKey, array $params, $environment)
{
    $baseUrl = ((string)$environment === 'production') ? 'https://www.flow.cl/api' : 'https://sandbox.flow.cl/api';
    $url = rtrim($baseUrl, '/') . '/' . ltrim((string)$endpoint, '/');
    $params['apiKey'] = (string)$apiKey;
    $params['s'] = flow_sign($params, $secretKey);

    if (strtoupper((string)$method) === 'POST') {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    } else {
        $ch = curl_init($url . '?' . http_build_query($params));
        curl_setopt($ch, CURLOPT_HTTPGET, true);
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);

    $raw = curl_exec($ch);
    $err = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($raw === false) {
        return ['ok' => false, 'http_code' => $code, 'error' => $err, 'data' => null, 'raw' => ''];
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        $data = null;
    }

    return ['ok' => $code >= 200 && $code < 300, 'http_code' => $code, 'error' => $err, 'data' => $data, 'raw' => $raw];
}

function flow_token_from_request()
{
    $token = trim((string)($_POST['token'] ?? $_GET['token'] ?? ''));
    if ($token !== '') {
        return $token;
    }

    $rawInput = file_get_contents('php://input');
    if (!$rawInput) {
        return '';
    }

    $json = json_decode($rawInput, true);
    if (is_array($json) && !empty($json['token'])) {
        return trim((string)$json['token']);
    }

    parse_str($rawInput, $formPayload);
    if (is_array($formPayload) && !empty($formPayload['token'])) {
        return trim((string)$formPayload['token']);
    }

    return '';
}

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
            verification_token_hash CHAR(64) NULL,
            verification_expires_at DATETIME NULL,
            email_verified_at DATETIME NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_account_signups_email (email),
            KEY idx_account_signups_status (status)
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
            KEY idx_tenant_companies_plan (plan_code),
            KEY idx_tenant_companies_status (status)
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

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS payment_transactions (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            signup_id BIGINT UNSIGNED NOT NULL,
            provider VARCHAR(30) NOT NULL,
            external_reference VARCHAR(80) NOT NULL,
            preference_id VARCHAR(120) NULL,
            provider_payment_id VARCHAR(120) NULL,
            status VARCHAR(40) NOT NULL,
            amount DECIMAL(10,2) NOT NULL DEFAULT 1.00,
            currency_id VARCHAR(10) NOT NULL DEFAULT "CLP",
            idempotency_key VARCHAR(80) NULL,
            raw_payload_json LONGTEXT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_payment_provider_payment (provider, provider_payment_id),
            KEY idx_payment_signup (signup_id),
            KEY idx_payment_reference (external_reference)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );

    ensure_column($pdo, 'account_signups', 'payment_status', 'VARCHAR(20) NOT NULL DEFAULT "unpaid"');
    ensure_column($pdo, 'account_signups', 'plan_code', 'VARCHAR(40) NOT NULL DEFAULT "basico"');
    ensure_column($pdo, 'account_signups', 'tenant_company_id', 'BIGINT UNSIGNED NULL');
    ensure_column($pdo, 'account_signups', 'activated_at', 'DATETIME NULL');
    ensure_column($pdo, 'account_signups', 'payment_access_token', 'CHAR(64) NULL');
    ensure_column($pdo, 'account_signups', 'payment_access_expires_at', 'DATETIME NULL');
    ensure_column($pdo, 'payment_method_settings', 'public_key_enc', 'TEXT NULL');
    ensure_column($pdo, 'payment_method_settings', 'access_token_enc', 'TEXT NULL');

    ensure_column($pdo, 'tenant_companies', 'signup_id', 'BIGINT UNSIGNED NULL');
    ensure_column($pdo, 'tenant_companies', 'owner_email', 'VARCHAR(190) NULL');
    ensure_column($pdo, 'tenant_companies', 'contact_name', 'VARCHAR(190) NULL');
    ensure_column($pdo, 'tenant_companies', 'plan_status', 'VARCHAR(40) NOT NULL DEFAULT "pending_payment"');
    ensure_column($pdo, 'tenant_companies', 'is_enabled', 'TINYINT(1) NOT NULL DEFAULT 0');

    if (column_exists($pdo, 'tenant_companies', 'business_email') && column_exists($pdo, 'tenant_companies', 'owner_email')) {
        $pdo->exec(
            'UPDATE tenant_companies
             SET owner_email = business_email
             WHERE (owner_email IS NULL OR owner_email = "")
               AND business_email IS NOT NULL
               AND business_email <> ""'
        );
    }

    $flowToken = flow_token_from_request();
    if ($flowToken === '') {
        respond_json(200, ['ok' => true, 'ignored' => true, 'reason' => 'missing_token']);
    }

    $stCfg = $pdo->prepare(
        'SELECT is_enabled, environment, public_key, access_token, public_key_enc, access_token_enc
         FROM payment_method_settings
         WHERE method_code = :method_code
         LIMIT 1'
    );
    $stCfg->execute(['method_code' => 'flow']);
    $cfgPay = $stCfg->fetch();

    if (!$cfgPay) {
        $cfgPay = [
            'is_enabled' => 0,
            'environment' => 'sandbox',
            'public_key' => '',
            'access_token' => '',
            'public_key_enc' => '',
            'access_token_enc' => '',
        ];
    }

    $cryptoKey = load_mp_db_crypto_key();
    if ($cryptoKey !== null) {
        if (!empty($cfgPay['public_key_enc'])) {
            $decrypted = mp_decrypt_value((string)$cfgPay['public_key_enc'], $cryptoKey);
            if (is_string($decrypted) && $decrypted !== '') {
                $cfgPay['public_key'] = $decrypted;
            }
        }
        if (!empty($cfgPay['access_token_enc'])) {
            $decrypted = mp_decrypt_value((string)$cfgPay['access_token_enc'], $cryptoKey);
            if (is_string($decrypted) && $decrypted !== '') {
                $cfgPay['access_token'] = $decrypted;
            }
        }
    }

    $securePayCfg = load_secure_flow_credentials();
    if (is_array($securePayCfg)) {
        if (array_key_exists('is_enabled', $securePayCfg) && (int)$cfgPay['is_enabled'] === 0) {
            $cfgPay['is_enabled'] = (int)$securePayCfg['is_enabled'];
        }
        if (trim((string)($cfgPay['public_key'] ?? '')) === '' && !empty($securePayCfg['api_key'])) {
            $cfgPay['public_key'] = (string)$securePayCfg['api_key'];
        }
        if (trim((string)($cfgPay['access_token'] ?? '')) === '' && !empty($securePayCfg['secret_key'])) {
            $cfgPay['access_token'] = (string)$securePayCfg['secret_key'];
        }
        if (!empty($securePayCfg['environment']) && in_array((string)$securePayCfg['environment'], ['sandbox', 'production'], true)) {
            $cfgPay['environment'] = (string)$securePayCfg['environment'];
        }
    }

    if ((int)$cfgPay['is_enabled'] !== 1 || trim((string)$cfgPay['public_key']) === '' || trim((string)$cfgPay['access_token']) === '') {
        respond_json(500, ['ok' => false, 'error' => 'pasarela_no_configurada']);
    }

    $flow = flow_request(
        'GET',
        '/payment/getStatus',
        (string)$cfgPay['public_key'],
        (string)$cfgPay['access_token'],
        ['token' => $flowToken],
        (string)$cfgPay['environment']
    );

    if (!$flow['ok'] || !is_array($flow['data'])) {
        respond_json(500, ['ok' => false, 'error' => 'flow_api_error']);
    }

    $payment = $flow['data'];
    $commerceOrder = (string)($payment['commerceOrder'] ?? '');
    if (!preg_match('/^signup:(\d+)/', $commerceOrder, $m)) {
        respond_json(200, ['ok' => true, 'ignored' => true, 'reason' => 'commerce_order_no_coincide']);
    }

    $signupId = (int)$m[1];
    $flowStatus = (int)($payment['status'] ?? 0);
    $flowOrder = (string)($payment['flowOrder'] ?? '');
    $amount = (float)($payment['amount'] ?? 0);
    $currencyId = 'CLP';

    $expectedAmount = null;
    $stExpected = $pdo->prepare(
        'SELECT amount
         FROM payment_transactions
         WHERE signup_id = :signup_id
           AND external_reference = :external_reference
         ORDER BY id DESC
         LIMIT 1'
    );
    $stExpected->execute([
        'signup_id' => $signupId,
        'external_reference' => 'signup:' . $signupId,
    ]);
    $rowExpected = $stExpected->fetch();
    if ($rowExpected && isset($rowExpected['amount'])) {
        $expectedAmount = (float)$rowExpected['amount'];
    }

    $stSignup = $pdo->prepare(
        'SELECT id, email, company_name, contact_name, phone, email_verified_at, payment_status, tenant_company_id
         FROM account_signups
         WHERE id = :id
         LIMIT 1'
    );
    $stSignup->execute(['id' => $signupId]);
    $signup = $stSignup->fetch();

    if (!$signup) {
        respond_json(200, ['ok' => true, 'ignored' => true, 'reason' => 'signup_no_existe']);
    }

    $statusMap = [
        1 => 'pending',
        2 => 'approved',
        3 => 'rejected',
        4 => 'canceled',
    ];
    $statusLabel = $statusMap[$flowStatus] ?? ('status_' . $flowStatus);

    $insTx = $pdo->prepare(
        'INSERT INTO payment_transactions (signup_id, provider, external_reference, preference_id, provider_payment_id, status, amount, currency_id, raw_payload_json)
         VALUES (:signup_id, :provider, :external_reference, :preference_id, :provider_payment_id, :status, :amount, :currency_id, :raw_payload_json)
         ON DUPLICATE KEY UPDATE
            status = VALUES(status),
            amount = VALUES(amount),
            currency_id = VALUES(currency_id),
            raw_payload_json = VALUES(raw_payload_json)'
    );
    $insTx->execute([
        'signup_id' => $signupId,
        'provider' => 'flow',
        'external_reference' => 'signup:' . $signupId,
        'preference_id' => $flowToken,
        'provider_payment_id' => ($flowOrder !== '' ? $flowOrder : $flowToken),
        'status' => $statusLabel,
        'amount' => $amount,
        'currency_id' => $currencyId,
        'raw_payload_json' => json_encode($payment, JSON_UNESCAPED_UNICODE),
    ]);

    $isApproved = $flowStatus === 2;
    $isExpectedAmount = ($expectedAmount !== null ? abs($amount - $expectedAmount) < 0.01 : $amount > 0);

    if (!$isApproved || !$isExpectedAmount) {
        respond_json(200, [
            'ok' => true,
            'processed' => true,
            'status' => $statusLabel,
            'amount' => $amount,
            'expected_amount' => $expectedAmount,
            'reason' => 'pago_no_aprobado_o_monto_distinto',
        ]);
    }

    $pdo->beginTransaction();

    $upSignup = $pdo->prepare(
        'UPDATE account_signups
         SET payment_status = :payment_status,
             status = :status,
             plan_code = :plan_code,
             payment_access_token = NULL,
             payment_access_expires_at = NULL,
             activated_at = NOW()
         WHERE id = :id'
    );
    $upSignup->execute([
        'payment_status' => 'paid',
        'status' => (!empty($signup['email_verified_at']) ? 'active' : 'payment_confirmed'),
        'plan_code' => 'basico',
        'id' => $signupId,
    ]);

    if (!empty($signup['email_verified_at'])) {
        $tenantId = (int)($signup['tenant_company_id'] ?? 0);
        if ($tenantId > 0) {
            $upTenant = $pdo->prepare(
                'UPDATE tenant_companies
                 SET company_name = :company_name,
                     owner_email = :owner_email,
                     contact_name = :contact_name,
                     phone = :phone,
                     plan_code = :plan_code,
                     plan_status = :plan_status,
                     is_enabled = :is_enabled,
                     status = :status
                 WHERE id = :id'
            );
            $upTenant->execute([
                'company_name' => (string)$signup['company_name'],
                'owner_email' => (string)$signup['email'],
                'contact_name' => (string)$signup['contact_name'],
                'phone' => ((string)$signup['phone'] !== '' ? (string)$signup['phone'] : null),
                'plan_code' => 'basico',
                'plan_status' => 'paid',
                'is_enabled' => 1,
                'status' => 'active',
                'id' => $tenantId,
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
                'signup_id' => $signupId,
                'company_name' => (string)$signup['company_name'],
                'company_slug' => $slug,
                'owner_email' => (string)$signup['email'],
                'contact_name' => (string)$signup['contact_name'],
                'phone' => ((string)$signup['phone'] !== '' ? (string)$signup['phone'] : null),
                'plan_code' => 'basico',
                'plan_status' => 'paid',
                'is_enabled' => 1,
                'status' => 'active',
                'created_by' => 'flow_webhook',
            ]);
            $newTenantId = (int)$pdo->lastInsertId();

            $upSignupTenant = $pdo->prepare(
                'UPDATE account_signups
                 SET tenant_company_id = :tenant_company_id
                 WHERE id = :id'
            );
            $upSignupTenant->execute([
                'tenant_company_id' => $newTenantId,
                'id' => $signupId,
            ]);
        }
    }

    $pdo->commit();

    respond_json(200, ['ok' => true, 'processed' => true, 'status' => 'approved']);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    respond_json(500, ['ok' => false, 'error' => 'internal_error']);
}
