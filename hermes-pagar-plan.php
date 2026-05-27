<?php
require_once __DIR__ . '/security-helpers.php';
security_apply_web_headers();

function h($value)
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
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

function table_exists(PDO $pdo, $tableName)
{
    $st = $pdo->prepare(
        'SELECT 1
         FROM information_schema.TABLES
         WHERE TABLE_SCHEMA = DATABASE()
           AND TABLE_NAME = :table_name
         LIMIT 1'
    );
    $st->execute([
        'table_name' => $tableName,
    ]);
    return (bool)$st->fetchColumn();
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

    $ch = null;
    if (strtoupper((string)$method) === 'POST') {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    } else {
        $queryUrl = $url . '?' . http_build_query($params);
        $ch = curl_init($queryUrl);
        curl_setopt($ch, CURLOPT_HTTPGET, true);
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);

    $raw = curl_exec($ch);
    $curlError = curl_error($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($raw === false) {
        return ['ok' => false, 'http_code' => $httpCode, 'error' => $curlError, 'data' => null];
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        $data = null;
    }

    return ['ok' => $httpCode >= 200 && $httpCode < 300, 'http_code' => $httpCode, 'error' => $curlError, 'data' => $data, 'raw' => $raw];
}

function plan_display_name($planCode)
{
    $code = strtolower(trim((string)$planCode));
    if ($code === 'pro') {
        return 'Heroe';
    }
    if ($code === 'enterprise') {
        return 'Semidios';
    }
    return 'Mortal';
}

function normalize_plan_code($planCode, $fallback = '')
{
    $code = strtolower(trim((string)$planCode));
    if (in_array($code, ['heroe', 'pro'], true)) {
        return 'pro';
    }
    if (in_array($code, ['semidios', 'semi_dios', 'enterprise'], true)) {
        return 'enterprise';
    }
    if (in_array($code, ['basico', 'basic', 'mortal'], true)) {
        return 'basico';
    }
    return (string)$fallback;
}

function default_plan_prices_clp()
{
    return [
        'basico' => ['monthly' => 350, 'annual' => 3500],
        'pro' => ['monthly' => 990, 'annual' => 9900],
        'enterprise' => ['monthly' => 1990, 'annual' => 19900],
    ];
}

$view = [
    'ok' => false,
    'error' => '',
    'already_paid_same_plan' => false,
    'already_paid_message' => '',
    'company_name' => '',
    'email' => '',
    'status' => '',
    'payment_status' => '',
    'signup_plan_code' => 'basico',
    'payer_email' => '',
    'plan_name' => 'Mortal',
    'plan_code' => 'basico',
    'billing_cycle' => 'monthly',
    'billing_cycle_name' => 'Mensual',
    'amount' => '350',
    'currency_id' => 'CLP',
];

$paymentToken = trim((string)($_GET['pt'] ?? ''));
$requestedTargetPlan = normalize_plan_code((string)($_GET['tp'] ?? ''), '');
if ($paymentToken === '' || strlen($paymentToken) < 40) {
    $view['error'] = 'El enlace de pago no es valido o expiro.';
}

if ($view['error'] === '') {
    try {
        $cfg = require __DIR__ . '/.db_credentials.php';
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $cfg['host'], (int)$cfg['port'], $cfg['dbname'], $cfg['charset']);
        $pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        security_ensure_tables($pdo);

        if (!table_exists($pdo, 'account_signups')) {
          $pdo->exec(
            'CREATE TABLE account_signups (
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
                }

                if (!table_exists($pdo, 'payment_method_settings')) {
                    $pdo->exec(
                        'CREATE TABLE payment_method_settings (
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
                }

                if (!table_exists($pdo, 'payment_transactions')) {
                    $pdo->exec(
                        'CREATE TABLE payment_transactions (
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
                }

                if (!table_exists($pdo, 'plan_pricing')) {
                    $pdo->exec(
                        'CREATE TABLE plan_pricing (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                plan_code VARCHAR(40) NOT NULL,
                amount_clp INT UNSIGNED NOT NULL DEFAULT 350,
                monthly_amount_clp INT UNSIGNED NOT NULL DEFAULT 350,
                annual_amount_clp INT UNSIGNED NOT NULL DEFAULT 3500,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_plan_pricing_code (plan_code)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
                    );
                }

        $seedPlanPrice = $pdo->prepare(
            'INSERT INTO plan_pricing (plan_code, amount_clp, monthly_amount_clp, annual_amount_clp)
             VALUES (:plan_code, :amount_clp, :monthly_amount_clp, :annual_amount_clp)
             ON DUPLICATE KEY UPDATE plan_code = plan_code'
        );
        foreach (default_plan_prices_clp() as $seedPlanCode => $seedCfg) {
            $seedPlanPrice->execute([
                'plan_code' => $seedPlanCode,
                'amount_clp' => (int)($seedCfg['monthly'] ?? 350),
                'monthly_amount_clp' => (int)($seedCfg['monthly'] ?? 350),
                'annual_amount_clp' => (int)($seedCfg['annual'] ?? 3500),
            ]);
        }

        ensure_column($pdo, 'account_signups', 'payment_status', 'VARCHAR(20) NOT NULL DEFAULT "unpaid"');
        ensure_column($pdo, 'account_signups', 'plan_code', 'VARCHAR(40) NOT NULL DEFAULT "basico"');
        ensure_column($pdo, 'account_signups', 'billing_cycle', 'VARCHAR(20) NOT NULL DEFAULT "monthly"');
        ensure_column($pdo, 'account_signups', 'payment_access_token', 'CHAR(64) NULL');
        ensure_column($pdo, 'account_signups', 'payment_access_expires_at', 'DATETIME NULL');
        ensure_column($pdo, 'account_signups', 'tenant_company_id', 'BIGINT UNSIGNED NULL');
        ensure_column($pdo, 'account_signups', 'activated_at', 'DATETIME NULL');
        ensure_column($pdo, 'plan_pricing', 'monthly_amount_clp', 'INT UNSIGNED NOT NULL DEFAULT 350');
        ensure_column($pdo, 'plan_pricing', 'annual_amount_clp', 'INT UNSIGNED NOT NULL DEFAULT 3500');
        ensure_column($pdo, 'payment_method_settings', 'public_key_enc', 'TEXT NULL');
        ensure_column($pdo, 'payment_method_settings', 'access_token_enc', 'TEXT NULL');

        $stSignup = $pdo->prepare(
            'SELECT id, email, company_name, status, payment_status, plan_code, billing_cycle, tenant_company_id, email_verified_at, payment_access_expires_at
             FROM account_signups
             WHERE payment_access_token = :payment_access_token
             LIMIT 1'
        );
        $stSignup->execute(['payment_access_token' => $paymentToken]);
        $signup = $stSignup->fetch();

        if (!$signup) {
            $view['error'] = 'No encontramos una cuenta pendiente asociada a este enlace de pago.';
        } else {
            $expiresAt = strtotime((string)($signup['payment_access_expires_at'] ?? ''));
            if ($expiresAt === false || $expiresAt < time()) {
                $view['error'] = 'El enlace de pago expiro. Solicita un nuevo enlace desde soporte.';
            } elseif (empty($signup['email_verified_at'])) {
                $view['error'] = 'Tu correo aun no esta verificado. Verifica el correo antes de pagar.';
            } else {
                $signupPlanCode = normalize_plan_code((string)$signup['plan_code'], 'basico');
                $effectivePaymentStatus = strtolower(trim((string)($signup['payment_status'] ?? 'unpaid')));
                $planCode = $requestedTargetPlan;
                $billingCycle = strtolower(trim((string)($signup['billing_cycle'] ?? 'monthly')));
                if (!in_array($billingCycle, ['monthly', 'annual'], true)) {
                    $billingCycle = 'monthly';
                }

                // Si el plan fue ajustado desde admin master, tenant_companies es la fuente efectiva.
                if (table_exists($pdo, 'tenant_companies')) {
                    $stTenantPlan = $pdo->prepare(
                        'SELECT plan_code, billing_cycle, plan_status
                         FROM tenant_companies
                         WHERE signup_id = :signup_id
                         LIMIT 1'
                    );
                    $stTenantPlan->execute(['signup_id' => (int)$signup['id']]);
                    $tenantPlanRow = $stTenantPlan->fetch();

                    if (!$tenantPlanRow) {
                        $stTenantByEmail = $pdo->prepare(
                            'SELECT plan_code, billing_cycle, plan_status
                             FROM tenant_companies
                             WHERE LOWER(owner_email) = LOWER(:owner_email)
                             LIMIT 1'
                        );
                        $stTenantByEmail->execute(['owner_email' => (string)$signup['email']]);
                        $tenantPlanRow = $stTenantByEmail->fetch();
                    }

                    if ($tenantPlanRow) {
                        $tenantPlanCode = normalize_plan_code((string)($tenantPlanRow['plan_code'] ?? ''), '');
                        if (in_array($tenantPlanCode, ['basico', 'pro', 'enterprise'], true)) {
                            $signupPlanCode = $tenantPlanCode;
                        }

                        $tenantBillingCycle = strtolower(trim((string)($tenantPlanRow['billing_cycle'] ?? '')));
                        if (in_array($tenantBillingCycle, ['monthly', 'annual'], true)) {
                            $billingCycle = $tenantBillingCycle;
                        }

                        $tenantPlanStatus = strtolower(trim((string)($tenantPlanRow['plan_status'] ?? '')));
                        if ($tenantPlanStatus === 'paid') {
                            $effectivePaymentStatus = 'paid';
                        }

                        if (
                            $signupPlanCode !== normalize_plan_code((string)$signup['plan_code'], 'basico')
                            || $billingCycle !== strtolower(trim((string)($signup['billing_cycle'] ?? 'monthly')))
                            || ($effectivePaymentStatus === 'paid' && strtolower(trim((string)($signup['payment_status'] ?? 'unpaid'))) !== 'paid')
                        ) {
                            $upSignupPlan = $pdo->prepare(
                                'UPDATE account_signups
                                 SET plan_code = :plan_code,
                                     billing_cycle = :billing_cycle,
                                     payment_status = :payment_status
                                 WHERE id = :id
                                 LIMIT 1'
                            );
                            $upSignupPlan->execute([
                                'plan_code' => $signupPlanCode,
                                'billing_cycle' => $billingCycle,
                                'payment_status' => $effectivePaymentStatus,
                                'id' => (int)$signup['id'],
                            ]);
                        }
                    }
                }

                if (!in_array($planCode, ['basico', 'pro', 'enterprise'], true)) {
                    $planCode = $signupPlanCode;
                }

                $stPlanPrice = $pdo->prepare('SELECT amount_clp, monthly_amount_clp, annual_amount_clp FROM plan_pricing WHERE plan_code = :plan_code LIMIT 1');
                $stPlanPrice->execute(['plan_code' => $planCode]);
                $priceRow = $stPlanPrice->fetch();
                $amountByPlan = 0;
                if ($priceRow) {
                    if ($billingCycle === 'annual') {
                        $amountByPlan = (int)($priceRow['annual_amount_clp'] ?? 0);
                    } else {
                        $amountByPlan = (int)($priceRow['monthly_amount_clp'] ?? 0);
                    }
                    if ($amountByPlan < 350) {
                        $amountByPlan = (int)($priceRow['amount_clp'] ?? 0);
                    }
                }
                if ($amountByPlan < 350) {
                    $defaults = default_plan_prices_clp();
                    $amountByPlan = (int)(($defaults[$planCode][$billingCycle] ?? 350));
                }

                $view['ok'] = true;
                $view['company_name'] = (string)$signup['company_name'];
                $view['email'] = (string)$signup['email'];
                $view['payer_email'] = (string)$signup['email'];
                $view['status'] = (string)$signup['status'];
                $view['payment_status'] = $effectivePaymentStatus;
                $view['signup_plan_code'] = $signupPlanCode;
                $view['plan_code'] = $planCode;
                $view['plan_name'] = plan_display_name($planCode);
                $view['billing_cycle'] = $billingCycle;
                $view['billing_cycle_name'] = ($billingCycle === 'annual') ? 'Anual' : 'Mensual';
                $view['amount'] = (string)$amountByPlan;

                $isSamePaidPlanNow = (strtolower(trim((string)$view['payment_status'])) === 'paid') && ($planCode === $signupPlanCode);
                if ($isSamePaidPlanNow) {
                    $view['already_paid_same_plan'] = true;
                    $view['already_paid_message'] = 'Tu plan ' . $view['plan_name'] . ' ya se encuentra al dia. No necesitas realizar un pago adicional.';
                }

                if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                    $postedTargetPlan = normalize_plan_code((string)($_POST['target_plan'] ?? ''), '');
                    if (in_array($postedTargetPlan, ['basico', 'pro', 'enterprise'], true)) {
                        $view['plan_code'] = $postedTargetPlan;
                        $view['plan_name'] = plan_display_name($postedTargetPlan);
                    }
                }
            }
        }

        if ($view['ok'] && $_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'create_checkout') {
            $clientIp = security_client_ip();
            $ipRate = security_rate_limit_check($pdo, 'public-checkout:ip:' . $clientIp, 10, 60);
            $tokenRate = security_rate_limit_check($pdo, 'public-checkout:token:' . substr(hash('sha256', $paymentToken), 0, 24), 4, 60);
            if (!$ipRate['allowed'] || !$tokenRate['allowed']) {
                try {
                    security_audit_log($pdo, [
                        'tenant_company_id' => isset($signup['tenant_company_id']) ? (int)$signup['tenant_company_id'] : null,
                        'actor_email' => (string)($view['email'] ?? ''),
                        'action_name' => 'public_checkout_rate_limited',
                        'entity_name' => 'public_checkout',
                        'entity_id' => substr(hash('sha256', $paymentToken), 0, 12),
                        'result_status' => 'blocked',
                        'ip_address' => $clientIp,
                        'detail' => [
                            'retry_after' => max((int)$ipRate['retry_after'], (int)$tokenRate['retry_after']),
                            'plan_code' => (string)($view['plan_code'] ?? ''),
                        ],
                    ]);
                } catch (Throwable $auditError) {
                }
                $view['error'] = 'Detectamos demasiados intentos seguidos. Espera 1 minuto para volver a intentar.';
                $view['ok'] = false;
            }

            if (!$view['ok']) {
                throw new RuntimeException('checkout_rate_limited');
            }

            $checkoutPlanCode = normalize_plan_code((string)($_POST['target_plan'] ?? $view['plan_code']), 'basico');
            $view['plan_code'] = $checkoutPlanCode;
            $view['plan_name'] = plan_display_name($checkoutPlanCode);

            $stCheckoutPrice = $pdo->prepare('SELECT amount_clp, monthly_amount_clp, annual_amount_clp FROM plan_pricing WHERE plan_code = :plan_code LIMIT 1');
            $stCheckoutPrice->execute(['plan_code' => $checkoutPlanCode]);
            $checkoutPrice = $stCheckoutPrice->fetch();
            $checkoutAmount = 0;
            if ($checkoutPrice) {
                if ($view['billing_cycle'] === 'annual') {
                    $checkoutAmount = (int)($checkoutPrice['annual_amount_clp'] ?? 0);
                } else {
                    $checkoutAmount = (int)($checkoutPrice['monthly_amount_clp'] ?? 0);
                }
                if ($checkoutAmount < 350) {
                    $checkoutAmount = (int)($checkoutPrice['amount_clp'] ?? 0);
                }
            }
            if ($checkoutAmount < 350) {
                $defaults = default_plan_prices_clp();
                $checkoutAmount = (int)(($defaults[$checkoutPlanCode][$view['billing_cycle']] ?? 350));
            }
            $view['amount'] = (string)$checkoutAmount;

            $isSamePaidPlan = ((string)$view['payment_status'] === 'paid') && ($checkoutPlanCode === (string)$view['signup_plan_code']);
            if ($isSamePaidPlan) {
                $view['already_paid_same_plan'] = true;
                $view['already_paid_message'] = 'Tu plan ' . $view['plan_name'] . ' ya se encuentra al dia. No necesitas realizar un pago adicional.';
            }

            // Revalida contra DB para bloquear doble pago si la cuenta ya se marco como pagada entre solicitudes.
            $stFreshSignup = $pdo->prepare('SELECT payment_status FROM account_signups WHERE id = :id LIMIT 1');
            $stFreshSignup->execute(['id' => (int)$signup['id']]);
            $freshPaymentStatus = strtolower(trim((string)$stFreshSignup->fetchColumn()));
            if ($freshPaymentStatus === 'paid' && $checkoutPlanCode === (string)$view['signup_plan_code']) {
                $view['already_paid_same_plan'] = true;
                $view['already_paid_message'] = 'Tu plan ' . $view['plan_name'] . ' ya se encuentra al dia. No necesitas realizar un pago adicional.';
            }

            if (!$view['already_paid_same_plan']) {
                $upRequestedPlan = $pdo->prepare('UPDATE account_signups SET plan_code = :plan_code WHERE id = :id LIMIT 1');
                $upRequestedPlan->execute([
                    'plan_code' => $checkoutPlanCode,
                    'id' => (int)$signup['id'],
                ]);

            $stPay = $pdo->prepare(
                'SELECT is_enabled, environment, public_key, access_token, public_key_enc, access_token_enc, webhook_url
                 FROM payment_method_settings
                 WHERE method_code = :method_code
                 LIMIT 1'
            );
            $stPay->execute(['method_code' => 'flow']);
            $payCfg = $stPay->fetch();

            if (!$payCfg) {
                $payCfg = [
                    'is_enabled' => 0,
                    'environment' => 'sandbox',
                    'public_key' => '',
                    'access_token' => '',
                    'public_key_enc' => '',
                    'access_token_enc' => '',
                    'webhook_url' => '',
                ];
            }

            $cryptoKey = load_mp_db_crypto_key();
            if ($cryptoKey !== null) {
                if (!empty($payCfg['public_key_enc'])) {
                    $decrypted = mp_decrypt_value((string)$payCfg['public_key_enc'], $cryptoKey);
                    if (is_string($decrypted) && $decrypted !== '') {
                        $payCfg['public_key'] = $decrypted;
                    }
                }
                if (!empty($payCfg['access_token_enc'])) {
                    $decrypted = mp_decrypt_value((string)$payCfg['access_token_enc'], $cryptoKey);
                    if (is_string($decrypted) && $decrypted !== '') {
                        $payCfg['access_token'] = $decrypted;
                    }
                }
            }

            $securePayCfg = load_secure_mp_credentials();
            if (is_array($securePayCfg)) {
                // Archivo seguro solo como fallback cuando no hay dato en DB.
                if (array_key_exists('is_enabled', $securePayCfg) && (int)$payCfg['is_enabled'] === 0) {
                    $payCfg['is_enabled'] = (int)$securePayCfg['is_enabled'];
                }
                if (
                    (!isset($payCfg['environment']) || trim((string)$payCfg['environment']) === '')
                    && !empty($securePayCfg['environment'])
                    && in_array((string)$securePayCfg['environment'], ['sandbox', 'production'], true)
                ) {
                    $payCfg['environment'] = (string)$securePayCfg['environment'];
                }
                if (trim((string)($payCfg['public_key'] ?? '')) === '' && !empty($securePayCfg['api_key'])) {
                    $payCfg['public_key'] = (string)$securePayCfg['api_key'];
                }
                if (trim((string)($payCfg['access_token'] ?? '')) === '' && !empty($securePayCfg['secret_key'])) {
                    $payCfg['access_token'] = (string)$securePayCfg['secret_key'];
                }
                if (trim((string)($payCfg['webhook_url'] ?? '')) === '' && !empty($securePayCfg['webhook_url'])) {
                    $payCfg['webhook_url'] = (string)$securePayCfg['webhook_url'];
                }
            }

                if (!$payCfg || (int)$payCfg['is_enabled'] !== 1) {
                    $view['error'] = 'La pasarela de pago aun no esta habilitada. Intenta en unos minutos.';
                } elseif (trim((string)($payCfg['public_key'] ?? '')) === '' || trim((string)($payCfg['access_token'] ?? '')) === '') {
                    $view['error'] = 'La pasarela no tiene credenciales completas para procesar pagos.';
                } else {
                    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                    $host = $_SERVER['HTTP_HOST'] ?? 'gesmanolympus.com';
                    $externalReference = 'signup:' . (int)$signup['id'];
                    $commerceOrder = $externalReference . ':' . time();
                    $notificationUrl = trim((string)($payCfg['webhook_url'] ?? ''));
                    if ($notificationUrl === '') {
                        $notificationUrl = $scheme . '://' . $host . '/webhook/flow/';
                    }
                    $returnUrl = $scheme . '://' . $host . '/pago-resultado/?s=pending';

                    $payerEmail = trim((string)($_POST['payer_email'] ?? $view['payer_email'] ?? $view['email'] ?? ''));
                    if (!filter_var($payerEmail, FILTER_VALIDATE_EMAIL)) {
                        $view['error'] = 'Debes ingresar un email valido para continuar con Flow.';
                    }

                    if ($view['error'] !== '') {
                        // Evita invocar Flow cuando faltan datos base del pagador.
                    } else {
                        $view['payer_email'] = $payerEmail;

                        $payload = [
                            'commerceOrder' => $commerceOrder,
                            'subject' => 'Plan ' . $view['plan_name'] . ' ' . $view['billing_cycle_name'] . ' GesMan HERMES',
                            'currency' => 'CLP',
                            'amount' => (int)round((float)$view['amount']),
                            'email' => $payerEmail,
                            'urlConfirmation' => $notificationUrl,
                            'urlReturn' => $returnUrl,
                        ];

                        $flow = flow_request('POST', '/payment/create', (string)$payCfg['public_key'], (string)$payCfg['access_token'], $payload, (string)$payCfg['environment']);
                        if (!$flow['ok'] || !is_array($flow['data'])) {
                            $flowCode = is_array($flow['data']) ? (int)($flow['data']['code'] ?? 0) : 0;
                            error_log(
                                'HERMES_FLOW_CREATE_ERROR: http=' . (int)$flow['http_code']
                                . ' curl=' . (string)($flow['error'] ?? '')
                                . ' payload=' . json_encode($payload, JSON_UNESCAPED_UNICODE)
                                . ' response=' . (string)($flow['raw'] ?? '')
                            );
                            if ($flowCode === 1901) {
                                $view['error'] = 'Flow exige un monto minimo de $350 CLP para iniciar el checkout.';
                            } elseif ($flowCode === 1620) {
                                $view['error'] = 'Flow rechazo el email del pagador. Prueba con otro correo real y vuelve a intentar.';
                            } else {
                                $view['error'] = 'No se pudo iniciar el checkout con Flow. Intenta nuevamente.';
                            }
                        } else {
                            $flowUrl = (string)($flow['data']['url'] ?? '');
                            $flowToken = (string)($flow['data']['token'] ?? '');
                            $redirectUrl = ($flowUrl !== '' && $flowToken !== '') ? ($flowUrl . '?token=' . rawurlencode($flowToken)) : '';

                            if ($redirectUrl === '') {
                                $view['error'] = 'Flow no devolvio una URL valida de pago.';
                            } else {
                                $insTx = $pdo->prepare(
                                    'INSERT INTO payment_transactions (signup_id, provider, external_reference, preference_id, status, amount, currency_id, idempotency_key, raw_payload_json)
                                     VALUES (:signup_id, :provider, :external_reference, :preference_id, :status, :amount, :currency_id, :idempotency_key, :raw_payload_json)'
                                );
                                $insTx->execute([
                                    'signup_id' => (int)$signup['id'],
                                    'provider' => 'flow',
                                    'external_reference' => $externalReference,
                                    'preference_id' => $flowToken,
                                    'status' => 'payment_created',
                                    'amount' => (float)$view['amount'],
                                    'currency_id' => $view['currency_id'],
                                    'idempotency_key' => bin2hex(random_bytes(12)),
                                    'raw_payload_json' => json_encode($flow['data'], JSON_UNESCAPED_UNICODE),
                                ]);

                                header('Location: ' . $redirectUrl);
                                exit;
                            }
                        }
                    }
                }
            }
        }
    } catch (Throwable $e) {
        error_log('HERMES_FLOW_CHECKOUT_INIT_ERROR: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
        if ((string)$e->getMessage() !== 'checkout_rate_limited') {
            $view['error'] = 'No fue posible inicializar el pago en este momento.';
        }
    }
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Pagar plan | GesMan HERMES</title>
    <meta name="description" content="Checkout de validacion del plan empresarial de GesMan HERMES.">
  <link rel="icon" type="image/svg+xml" href="/assets/img/favicon-hermes.svg">
  <style>
    :root {
      --bg-1: #0b132b;
      --bg-2: #121c3f;
      --line: #3a2d0d;
      --gold: #f4b400;
      --gold-2: #ffd84d;
      --txt: #f8fafc;
      --muted: #cbd5e1;
      --ok: #86efac;
      --danger: #fda4af;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: 'Segoe UI', Arial, sans-serif;
      color: var(--txt);
      background:
        radial-gradient(circle at 10% 0%, rgba(255,216,77,.22), transparent 40%),
        radial-gradient(circle at 90% 0%, rgba(244,180,0,.14), transparent 44%),
        linear-gradient(180deg, var(--bg-1), var(--bg-2));
      display: grid;
      place-items: center;
      padding: 1.2rem;
    }
    .card {
      width: min(760px, 100%);
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(17,24,39,.92);
      box-shadow: 0 28px 48px rgba(0,0,0,.35);
      padding: 1.4rem;
    }
    h1 {
      margin: .2rem 0 .45rem;
      color: #fff4b8;
      font-size: 1.45rem;
    }
    p { color: var(--muted); margin: 0 0 .8rem; }
    .msg {
      border: 1px solid;
      border-radius: 10px;
      padding: .65rem .72rem;
      margin-bottom: .8rem;
      font-size: .9rem;
    }
    .msg.err { color: var(--danger); border-color: #7f1d1d; background: rgba(127,29,29,.2); }
    .msg.ok { color: var(--ok); border-color: #14532d; background: rgba(20,83,45,.2); }
    .summary {
      border: 1px solid rgba(244,180,0,.28);
      border-radius: 12px;
      background: rgba(15,23,42,.72);
      padding: .8rem;
      margin-bottom: .9rem;
    }
    .summary strong { color: var(--gold-2); }
    .list { margin: .65rem 0 0; padding-left: 1rem; }
    .list li { margin-bottom: .35rem; color: var(--muted); }
    .actions { display: flex; gap: .6rem; flex-wrap: wrap; }
        .payer-row {
            display: grid;
            gap: .35rem;
            margin: .75rem 0 .9rem;
        }
        .payer-row label { color: #cbd5e1; font-size: .86rem; }
        .payer-row input {
            border: 1px solid #475569;
            border-radius: 10px;
            background: #0f172a;
            color: #f8fafc;
            padding: .62rem .72rem;
            font-size: .9rem;
            width: min(420px, 100%);
        }
    .btn {
      border: 1px solid #8b6500;
      border-radius: 10px;
      background: linear-gradient(180deg, #ffe38b, #f4b400);
      color: #1f2937;
      text-decoration: none;
      font-weight: 700;
      font-size: .92rem;
      letter-spacing: .03em;
      padding: .72rem .9rem;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
    }
    .btn.ghost {
      border-color: #475569;
      background: #0f172a;
      color: #cbd5e1;
    }
        .btn.app {
            border-color: #14532d;
            background: linear-gradient(180deg, #86efac, #22c55e);
            color: #052e16;
        }
  </style>
</head>
<body>
  <main class="card">
                <h1><?= $view['already_paid_same_plan'] ? 'Plan al dia' : ('Pagar plan ' . h($view['plan_name'])) ?></h1>
                <p>
                    <?php if ($view['already_paid_same_plan']): ?>
                        Tu cuenta ya se encuentra al dia para el plan seleccionado.
                    <?php else: ?>
                        Este pago permite validar el flujo real de onboarding y activacion con resguardos de seguridad.
                    <?php endif; ?>
                </p>

    <?php if ($view['error'] !== ''): ?>
      <div class="msg err"><?= h($view['error']) ?></div>
    <?php endif; ?>

    <?php if ($view['ok']): ?>
            <?php if ($view['already_paid_same_plan']): ?>
            <div class="msg ok" style="margin-bottom:.9rem;"><?= h($view['already_paid_message']) ?></div>
            <?php endif; ?>
      <div class="summary">
        <p><strong>Empresa:</strong> <?= h($view['company_name']) ?></p>
        <p><strong>Correo:</strong> <?= h($view['email']) ?></p>
        <p><strong>Plan:</strong> <?= h($view['plan_name']) ?></p>
        <p><strong>Modalidad:</strong> <?= h($view['billing_cycle_name']) ?></p>
                <p><strong>Monto:</strong> <?= h($view['amount']) ?> <?= h($view['currency_id']) ?></p>
        <ul class="list">
                    <li>Acceso habilitado solo al confirmar pago aprobado.</li>
                    <li>Validacion de transaccion contra API oficial de Flow.</li>
          <li>Registro transaccional e idempotencia para evitar doble activacion.</li>
        </ul>
      </div>

      <div class="actions">
                <?php if (!$view['already_paid_same_plan']): ?>
        <form method="post" style="margin:0;">
          <input type="hidden" name="action" value="create_checkout">
                    <input type="hidden" name="target_plan" value="<?= h($view['plan_code']) ?>">
                    <div class="payer-row">
                        <label for="payer_email">Email del pagador (Flow)</label>
                        <input id="payer_email" name="payer_email" type="email" value="<?= h($view['payer_email'] !== '' ? $view['payer_email'] : $view['email']) ?>" required>
                    </div>
                    <button class="btn" type="submit">Pagar ahora con Flow</button>
        </form>
                <?php endif; ?>
                <a class="btn app" href="/empresa/dashboard/?module=plan">Volver a la app</a>
        <a class="btn ghost" href="/">Volver al sitio</a>
      </div>
    <?php endif; ?>
  </main>
</body>
</html>
