<?php
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
    $pairs = [];
    foreach ($params as $k => $v) {
        $pairs[] = (string)$k . '=' . rawurlencode((string)$v);
    }
    $toSign = implode('&', $pairs);
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

$view = [
    'ok' => false,
    'error' => '',
    'company_name' => '',
    'email' => '',
    'status' => '',
    'payment_status' => '',
    'plan_code' => 'basico',
    'amount' => '100',
    'currency_id' => 'CLP',
];

$paymentToken = trim((string)($_GET['pt'] ?? ''));
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
        ensure_column($pdo, 'account_signups', 'payment_access_token', 'CHAR(64) NULL');
        ensure_column($pdo, 'account_signups', 'payment_access_expires_at', 'DATETIME NULL');
        ensure_column($pdo, 'account_signups', 'tenant_company_id', 'BIGINT UNSIGNED NULL');
        ensure_column($pdo, 'account_signups', 'activated_at', 'DATETIME NULL');
        ensure_column($pdo, 'payment_method_settings', 'public_key_enc', 'TEXT NULL');
        ensure_column($pdo, 'payment_method_settings', 'access_token_enc', 'TEXT NULL');

        $stSignup = $pdo->prepare(
            'SELECT id, email, company_name, status, payment_status, plan_code, email_verified_at, payment_access_expires_at
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
                $view['ok'] = true;
                $view['company_name'] = (string)$signup['company_name'];
                $view['email'] = (string)$signup['email'];
                $view['status'] = (string)$signup['status'];
                $view['payment_status'] = (string)$signup['payment_status'];
                $view['plan_code'] = (string)$signup['plan_code'];
            }
        }

        if ($view['ok'] && $_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'create_checkout') {
            if ((string)$view['payment_status'] === 'paid') {
                header('Location: /pago-resultado/?s=ok');
                exit;
            }

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

                $payerEmail = '';
                if (isset($view['email']) && filter_var((string)$view['email'], FILTER_VALIDATE_EMAIL)) {
                    $payerEmail = (string)$view['email'];
                }

                $payload = [
                    'commerceOrder' => $commerceOrder,
                    'subject' => 'Plan Basico GesMan HERMES',
                    'currency' => 'CLP',
                    'amount' => (int)round((float)$view['amount']),
                    'email' => $payerEmail,
                    'urlConfirmation' => $notificationUrl,
                    'urlReturn' => $returnUrl,
                ];

                $flow = flow_request('POST', '/payment/create', (string)$payCfg['public_key'], (string)$payCfg['access_token'], $payload, (string)$payCfg['environment']);
                if (!$flow['ok'] || !is_array($flow['data'])) {
                    error_log(
                        'HERMES_FLOW_CREATE_ERROR: http=' . (int)$flow['http_code']
                        . ' curl=' . (string)($flow['error'] ?? '')
                        . ' payload=' . json_encode($payload, JSON_UNESCAPED_UNICODE)
                        . ' response=' . (string)($flow['raw'] ?? '')
                    );
                    $view['error'] = 'No se pudo iniciar el checkout con Flow. Intenta nuevamente.';
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
    } catch (Throwable $e) {
        error_log('HERMES_FLOW_CHECKOUT_INIT_ERROR: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
        $view['error'] = 'No fue posible inicializar el pago en este momento.';
    }
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Pagar plan basico | GesMan HERMES</title>
  <meta name="description" content="Checkout de validacion para plan basico de GesMan HERMES.">
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
  </style>
</head>
<body>
  <main class="card">
    <h1>Pagar plan basico de validacion</h1>
    <p>Este pago de $100 CLP permite validar el flujo real de onboarding y activacion con resguardos de seguridad.</p>

    <?php if ($view['error'] !== ''): ?>
      <div class="msg err"><?= h($view['error']) ?></div>
    <?php endif; ?>

    <?php if ($view['ok']): ?>
      <div class="summary">
        <p><strong>Empresa:</strong> <?= h($view['company_name']) ?></p>
        <p><strong>Correo:</strong> <?= h($view['email']) ?></p>
        <p><strong>Plan:</strong> Basico</p>
        <p><strong>Monto:</strong> <?= h($view['amount']) ?> <?= h($view['currency_id']) ?></p>
        <ul class="list">
          <li>Acceso habilitado solo al confirmar pago aprobado.</li>
                    <li>Validacion de transaccion contra API oficial de Flow.</li>
          <li>Registro transaccional e idempotencia para evitar doble activacion.</li>
        </ul>
      </div>

      <div class="actions">
        <form method="post" style="margin:0;">
          <input type="hidden" name="action" value="create_checkout">
                    <button class="btn" type="submit">Pagar ahora con Flow</button>
        </form>
        <a class="btn ghost" href="/">Volver al sitio</a>
      </div>
    <?php endif; ?>
  </main>
</body>
</html>
