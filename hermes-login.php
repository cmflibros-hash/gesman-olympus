<?php
session_start();

function resolve_dashboard_by_role($role)
{
  $normalizedRole = strtolower(trim((string)$role));
  if (in_array($normalizedRole, ['adm_master', 'master_admin'], true)) {
    return '/admin/';
  }
  if (in_array($normalizedRole, ['company_owner', 'company_admin', 'company_user'], true)) {
    return '/empresa/dashboard/';
  }
  return '/';
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

function is_payment_gateway_enabled(PDO $pdo)
{
  try {
    $st = $pdo->prepare(
      'SELECT is_enabled
       FROM payment_method_settings
       WHERE method_code = :method_code
       LIMIT 1'
    );
    $st->execute(['method_code' => 'flow']);
    $row = $st->fetch();
    if ($row) {
      return (int)($row['is_enabled'] ?? 0) === 1;
    }
  } catch (Throwable $e) {
    // Fallback a archivo seguro si hay problemas con DB.
  }

  $secureCfg = load_secure_mp_credentials();
  if (is_array($secureCfg) && array_key_exists('is_enabled', $secureCfg)) {
    return (int)$secureCfg['is_enabled'] === 1;
  }

  return false;
}

function issue_company_payment_token(PDO $pdo, $signupId)
{
  $token = bin2hex(random_bytes(32));
  $up = $pdo->prepare(
    'UPDATE account_signups
     SET payment_access_token = :payment_access_token,
       payment_access_expires_at = DATE_ADD(NOW(), INTERVAL 72 HOUR)
     WHERE id = :id'
  );
  $up->execute([
    'payment_access_token' => $token,
    'id' => (int)$signupId,
  ]);
  return $token;
}

function is_company_account_enabled($status, $emailVerifiedAt)
{
    $normalizedStatus = strtolower(trim((string)$status));
    if ((string)$emailVerifiedAt !== '') {
        return true;
    }
    return in_array($normalizedStatus, ['email_verified', 'pending_payment', 'payment_confirmed', 'active'], true);
}

$auth = [
    'ok' => false,
    'message' => '',
  'message_html' => '',
    'role' => null,
    'username' => null,
];

if (!empty($_SESSION['hermes_auth']) && !empty($_SESSION['hermes_user'])) {
    $auth['ok'] = true;
    $auth['username'] = (string)$_SESSION['hermes_user'];
    $auth['role'] = (string)($_SESSION['hermes_role'] ?? '');
}

if ($auth['ok'] && !($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout']))) {
  header('Location: ' . resolve_dashboard_by_role($auth['role']));
  exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    header('Location: /');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'], $_POST['password']) && !$auth['ok']) {
  $identifier = trim((string)$_POST['username']);
    $password = (string)$_POST['password'];

    try {
        $cfg = require __DIR__ . '/.db_credentials.php';
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $cfg['host'], (int)$cfg['port'], $cfg['dbname'], $cfg['charset']);
        $pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        ensure_column($pdo, 'account_signups', 'payment_status', 'VARCHAR(20) NOT NULL DEFAULT "unpaid"');
        ensure_column($pdo, 'account_signups', 'payment_access_token', 'CHAR(64) NULL');
        ensure_column($pdo, 'account_signups', 'payment_access_expires_at', 'DATETIME NULL');

        $st = $pdo->prepare('SELECT username, password_hash, role, is_active FROM users WHERE username = :username LIMIT 1');
        $st->execute(['username' => $identifier]);
        $user = $st->fetch();

        if ($user && (int)$user['is_active'] === 1 && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['hermes_auth'] = 1;
            $_SESSION['hermes_user'] = $user['username'];
            $_SESSION['hermes_role'] = $user['role'];
            header('Location: ' . resolve_dashboard_by_role($user['role']));
            exit;
        }

          $stCompany = $pdo->prepare(
            'SELECT id, email, company_name, password_hash, status, email_verified_at, payment_status, payment_access_token, payment_access_expires_at
             FROM account_signups
             WHERE LOWER(email) = LOWER(:email)
             LIMIT 1'
          );
          $stCompany->execute([
            'email' => $identifier,
          ]);
          $company = $stCompany->fetch();

          if (
            $company
            && password_verify($password, (string)$company['password_hash'])
            && is_company_account_enabled((string)$company['status'], (string)($company['email_verified_at'] ?? ''))
          ) {
            $paymentRequired = is_payment_gateway_enabled($pdo);
            $paymentStatus = strtolower(trim((string)($company['payment_status'] ?? 'unpaid')));

            if ($paymentRequired && $paymentStatus !== 'paid') {
                $paymentToken = (string)($company['payment_access_token'] ?? '');
                $paymentExpiresAt = strtotime((string)($company['payment_access_expires_at'] ?? ''));
                $tokenExpired = ($paymentToken === '' || $paymentExpiresAt === false || $paymentExpiresAt < time());
                if ($tokenExpired) {
                    $paymentToken = issue_company_payment_token($pdo, (int)$company['id']);
                }

                $auth['message'] = 'Tu cuenta esta verificada, pero aun no registra pago del plan.';
                $auth['message_html'] = 'Tu cuenta esta verificada, pero aun no registra pago del plan. <a href="/pagar-plan/?pt=' . rawurlencode($paymentToken) . '">Pagar ahora</a>';
            } else {
              session_regenerate_id(true);
              $_SESSION['hermes_auth'] = 1;
              $_SESSION['hermes_user'] = (string)$company['email'];
              $_SESSION['hermes_role'] = 'company_owner';
              $_SESSION['hermes_company_id'] = (int)$company['id'];
              $_SESSION['hermes_company_name'] = (string)$company['company_name'];
              $_SESSION['hermes_company_email'] = (string)$company['email'];
              header('Location: /empresa/dashboard/');
              exit;
            }
          }

        $auth['message'] = 'Credenciales invalidas.';
    } catch (Throwable $e) {
        $auth['message'] = 'Error de conexion a base de datos.';
    }
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GesMan HERMES | Login</title>
  <meta name="description" content="Ingreso seguro a GesMan HERMES.">
  <link rel="icon" type="image/svg+xml" href="/assets/img/favicon-hermes.svg">
  <link rel="shortcut icon" href="/assets/img/favicon-hermes.svg" type="image/svg+xml">
  <style>
    :root {
      --bg-1: #0b132b;
      --bg-2: #121c3f;
      --card: #111827;
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
    .page-back {
      position: fixed;
      top: 1rem;
      right: 1rem;
      z-index: 30;
    }
    .login-shell {
      width: min(980px, 100%);
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(17,24,39,.92);
      box-shadow: 0 28px 48px rgba(0,0,0,.35);
      overflow: hidden;
      display: grid;
      grid-template-columns: 1.05fr .95fr;
    }
    .brand-side {
      padding: 1.5rem;
      border-right: 1px solid #2b354f;
      background: linear-gradient(180deg, rgba(255,216,77,.09), rgba(17,24,39,.1));
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .brand-logo {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      text-align: center;
    }
    .brand-side svg {
      width: min(360px, 92%);
      height: auto;
      display: block;
      margin: 0 auto;
      justify-self: center;
      align-self: center;
    }

    .form-side {
      padding: 1.5rem;
      display: grid;
      align-content: center;
      gap: .9rem;
    }
    .badge {
      display: inline-flex;
      width: fit-content;
      border: 1px solid #735100;
      border-radius: 999px;
      color: var(--gold-2);
      padding: .24rem .58rem;
      font-size: .72rem;
      font-weight: 700;
      letter-spacing: .05em;
      text-transform: uppercase;
      background: rgba(244,180,0,.16);
    }
    .form-title {
      margin: .1rem 0 0;
      font-size: 1.35rem;
      color: #fff4b8;
    }
    .row { display: grid; gap: .35rem; }
    label { color: var(--muted); font-size: .9rem; }
    input {
      border: 1px solid #475569;
      border-radius: 10px;
      background: #0f172a;
      color: var(--txt);
      padding: .72rem .78rem;
      font-size: .95rem;
      outline: none;
    }
    input:focus { border-color: var(--gold-2); box-shadow: 0 0 0 3px rgba(255,216,77,.2); }
    .btn {
      margin-top: .3rem;
      border: 1px solid #8b6500;
      border-radius: 10px;
      background: linear-gradient(180deg, #ffe38b, #f4b400);
      color: #1f2937;
      font-weight: 800;
      font-size: .92rem;
      letter-spacing: .03em;
      padding: .75rem .9rem;
      cursor: pointer;
    }
    .btn.login-btn {
      margin-top: .8rem;
      font-weight: 700;
    }
    .btn.back-btn {
      margin-top: 0;
      border-color: #475569;
      background: #0f172a;
      color: #cbd5e1;
      font-weight: 600;
      text-decoration: none;
      text-align: center;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .btn.logout {
      border-color: #64748b;
      background: #1f2937;
      color: #e2e8f0;
    }
    .msg { font-size: .9rem; border-radius: 10px; padding: .62rem .72rem; border: 1px solid; }
    .msg.err { color: var(--danger); border-color: #7f1d1d; background: rgba(127,29,29,.2); }
    .msg.ok { color: var(--ok); border-color: #14532d; background: rgba(20,83,45,.2); }
    .meta { color: #94a3b8; font-size: .82rem; }
    .form-links {
      margin-top: .35rem;
      display: flex;
      justify-content: space-between;
      gap: .6rem;
      flex-wrap: wrap;
      font-size: .84rem;
    }
    .form-links a {
      color: #cbd5e1;
      text-decoration: underline;
      text-decoration-color: rgba(255,216,77,.45);
      text-underline-offset: 3px;
    }
    .form-links a:hover { color: #ffe38b; }

    @media (max-width: 900px) {
      .login-shell { grid-template-columns: 1fr; }
      .brand-side { border-right: 0; border-bottom: 1px solid #2b354f; }
      .page-back {
        top: .75rem;
        right: .75rem;
      }
    }
  </style>
</head>
<body>
  <a class="btn back-btn page-back" href="/">Volver a HERMES</a>
  <main class="login-shell">
    <section class="brand-side">
      <div class="brand-logo" aria-label="Logo GesMan HERMES">
        <?php readfile(__DIR__ . '/assets/img/logo-hermes-page.svg'); ?>
      </div>
    </section>

    <section class="form-side">
      <?php if (!$auth['ok']): ?>
        <span class="badge">Login seguro</span>
        <h2 class="form-title">Iniciar sesion</h2>

        <?php if ($auth['message'] !== ''): ?>
          <div class="msg err">
            <?php if ($auth['message_html'] !== ''): ?>
              <?= $auth['message_html'] ?>
            <?php else: ?>
              <?= htmlspecialchars($auth['message'], ENT_QUOTES, 'UTF-8') ?>
            <?php endif; ?>
          </div>
        <?php endif; ?>

        <form method="post" autocomplete="off">
          <div class="row">
            <label for="username">Usuario o correo</label>
            <input id="username" name="username" type="text" required>
          </div>
          <div class="row">
            <label for="password">Contrasena</label>
            <input id="password" name="password" type="password" required>
          </div>
          <button class="btn login-btn" type="submit">Entrar a HERMES</button>
        </form>
        <div class="form-links">
          <a href="/registro/">Crear cuenta empresarial</a>
        </div>
      <?php else: ?>
        <span class="badge">Sesion activa</span>
        <h2 class="form-title">Ingreso exitoso</h2>
        <div class="msg ok">Bienvenido <?= htmlspecialchars($auth['username'], ENT_QUOTES, 'UTF-8') ?>. Autenticacion correcta.</div>
        <div class="meta">Rol actual: <strong><?= htmlspecialchars((string)$auth['role'], ENT_QUOTES, 'UTF-8') ?></strong></div>
        <form method="post">
          <input type="hidden" name="logout" value="1">
          <button class="btn logout" type="submit">Cerrar sesion</button>
        </form>
      <?php endif; ?>
    </section>
  </main>
</body>
</html>
