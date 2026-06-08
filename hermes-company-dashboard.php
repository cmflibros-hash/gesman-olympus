<?php
require_once __DIR__ . '/security-helpers.php';
security_start_session();
security_apply_web_headers();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout'])) {
  if (!security_validate_csrf($_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    echo 'Solicitud no valida (CSRF).';
    exit;
  }
    security_logout_session();
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

$sessionIdleTimeoutSeconds = 20 * 60;
$sessionWarningSeconds = 5 * 60;
$sessionActivity = security_session_activity_status($sessionIdleTimeoutSeconds);
if ($sessionActivity['expired']) {
  security_logout_session();
  if (isset($_GET['keepalive']) && (string)$_GET['keepalive'] === '1') {
    http_response_code(401);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['ok' => false, 'expired' => true], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
  }
  header('Location: /login/?session_timeout=1');
  exit;
}

if (isset($_GET['keepalive']) && (string)$_GET['keepalive'] === '1') {
  header('Content-Type: application/json; charset=UTF-8');
  echo json_encode([
    'ok' => true,
    'expires_at' => (int)$sessionActivity['expires_at'],
    'idle_timeout_seconds' => $sessionIdleTimeoutSeconds,
    'warning_seconds' => $sessionWarningSeconds,
  ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}

$sessionExpiresAt = (int)$sessionActivity['expires_at'];

$module = (string)($_GET['module'] ?? 'dashboard');
if (!in_array($module, ['dashboard', 'plan', 'empresa', 'clientes', 'cotizaciones', 'papelera', 'configuracion', 'inventario', 'ordenes-servicio', 'reportes', 'formularios', 'tecnicos', 'carta-gantt'], true)) {
    $module = 'dashboard';
}

$csrfToken = security_csrf_token();

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

function ensure_column_best_effort(PDO $pdo, $table, $column, $definition)
{
  try {
    ensure_column($pdo, $table, $column, $definition);
  } catch (Throwable $e) {
    // Algunos usuarios de DB en produccion no tienen permisos ALTER; continuar sin bloquear el dashboard.
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

function table_exists(PDO $pdo, $table)
{
    $st = $pdo->prepare(
        'SELECT 1 FROM information_schema.TABLES
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t LIMIT 1'
    );
    $st->execute(['t' => $table]);
    return (bool)$st->fetchColumn();
}

function ensure_service_forms_tables(PDO $pdo)
{
  // Se ejecuta de forma aislada para no depender de otros bloques de migracion que pueden fallar por permisos ALTER.
  try {
    $pdo->exec('CREATE TABLE IF NOT EXISTS tenant_form_templates (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      tenant_company_id BIGINT UNSIGNED NOT NULL,
      name VARCHAR(190) NOT NULL,
      description TEXT NULL,
      fields_json LONGTEXT NOT NULL,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_by VARCHAR(190) NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      KEY idx_form_templates_tenant_active (tenant_company_id, is_active),
      KEY idx_form_templates_created (tenant_company_id, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS tenant_service_order_form_templates (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      tenant_company_id BIGINT UNSIGNED NOT NULL,
      service_order_id BIGINT UNSIGNED NOT NULL,
      form_template_id BIGINT UNSIGNED NOT NULL,
      sort_order INT UNSIGNED NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      KEY idx_so_form_templates_order (service_order_id, sort_order),
      KEY idx_so_form_templates_template (form_template_id),
      UNIQUE KEY uq_so_form_templates (service_order_id, form_template_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
  } catch (Throwable $e) {
    error_log('HERMES_SERVICE_FORMS_SCHEMA_WARN: ' . $e->getMessage());
  }
}

function smtp_read_response($socket)
{
  $response = '';
  while (!feof($socket)) {
    $line = fgets($socket, 515);
    if ($line === false) {
      break;
    }
    $response .= $line;
    if (preg_match('/^\d{3} /', $line) === 1) {
      break;
    }
  }
  return $response;
}

function smtp_expect_code($response, $acceptedCodes)
{
  if (!preg_match('/^(\d{3})/m', (string)$response, $m)) {
    return false;
  }
  return in_array((int)$m[1], $acceptedCodes, true);
}

function smtp_send_command($socket, $command, $acceptedCodes)
{
  fwrite($socket, $command . "\r\n");
  $response = smtp_read_response($socket);
  return smtp_expect_code($response, $acceptedCodes);
}

function load_mail_credentials()
{
  $path = __DIR__ . '/.mail_credentials.php';
  if (!is_file($path)) {
    return null;
  }

  $cfg = require $path;
  if (!is_array($cfg)) {
    return null;
  }

  $required = ['host', 'port', 'username', 'password', 'from_email'];
  foreach ($required as $key) {
    if (empty($cfg[$key])) {
      return null;
    }
  }

  if (empty($cfg['from_name'])) {
    $cfg['from_name'] = 'GesMan HERMES';
  }

  return $cfg;
}

function send_password_recovery_email_smtp($mailCfg, $toEmail, $toName, $resetLink)
{
  $host = (string)$mailCfg['host'];
  $port = (int)$mailCfg['port'];
  $username = (string)$mailCfg['username'];
  $password = (string)$mailCfg['password'];
  $fromEmail = (string)$mailCfg['from_email'];
  $fromName = (string)($mailCfg['from_name'] ?? 'GesMan HERMES');
  $secure = strtolower(trim((string)($mailCfg['secure'] ?? 'ssl')));

  $transport = ($secure === 'ssl' || $secure === 'tls') ? ($secure . '://') : '';
  $socket = @fsockopen($transport . $host, $port, $errno, $errstr, 20);
  if (!$socket) {
    return false;
  }

  stream_set_timeout($socket, 20);

  $helloResponse = smtp_read_response($socket);
  if (!smtp_expect_code($helloResponse, [220])) {
    fclose($socket);
    return false;
  }

  $serverName = $_SERVER['SERVER_NAME'] ?? 'localhost';
  if (!smtp_send_command($socket, 'EHLO ' . $serverName, [250])) {
    fclose($socket);
    return false;
  }
  if (!smtp_send_command($socket, 'AUTH LOGIN', [334])) {
    fclose($socket);
    return false;
  }
  if (!smtp_send_command($socket, base64_encode($username), [334])) {
    fclose($socket);
    return false;
  }
  if (!smtp_send_command($socket, base64_encode($password), [235])) {
    fclose($socket);
    return false;
  }
  if (!smtp_send_command($socket, 'MAIL FROM:<' . $fromEmail . '>', [250])) {
    fclose($socket);
    return false;
  }
  if (!smtp_send_command($socket, 'RCPT TO:<' . $toEmail . '>', [250, 251])) {
    fclose($socket);
    return false;
  }
  if (!smtp_send_command($socket, 'DATA', [354])) {
    fclose($socket);
    return false;
  }

  $safeToName = str_replace(["\r", "\n"], '', (string)$toName);
  $safeFromName = str_replace(["\r", "\n"], '', (string)$fromName);
  $subject = 'Recuperacion de clave en GesMan HERMES';
  $body = "Hola {$safeToName},\n\n" .
    "Recibimos una solicitud para cambiar tu clave de acceso.\n" .
    "Usa este enlace para crear una nueva clave (expira en 60 minutos):\n\n" .
    $resetLink . "\n\n" .
    "Si no solicitaste este cambio, ignora este correo.\n";

  $headers = [
    'Date: ' . date(DATE_RFC2822),
    'From: ' . $safeFromName . ' <' . $fromEmail . '>',
    'To: ' . $safeToName . ' <' . $toEmail . '>',
    'Subject: ' . $subject,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
  ];

  $payload = implode("\r\n", $headers) . "\r\n\r\n" . $body . "\r\n.\r\n";
  fwrite($socket, $payload);

  $dataResponse = smtp_read_response($socket);
  if (!smtp_expect_code($dataResponse, [250])) {
    fclose($socket);
    return false;
  }

  smtp_send_command($socket, 'QUIT', [221]);
  fclose($socket);
  return true;
}

function sanitize_email_header_value($value)
{
  return trim(str_replace(["\r", "\n"], '', (string)$value));
}

function parse_email_list($raw, $max = 10)
{
  $tokens = [];
  if (is_array($raw)) {
    $tokens = $raw;
  } else {
    $tokens = preg_split('/[;,\n\r]+/', (string)$raw) ?: [];
  }

  $emails = [];
  foreach ($tokens as $token) {
    $email = strtolower(trim((string)$token));
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
      continue;
    }
    if (!in_array($email, $emails, true)) {
      $emails[] = $email;
    }
    if (count($emails) >= (int)$max) {
      break;
    }
  }
  return $emails;
}

function sanitize_attachment_name($name, $fallback = 'adjunto.bin')
{
  $clean = preg_replace('/[^A-Za-z0-9._-]+/', '_', (string)$name);
  $clean = trim((string)$clean, '._-');
  if ($clean === '') {
    $clean = $fallback;
  }
  return substr($clean, 0, 120);
}

function smtp_send_data_payload($socket, $payload)
{
  $data = str_replace(["\r\n", "\r"], "\n", (string)$payload);
  $data = preg_replace('/\n\./', "\n..", $data);
  $data = str_replace("\n", "\r\n", (string)$data);
  fwrite($socket, $data . "\r\n.\r\n");
  $response = smtp_read_response($socket);
  return smtp_expect_code($response, [250]);
}

function quote_pdf_escape_text($text)
{
  $raw = trim((string)$text);
  $raw = preg_replace('/\s+/', ' ', (string)$raw);
  $ascii = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $raw);
  if (!is_string($ascii) || $ascii === '') {
    $ascii = preg_replace('/[^\x20-\x7E]/', '', $raw);
  }
  $ascii = str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], (string)$ascii);
  return trim((string)$ascii);
}

function quote_pdf_wrap_line($text, $maxLen = 95)
{
  $line = trim((string)$text);
  if ($line === '') {
    return [''];
  }

  $words = preg_split('/\s+/', $line) ?: [];
  $lines = [];
  $current = '';

  foreach ($words as $word) {
    $candidate = ($current === '' ? $word : $current . ' ' . $word);
    if (strlen($candidate) <= (int)$maxLen) {
      $current = $candidate;
    } else {
      if ($current !== '') {
        $lines[] = $current;
      }
      $current = $word;
    }
  }

  if ($current !== '') {
    $lines[] = $current;
  }

  return $lines;
}

function quote_prepare_fixed_item_rows(array $quoteItems, $maxRows = 15)
{
  $limit = max(1, (int)$maxRows);
  $rows = [];

  foreach ($quoteItems as $it) {
    if (count($rows) >= $limit) {
      break;
    }

    $itemType = strtolower(trim((string)($it['item_type'] ?? 'normal')));
    if (!in_array($itemType, ['normal', 'text'], true)) {
      $itemType = 'normal';
    }

    $rows[] = [
      'descripcion' => trim((string)($it['descripcion'] ?? '')),
      'item_type' => $itemType,
      'is_bold' => ((int)($it['is_bold'] ?? 0) === 1) ? 1 : 0,
      'cantidad' => (float)($it['cantidad'] ?? 0),
      'precio_unitario' => (float)($it['precio_unitario'] ?? 0),
      'total_linea' => (float)($it['total_linea'] ?? 0),
      '__empty' => false,
    ];
  }

  while (count($rows) < $limit) {
    $rows[] = [
      'descripcion' => '',
      'item_type' => 'normal',
      'is_bold' => 0,
      'cantidad' => 0.0,
      'precio_unitario' => 0.0,
      'total_linea' => 0.0,
      '__empty' => true,
    ];
  }

  return $rows;
}

function quote_prepare_item_pages(array $quoteItems, $rowsPerPage = 15)
{
  $limit = max(1, (int)$rowsPerPage);
  $slots = [];
  $descCharsPerLine = 58;

  foreach ($quoteItems as $it) {
    $itemType = strtolower(trim((string)($it['item_type'] ?? 'normal')));
    if (!in_array($itemType, ['normal', 'text'], true)) {
      $itemType = 'normal';
    }

    $descRaw = trim((string)($it['descripcion'] ?? ''));
    $descLines = quote_pdf_wrap_line($descRaw, $descCharsPerLine);
    if (empty($descLines)) {
      $descLines = [''];
    }

    foreach ($descLines as $idx => $descLine) {
      $slots[] = [
        'descripcion' => (string)$descLine,
        'item_type' => $itemType,
        'is_bold' => ((int)($it['is_bold'] ?? 0) === 1) ? 1 : 0,
        'cantidad' => (float)($it['cantidad'] ?? 0),
        'precio_unitario' => (float)($it['precio_unitario'] ?? 0),
        'total_linea' => (float)($it['total_linea'] ?? 0),
        '__empty' => false,
        '__show_values' => ($idx === 0),
      ];
    }
  }

  if (empty($slots)) {
    return [quote_prepare_fixed_item_rows([], $limit)];
  }

  $pages = [];
  foreach (array_chunk($slots, $limit) as $chunk) {
    $pageRows = [];
    foreach ($chunk as $row) {
      $pageRows[] = $row;
    }
    while (count($pageRows) < $limit) {
      $pageRows[] = [
        'descripcion' => '',
        'item_type' => 'normal',
        'is_bold' => 0,
        'cantidad' => 0.0,
        'precio_unitario' => 0.0,
        'total_linea' => 0.0,
        '__empty' => true,
        '__show_values' => false,
      ];
    }
    $pages[] = $pageRows;
  }

  return $pages;
}

function build_quote_preview_html_for_attachment(array $profile, $logoPublicUrl, array $quoteRow, array $quoteItems)
{
  $companyName = trim((string)($profile['nombre'] ?? ''));
  if ($companyName === '') {
    $companyName = 'GesMan HERMES';
  }
  $companyRut = trim((string)($profile['rut'] ?? ''));
  $companyEmail = trim((string)($profile['email_principal'] ?? ''));
  $companyAddress = trim((string)($profile['direccion'] ?? ''));
  $companyPhone = trim((string)($profile['telefono'] ?? ''));

  $quoteNumber = (string)($quoteRow['numero_cotizacion'] ?? '');
  $quoteDate = (string)($quoteRow['fecha_emision'] ?? '');
  $quoteState = (string)($quoteRow['estado'] ?? 'Pendiente');
  $customerName = (string)($quoteRow['customer_name'] ?? '');
  $customerRut = (string)($quoteRow['customer_rut'] ?? '');
  $customerContact = (string)($quoteRow['customer_contact'] ?? '');
  if ($customerContact === '') {
    $customerContact = (string)($quoteRow['customer_contact_name'] ?? '');
  }
  $customerEmail = (string)($quoteRow['customer_email'] ?? '');

  $validez = trim((string)($quoteRow['validez_override'] ?? ''));
  if ($validez === '') {
    $validez = trim((string)($profile['validez'] ?? ''));
  }
  if ($validez === '') {
    $validez = ((int)($quoteRow['validez_dias'] ?? 15)) . ' dias';
  }

  $entrega = trim((string)($quoteRow['entrega_override'] ?? ''));
  if ($entrega === '') {
    $entrega = trim((string)($profile['entrega'] ?? ''));
  }
  if ($entrega === '') {
    $entrega = 'No definida';
  }

  $condicionPago = trim((string)($quoteRow['condicion_de_pago_override'] ?? ''));
  if ($condicionPago === '') {
    $condicionPago = trim((string)($profile['condicion_de_pago'] ?? ''));
  }
  if ($condicionPago === '') {
    $condicionPago = 'No definida';
  }

  $moneda = trim((string)($quoteRow['moneda_override'] ?? ''));
  if ($moneda === '') {
    $moneda = trim((string)($profile['moneda'] ?? ''));
  }
  if ($moneda === '') {
    $moneda = 'CLP';
  }

  $itemPages = quote_prepare_item_pages(is_array($quoteItems) ? $quoteItems : [], 15);
  $totalItemPages = count($itemPages);

  $money = quote_money_breakdown((float)($quoteRow['subtotal'] ?? 0), (float)($quoteRow['descuento_pct'] ?? 0));

  $obsRaw = trim((string)($quoteRow['observaciones'] ?? ''));

  ob_start();
  ?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cotizacion <?= htmlspecialchars((string)$quoteNumber, ENT_QUOTES, 'UTF-8') ?></title>
  <style>
    @page { size: Letter; margin: 7mm; }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      background: #fff;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    body {
      font-family: Arial, Helvetica, sans-serif;
      font-size: 13px;
      line-height: 1.25;
      color: #111827;
    }
     /* Area imprimible definida por @page (Letter, 12mm) para mantener
       consistencia entre Chrome headless y la impresion del navegador. */
    .page {
      width: 100%;
      margin: 0;
      background: #fff;
      border: 0;
      box-shadow: none;
      padding: 0;
      min-height: calc(11in - 24mm);
      display: flex;
      flex-direction: column;
    }
    .page-break {
      page-break-after: always;
      break-after: page;
    }
    .head-table { width: 100%; border-collapse: collapse; margin-bottom: 14px; border-bottom: 2px solid #0f172a; }
    .head-table > tbody > tr > td { vertical-align: top; padding: 0 8px 10px; border: 0; background: transparent; }
    .head-table .col-logo { width: 200px; padding-left: 0; }
    .head-table .col-quote { width: 200px; text-align: right; padding-right: 0; }
    .quote-logo { max-height: 92px; max-width: 190px; width: auto; height: auto; display: block; }
    .head-table h1 { margin: 0 0 4px; font-size: 18px; letter-spacing: .03em; line-height: 1.2; }
    .muted { color: #4b5563; font-size: 13px; line-height: 1.3; }
    .head-table .muted { font-size: 12px; }
    .quote-doc-label { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: .08em; font-weight: 700; }
    .quote-doc-number { font-size: 18px; font-weight: 800; line-height: 1.15; color: #0f172a; word-break: break-word; margin-bottom: 4px; }
    .info-table { width: 100%; border-collapse: separate; border-spacing: 12px 0; margin: 0 -12px 14px; table-layout: fixed; }
    .info-table > tbody > tr > td { width: 50%; vertical-align: top; border: 1px solid #d1d5db; border-radius: 8px; padding: 10px; background: #fff; }
    .info-table h3 { margin: 0 0 8px; font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: #374151; }
    .quote-items-section {
      margin-bottom: 0;
      flex: 1 1 auto;
    }
    .quote-items-section table { page-break-inside: auto; }
    .quote-items-section thead { display: table-header-group; }
    .quote-items-section tr { page-break-inside: avoid; break-inside: avoid; }
    table.items { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; table-layout: fixed; }
    table.items th, table.items td { border: 1px solid #bfdbfe; padding: 7px; vertical-align: top; line-height: 1.25; }
    table.items th { background: #dbeafe; color: #1e3a8a; text-align: left; }
    table.items tbody tr:nth-child(even) td { background: #f8fbff; }
    table.items tbody tr { height: 32px; }
    table.items td.desc-cell {
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .obs { margin-top: 14px; border: 1px solid #d1d5db; border-radius: 8px; padding: 10px; white-space: pre-line; font-size: 13px; }
    .quote-financials-wrap {
      padding-top: 12px;
      margin-top: auto;
      page-break-inside: avoid;
      break-inside: avoid;
    }
    .quote-financials {
      width: 100%;
      border-collapse: separate;
      border-spacing: 10px 0;
      margin: 0 -10px;
      table-layout: fixed;
    }
    .quote-financials > tbody > tr { page-break-inside: avoid; break-inside: avoid; }
    .quote-financials > tbody > tr > td { vertical-align: top; padding: 0; }
    .quote-financials .col-terms { width: 50%; }
    .quote-financials .col-totals { width: 50%; }
    .quote-terms-box, .totals-box { border: 1px solid #d1d5db; border-radius: 8px; background: #fff; min-height: 156px; page-break-inside: avoid; break-inside: avoid; }
    .quote-terms-box { padding: 10px; }
    .quote-terms-title { margin: 0; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: #374151; }
    .quote-terms-content { white-space: pre-line; font-size: 12px; line-height: 1.3; color: #374151; margin-top: 6px; }
    .quote-financials-placeholder .quote-terms-content {
      color: #6b7280;
      font-style: italic;
    }
    .quote-page-indicator {
      margin: 0;
      padding: 10px;
      font-size: 12px;
      color: #374151;
      text-align: right;
    }
    .totals { margin: 0; width: 100%; border-collapse: collapse; font-size: 13px; }
    .totals td { font-weight: 600; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; }
    .totals tr:last-child td { font-size: 15px; background: #dbeafe; color: #1e3a8a; border-bottom: 0; }
  </style>
</head>
<body>
  <?php foreach ($itemPages as $pageIndex => $pageRows): ?>
  <?php $isLastPage = ($pageIndex === ($totalItemPages - 1)); ?>
  <article class="page<?= $pageIndex < ($totalItemPages - 1) ? ' page-break' : '' ?>">
    <table class="head-table">
      <tbody>
        <tr>
          <td class="col-logo">
            <?php if (trim((string)$logoPublicUrl) !== ''): ?>
              <img class="quote-logo" src="<?= htmlspecialchars((string)$logoPublicUrl, ENT_QUOTES, 'UTF-8') ?>" alt="Logo empresa">
            <?php endif; ?>
          </td>
          <td class="col-company">
            <h1><?= htmlspecialchars($companyName, ENT_QUOTES, 'UTF-8') ?></h1>
            <div class="muted">RUT: <?= htmlspecialchars($companyRut, ENT_QUOTES, 'UTF-8') ?></div>
            <div class="muted">Email: <?= htmlspecialchars($companyEmail, ENT_QUOTES, 'UTF-8') ?></div>
            <?php if ($companyAddress !== ''): ?><div class="muted">Direccion: <?= htmlspecialchars($companyAddress, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
            <?php if ($companyPhone !== ''): ?><div class="muted">Telefono: <?= htmlspecialchars($companyPhone, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
          </td>
          <td class="col-quote">
            <div class="quote-doc-label">Cotizacion</div>
            <div class="quote-doc-number"><?= htmlspecialchars($quoteNumber, ENT_QUOTES, 'UTF-8') ?></div>
            <div class="muted">Fecha: <?= htmlspecialchars($quoteDate, ENT_QUOTES, 'UTF-8') ?></div>
            <div class="muted">Estado: <?= htmlspecialchars($quoteState, ENT_QUOTES, 'UTF-8') ?></div>
          </td>
        </tr>
      </tbody>
    </table>

    <table class="info-table">
      <tbody>
        <tr>
          <td>
            <h3>Cliente</h3>
            <div><strong><?= htmlspecialchars($customerName, ENT_QUOTES, 'UTF-8') ?></strong></div>
            <div class="muted">RUT: <?= htmlspecialchars($customerRut, ENT_QUOTES, 'UTF-8') ?></div>
            <div class="muted">Contacto: <?= htmlspecialchars($customerContact, ENT_QUOTES, 'UTF-8') ?></div>
            <div class="muted">Email: <?= htmlspecialchars($customerEmail, ENT_QUOTES, 'UTF-8') ?></div>
          </td>
          <td>
            <h3>Condiciones</h3>
            <div class="muted">Validez: <?= htmlspecialchars($validez, ENT_QUOTES, 'UTF-8') ?></div>
            <div class="muted">Entrega: <?= htmlspecialchars($entrega, ENT_QUOTES, 'UTF-8') ?></div>
            <div class="muted">Condicion de pago: <?= htmlspecialchars($condicionPago, ENT_QUOTES, 'UTF-8') ?></div>
            <div class="muted">Moneda: <?= htmlspecialchars($moneda, ENT_QUOTES, 'UTF-8') ?></div>
          </td>
        </tr>
      </tbody>
    </table>

    <section class="quote-items-section">
      <table class="items">
        <thead>
          <tr>
            <th style="width:52%;">Descripcion</th>
            <th style="width:12%;">Cantidad</th>
            <th style="width:18%;">Precio unitario</th>
            <th style="width:18%;">Total linea</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($pageRows as $it): ?>
            <?php
              $itemType = strtolower(trim((string)($it['item_type'] ?? 'normal')));
              if (!in_array($itemType, ['normal', 'text'], true)) {
                $itemType = 'normal';
              }
              $isBold = ((int)($it['is_bold'] ?? 0) === 1);
              $isEmpty = !empty($it['__empty']);
              $showValues = isset($it['__show_values']) ? !empty($it['__show_values']) : true;
              $desc = htmlspecialchars((string)($it['descripcion'] ?? ''), ENT_QUOTES, 'UTF-8');
            ?>
            <tr>
              <td class="desc-cell"><?= $isBold ? '<strong>' . $desc . '</strong>' : ($desc !== '' ? $desc : '&nbsp;') ?></td>
              <td><?= ($isEmpty || !$showValues) ? '&nbsp;' : ($itemType === 'text' ? '-' : htmlspecialchars((string)($it['cantidad'] ?? ''), ENT_QUOTES, 'UTF-8')) ?></td>
              <td><?= ($isEmpty || !$showValues) ? '&nbsp;' : ($itemType === 'text' ? '-' : ('$' . htmlspecialchars(money_clp((float)($it['precio_unitario'] ?? 0)), ENT_QUOTES, 'UTF-8'))) ?></td>
              <td><?= ($isEmpty || !$showValues) ? '&nbsp;' : ($itemType === 'text' ? '-' : ('$' . htmlspecialchars(money_clp((float)($it['total_linea'] ?? 0)), ENT_QUOTES, 'UTF-8'))) ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </section>

    <?php if ($isLastPage && $obsRaw !== ''): ?>
      <section class="obs">
        <strong>Observaciones</strong>
        <div><?= htmlspecialchars((string)$quoteRow['observaciones'], ENT_QUOTES, 'UTF-8') ?></div>
      </section>
    <?php endif; ?>

    <?php if ($isLastPage): ?>
    <div class="quote-financials-wrap" id="quoteFinancialsWrap">
      <table class="quote-financials">
        <tbody>
          <tr>
            <td class="col-terms">
              <div class="quote-terms-box">
                <h4 class="quote-terms-title">Terminos y condiciones adicionales</h4>
                <div class="quote-terms-content"><?= htmlspecialchars(trim((string)($quoteRow['terminos_condiciones_adicionales'] ?? '')) !== '' ? (string)$quoteRow['terminos_condiciones_adicionales'] : 'Sin terminos adicionales.', ENT_QUOTES, 'UTF-8') ?></div>
              </div>
            </td>
            <td class="col-totals">
              <div class="totals-box">
                <table class="totals">
                  <tbody>
                    <tr><td>Subtotal</td><td style="text-align:right;">$<?= htmlspecialchars(money_clp((float)$money['subtotal']), ENT_QUOTES, 'UTF-8') ?></td></tr>
                    <tr><td>Descuento (<?= htmlspecialchars(number_format((float)$money['descuento_pct'], 2, '.', ''), ENT_QUOTES, 'UTF-8') ?>%)</td><td style="text-align:right;">$<?= htmlspecialchars(money_clp((float)$money['descuento_monto']), ENT_QUOTES, 'UTF-8') ?></td></tr>
                    <tr><td>IVA (19%)</td><td style="text-align:right;">$<?= htmlspecialchars(money_clp((float)$money['iva_monto']), ENT_QUOTES, 'UTF-8') ?></td></tr>
                    <tr><td>Total</td><td style="text-align:right;">$<?= htmlspecialchars(money_clp((float)$money['total']), ENT_QUOTES, 'UTF-8') ?></td></tr>
                  </tbody>
                </table>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <?php else: ?>
    <div class="quote-financials-wrap quote-financials-placeholder" id="quoteFinancialsWrap">
      <table class="quote-financials">
        <tbody>
          <tr>
            <td class="col-terms">
              <div class="quote-terms-box">
                <h4 class="quote-terms-title">Terminos y condiciones adicionales</h4>
                <div class="quote-terms-content">Continua en la siguiente pagina.</div>
              </div>
            </td>
            <td class="col-totals">
              <div class="totals-box">
                <p class="quote-page-indicator">Pagina <?= (int)($pageIndex + 1) ?> de <?= (int)$totalItemPages ?></p>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <?php endif; ?>
  </article>
  <?php endforeach; ?>
</body>
</html>
<?php

  return (string)ob_get_clean();
}

function build_quote_pdf_attachment($companyName, $previewUrl, array $quoteRow, array $quoteItems, array $profile = [], $logoPublicUrl = '')
{
  $quoteNumber = (string)($quoteRow['numero_cotizacion'] ?? '');
  $attachmentName = sanitize_attachment_name('cotizacion-' . ($quoteNumber !== '' ? $quoteNumber : date('Ymd_His')) . '.pdf', 'cotizacion.pdf');

  // Intento principal: generar PDF estilizado local sin auto-llamadas HTTP para evitar bloqueos/timeout.
  $styledError = '';
  try {
    $html = build_quote_preview_html_for_attachment($profile, $logoPublicUrl, $quoteRow, $quoteItems);
    if (trim($html) !== '') {
      $tmpHtmlBase = @tempnam(sys_get_temp_dir(), 'quote_html_');
      $tmpPdfBase = @tempnam(sys_get_temp_dir(), 'quote_pdf_');
      if (is_string($tmpHtmlBase) && $tmpHtmlBase !== '' && is_string($tmpPdfBase) && $tmpPdfBase !== '') {
        $tmpHtmlPath = $tmpHtmlBase . '.html';
        $tmpPdfPath = $tmpPdfBase . '.pdf';
        @unlink($tmpHtmlBase);
        @unlink($tmpPdfBase);
        @file_put_contents($tmpHtmlPath, $html);

        $timeoutPrefix = '';
        if (PHP_OS_FAMILY !== 'Windows' && is_executable('/usr/bin/timeout')) {
          $timeoutPrefix = escapeshellarg('/usr/bin/timeout') . ' 25s ';
        }

        $htmlFileUrl = 'file://' . str_replace(DIRECTORY_SEPARATOR, '/', $tmpHtmlPath);
        $chromeEnvPrefix = '';
        $chromeUserDataDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'chrome_pdf_' . (string)getmypid() . '_' . uniqid();
        @mkdir($chromeUserDataDir, 0700, true);
        $cleanupChromeUserDataDir = null;
        $cleanupChromeUserDataDir = static function ($dir) use (&$cleanupChromeUserDataDir) {
          if (!is_string($dir) || $dir === '' || !is_dir($dir)) {
            return;
          }
          $items = @scandir($dir);
          if (!is_array($items)) {
            @rmdir($dir);
            return;
          }
          foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
              continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
              $cleanupChromeUserDataDir($path);
            } else {
              @unlink($path);
            }
          }
          @rmdir($dir);
        };
        if (PHP_OS_FAMILY !== 'Windows') {
          $chromeEnvPrefix = 'env HOME=/tmp XDG_CONFIG_HOME=/tmp XDG_CACHE_HOME=/tmp XDG_RUNTIME_DIR=/tmp ';
        }

        // Motor principal: Chromium/Chrome headless (mismo motor de render que el navegador).
        $chromeCandidates = [
          '/usr/bin/google-chrome-stable',
          '/usr/bin/chromium-browser',
          '/snap/bin/chromium',
          '/usr/bin/chromium',
          '/usr/bin/google-chrome',
          'chromium-browser',
          'chromium',
          'google-chrome-stable',
          'google-chrome',
        ];
        foreach ($chromeCandidates as $chromeBin) {
          @unlink($tmpPdfPath);
          $cmd = $chromeEnvPrefix
            . $timeoutPrefix
            . escapeshellarg($chromeBin)
            . ' --headless --disable-gpu --no-sandbox --disable-dev-shm-usage'
            . ' --allow-file-access-from-files --run-all-compositor-stages-before-draw'
            . ' --no-first-run --no-default-browser-check --disable-crash-reporter --disable-breakpad'
            . ' --user-data-dir=' . escapeshellarg($chromeUserDataDir)
            . ' --print-to-pdf-no-header'
            . ' --no-pdf-header-footer'
            . ' --print-to-pdf=' . escapeshellarg($tmpPdfPath)
            . ' ' . escapeshellarg($htmlFileUrl)
            . ' 2>&1';

          $out = [];
          $code = 1;
          @exec($cmd, $out, $code);

          if ($code === 0 && is_file($tmpPdfPath)) {
            $pdfStyled = @file_get_contents($tmpPdfPath);
            if (is_string($pdfStyled) && strlen($pdfStyled) > 20 && strncmp($pdfStyled, '%PDF', 4) === 0) {
              error_log('HERMES_QUOTE_PDF_ENGINE: chrome bin=' . $chromeBin . ' quote=' . ($quoteNumber !== '' ? $quoteNumber : 'N/A'));
              $cleanupChromeUserDataDir($chromeUserDataDir);
              @unlink($tmpHtmlPath);
              @unlink($tmpPdfPath);
              return [
                'name' => $attachmentName,
                'mime' => 'application/pdf',
                'content' => $pdfStyled,
              ];
            }
          }

          $styledError = 'chromium exit=' . (string)$code . ' output=' . implode(' | ', array_slice($out, -5));
        }
        $cleanupChromeUserDataDir($chromeUserDataDir);
        error_log('HERMES_QUOTE_PDF_CHROME_FALLBACK: quote=' . ($quoteNumber !== '' ? $quoteNumber : 'N/A') . ' reason=' . $styledError);

        $wkhtmlCandidates = ['/usr/bin/wkhtmltopdf', '/usr/local/bin/wkhtmltopdf', 'wkhtmltopdf'];
        foreach ($wkhtmlCandidates as $wkhtmlBin) {
          $cmd = $timeoutPrefix
            . escapeshellarg($wkhtmlBin)
            . ' --quiet --encoding UTF-8 --page-size Letter --background --dpi 96'
            . ' --margin-top 0 --margin-right 0 --margin-bottom 0 --margin-left 0'
            . ' --load-error-handling ignore --load-media-error-handling ignore'
            . ' --disable-javascript --disable-smart-shrinking'
            . ' --enable-local-file-access'
            . ' ' . escapeshellarg($tmpHtmlPath)
            . ' ' . escapeshellarg($tmpPdfPath)
            . ' 2>&1';

          $out = [];
          $code = 1;
          @exec($cmd, $out, $code);

          if ($code === 0 && is_file($tmpPdfPath)) {
            $pdfStyled = @file_get_contents($tmpPdfPath);
            if (is_string($pdfStyled) && strlen($pdfStyled) > 20 && strncmp($pdfStyled, '%PDF', 4) === 0) {
              error_log('HERMES_QUOTE_PDF_ENGINE: wkhtmltopdf bin=' . $wkhtmlBin . ' quote=' . ($quoteNumber !== '' ? $quoteNumber : 'N/A'));
              @unlink($tmpHtmlPath);
              @unlink($tmpPdfPath);
              return [
                'name' => $attachmentName,
                'mime' => 'application/pdf',
                'content' => $pdfStyled,
              ];
            }
          }

          $styledError = 'wkhtmltopdf exit=' . (string)$code . ' output=' . implode(' | ', array_slice($out, -5));
        }

        @unlink($tmpHtmlPath);
        @unlink($tmpPdfPath);
      }
    }
  } catch (Throwable $pdfError) {
    $styledError = $pdfError->getMessage();
  }
  throw new RuntimeException('No fue posible generar el PDF estilizado de cotizacion. ' . $styledError);
}

function send_quote_email_smtp($mailCfg, array $toList, array $ccList, $subject, $textMessage, $htmlMessage, array $attachments)
{
  if (empty($toList)) {
    return false;
  }

  $host = (string)$mailCfg['host'];
  $port = (int)$mailCfg['port'];
  $username = (string)$mailCfg['username'];
  $password = (string)$mailCfg['password'];
  $fromEmail = (string)$mailCfg['from_email'];
  $fromName = sanitize_email_header_value((string)($mailCfg['from_name'] ?? 'GesMan HERMES'));
  $secure = strtolower(trim((string)($mailCfg['secure'] ?? 'ssl')));

  $transport = ($secure === 'ssl' || $secure === 'tls') ? ($secure . '://') : '';
  $socket = @fsockopen($transport . $host, $port, $errno, $errstr, 20);
  if (!$socket) {
    return false;
  }
  stream_set_timeout($socket, 25);

  $helloResponse = smtp_read_response($socket);
  if (!smtp_expect_code($helloResponse, [220])) {
    fclose($socket);
    return false;
  }

  $serverName = $_SERVER['SERVER_NAME'] ?? 'localhost';
  if (!smtp_send_command($socket, 'EHLO ' . $serverName, [250])
    || !smtp_send_command($socket, 'AUTH LOGIN', [334])
    || !smtp_send_command($socket, base64_encode($username), [334])
    || !smtp_send_command($socket, base64_encode($password), [235])
    || !smtp_send_command($socket, 'MAIL FROM:<' . $fromEmail . '>', [250])) {
    fclose($socket);
    return false;
  }

  $allRecipients = array_values(array_unique(array_merge($toList, $ccList)));
  foreach ($allRecipients as $recipient) {
    if (!smtp_send_command($socket, 'RCPT TO:<' . $recipient . '>', [250, 251])) {
      fclose($socket);
      return false;
    }
  }
  if (!smtp_send_command($socket, 'DATA', [354])) {
    fclose($socket);
    return false;
  }

  $safeSubject = sanitize_email_header_value($subject !== '' ? $subject : 'Cotizacion');
  $toHeader = implode(', ', $toList);
  $ccHeader = implode(', ', $ccList);
  $mixedBoundary = 'mix_' . bin2hex(random_bytes(12));
  $altBoundary = 'alt_' . bin2hex(random_bytes(12));

  $headers = [
    'Date: ' . date(DATE_RFC2822),
    'From: ' . $fromName . ' <' . $fromEmail . '>',
    'To: ' . $toHeader,
    'Subject: ' . $safeSubject,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="' . $mixedBoundary . '"',
  ];
  if ($ccHeader !== '') {
    $headers[] = 'Cc: ' . $ccHeader;
  }

  $textBody = trim((string)$textMessage);
  if ($textBody === '') {
    $textBody = 'Adjuntamos y compartimos el detalle de la cotizacion solicitada.';
  }

  $safeHtml = (string)$htmlMessage;
  if ($safeHtml === '') {
    $safeHtml = '<p>Adjuntamos y compartimos el detalle de la cotizacion solicitada.</p>';
  }

  $body = [];
  $body[] = '--' . $mixedBoundary;
  $body[] = 'Content-Type: multipart/alternative; boundary="' . $altBoundary . '"';
  $body[] = '';
  $body[] = '--' . $altBoundary;
  $body[] = 'Content-Type: text/plain; charset=UTF-8';
  $body[] = 'Content-Transfer-Encoding: 8bit';
  $body[] = '';
  $body[] = $textBody;
  $body[] = '';
  $body[] = '--' . $altBoundary;
  $body[] = 'Content-Type: text/html; charset=UTF-8';
  $body[] = 'Content-Transfer-Encoding: 8bit';
  $body[] = '';
  $body[] = $safeHtml;
  $body[] = '';
  $body[] = '--' . $altBoundary . '--';

  foreach ($attachments as $attachment) {
    $name = sanitize_attachment_name((string)($attachment['name'] ?? ''), 'adjunto.bin');
    $mime = trim((string)($attachment['mime'] ?? 'application/octet-stream'));
    if ($mime === '') {
      $mime = 'application/octet-stream';
    }
    $content = (string)($attachment['content'] ?? '');
    if ($content === '') {
      continue;
    }

    $body[] = '';
    $body[] = '--' . $mixedBoundary;
    $body[] = 'Content-Type: ' . $mime . '; name="' . $name . '"';
    $body[] = 'Content-Disposition: attachment; filename="' . $name . '"';
    $body[] = 'Content-Transfer-Encoding: base64';
    $body[] = '';
    $body[] = chunk_split(base64_encode($content));
  }

  $body[] = '';
  $body[] = '--' . $mixedBoundary . '--';

  $payload = implode("\r\n", $headers) . "\r\n\r\n" . implode("\r\n", $body);
  $ok = smtp_send_data_payload($socket, $payload);
  smtp_send_command($socket, 'QUIT', [221, 250]);
  fclose($socket);
  return $ok;
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

    $imageInfo = @getimagesize($tmp);
    if (!is_array($imageInfo) || empty($imageInfo[0]) || empty($imageInfo[1])) {
      throw new RuntimeException('El archivo subido no es una imagen valida.');
    }

    $width = (int)$imageInfo[0];
    $height = (int)$imageInfo[1];
    if ($width < 32 || $height < 32 || $width > 6000 || $height > 6000) {
      throw new RuntimeException('El logo debe tener dimensiones validas (entre 32px y 6000px por lado).');
    }

    $imageType = (int)($imageInfo[2] ?? 0);
    $typeToMime = [
      IMAGETYPE_JPEG => 'image/jpeg',
      IMAGETYPE_PNG => 'image/png',
      IMAGETYPE_WEBP => 'image/webp',
    ];
    $detectedMime = $typeToMime[$imageType] ?? '';
    if ($detectedMime === '' || $detectedMime !== $mime) {
      throw new RuntimeException('El archivo no cumple las validaciones de tipo de imagen.');
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

function service_report_relative_dir($tenantCompanyId)
{
  return 'service_reports/' . (int)$tenantCompanyId;
}

function service_report_absolute_dir($tenantCompanyId, $create = false)
{
  $root = uploads_root_dir($create);
  $dir = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, service_report_relative_dir((int)$tenantCompanyId));
  if ($create && !is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
    throw new RuntimeException('No se pudo crear directorio de reportes.');
  }
  return $dir;
}

function service_report_photo_public_url($relativePath)
{
  $rel = trim((string)$relativePath);
  if ($rel === '') {
    return '';
  }
  return '/uploads/' . ltrim(str_replace('\\', '/', $rel), '/');
}

function store_service_report_photo($file, $tenantCompanyId, $serviceOrderId, $technicianId)
{
  $error = (int)($file['error'] ?? UPLOAD_ERR_NO_FILE);
  if ($error === UPLOAD_ERR_NO_FILE) {
    return null;
  }
  if ($error !== UPLOAD_ERR_OK) {
    throw new RuntimeException('No se pudo subir una foto del reporte.');
  }

  $tmp = (string)($file['tmp_name'] ?? '');
  if ($tmp === '' || !is_uploaded_file($tmp)) {
    throw new RuntimeException('No se pudo leer un archivo temporal de foto.');
  }

  $size = (int)($file['size'] ?? 0);
  if ($size <= 0 || $size > 8 * 1024 * 1024) {
    throw new RuntimeException('Cada foto debe pesar maximo 8MB.');
  }

  $finfo = new finfo(FILEINFO_MIME_TYPE);
  $mime = (string)$finfo->file($tmp);
  $ext = logo_ext_from_mime($mime);
  if ($ext === null) {
    throw new RuntimeException('Formato de foto no permitido. Usa JPG, PNG o WEBP.');
  }

  $imageInfo = @getimagesize($tmp);
  if (!is_array($imageInfo) || empty($imageInfo[0]) || empty($imageInfo[1])) {
    throw new RuntimeException('Una foto no es una imagen valida.');
  }

  $width = (int)$imageInfo[0];
  $height = (int)$imageInfo[1];
  if ($width < 32 || $height < 32 || $width > 8000 || $height > 8000) {
    throw new RuntimeException('Las fotos deben tener dimensiones validas.');
  }

  $dir = service_report_absolute_dir((int)$tenantCompanyId, true);
  $name = 'os_' . (int)$serviceOrderId . '_tech_' . (int)$technicianId . '_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
  $path = $dir . DIRECTORY_SEPARATOR . $name;
  if (!move_uploaded_file($tmp, $path)) {
    throw new RuntimeException('No se pudo guardar una foto del reporte.');
  }

  return [
    'path' => service_report_relative_dir((int)$tenantCompanyId) . '/' . $name,
    'name' => (string)($file['name'] ?? $name),
    'size' => $size,
    'uploaded_at' => date('Y-m-d H:i:s'),
  ];
}

function service_report_photo_records_normalize($raw)
{
  if (is_string($raw)) {
    $decoded = json_decode($raw, true);
    if (is_array($decoded)) {
      $raw = $decoded;
    }
  }
  if (!is_array($raw)) {
    return [];
  }

  $out = [];
  foreach ($raw as $item) {
    if (!is_array($item)) {
      continue;
    }
    $path = trim((string)($item['path'] ?? ''));
    if ($path === '') {
      continue;
    }
    $out[] = [
      'path' => $path,
      'name' => trim((string)($item['name'] ?? '')),
      'size' => (int)($item['size'] ?? 0),
      'uploaded_at' => trim((string)($item['uploaded_at'] ?? '')),
      'template_id' => (int)($item['template_id'] ?? 0),
      'field_key' => trim((string)($item['field_key'] ?? '')),
      'url' => service_report_photo_public_url($path),
    ];
  }
  return $out;
}

function service_report_collect_uploaded_photos($filesField, $tenantCompanyId, $serviceOrderId, $technicianId)
{
  if (!is_array($filesField) || !isset($filesField['name'])) {
    return [];
  }

  $names = (array)($filesField['name'] ?? []);
  $errors = (array)($filesField['error'] ?? []);
  $tmpNames = (array)($filesField['tmp_name'] ?? []);
  $sizes = (array)($filesField['size'] ?? []);
  $types = (array)($filesField['type'] ?? []);

  $saved = [];
  foreach ($names as $idx => $n) {
    $file = [
      'name' => $n,
      'error' => $errors[$idx] ?? UPLOAD_ERR_NO_FILE,
      'tmp_name' => $tmpNames[$idx] ?? '',
      'size' => $sizes[$idx] ?? 0,
      'type' => $types[$idx] ?? '',
    ];
    $stored = store_service_report_photo($file, $tenantCompanyId, $serviceOrderId, $technicianId);
    if (is_array($stored)) {
      $saved[] = $stored;
    }
  }
  return $saved;
}

function store_service_report_form_photo($file, $tenantCompanyId, $serviceOrderId, $technicianId, $templateId, $fieldKey)
{
  $stored = store_service_report_photo($file, $tenantCompanyId, $serviceOrderId, $technicianId);
  if (!is_array($stored)) {
    return null;
  }
  $stored['template_id'] = (int)$templateId;
  $stored['field_key'] = trim((string)$fieldKey);
  return $stored;
}

function service_report_collect_uploaded_form_photos($filesField, $tenantCompanyId, $serviceOrderId, $technicianId)
{
  if (!is_array($filesField) || !isset($filesField['name']) || !is_array($filesField['name'])) {
    return [];
  }

  $saved = [];
  foreach ($filesField['name'] as $groupKey => $groupNames) {
    if (!is_array($groupNames)) {
      continue;
    }
    $groupKeyRaw = trim((string)$groupKey);
    if ($groupKeyRaw === '') {
      continue;
    }
    $parts = explode('__', $groupKeyRaw, 2);
    $templateId = (int)($parts[0] ?? 0);
    $fieldKey = trim((string)($parts[1] ?? ''));
    if ($templateId <= 0 || $fieldKey === '') {
      continue;
    }

    foreach ($groupNames as $idx => $name) {
      $file = [
        'name' => $name,
        'error' => $filesField['error'][$groupKey][$idx] ?? UPLOAD_ERR_NO_FILE,
        'tmp_name' => $filesField['tmp_name'][$groupKey][$idx] ?? '',
        'size' => $filesField['size'][$groupKey][$idx] ?? 0,
        'type' => $filesField['type'][$groupKey][$idx] ?? '',
      ];
      $stored = store_service_report_form_photo($file, $tenantCompanyId, $serviceOrderId, $technicianId, $templateId, $fieldKey);
      if (is_array($stored)) {
        $saved[] = $stored;
      }
    }
  }

  return $saved;
}

function service_report_signature_relative_dir($tenantCompanyId)
{
  return service_report_relative_dir((int)$tenantCompanyId) . '/signatures';
}

function service_report_signature_absolute_dir($tenantCompanyId, $create = false)
{
  $root = uploads_root_dir($create);
  $dir = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, service_report_signature_relative_dir((int)$tenantCompanyId));
  if ($create && !is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
    throw new RuntimeException('No se pudo crear directorio de firmas de reportes.');
  }
  return $dir;
}

function service_report_signature_draw_public_url($relativePath)
{
  return service_report_photo_public_url((string)$relativePath);
}

function store_service_report_signature_drawing($dataUrl, $tenantCompanyId, $serviceOrderId, $technicianId, $role)
{
  $raw = trim((string)$dataUrl);
  if ($raw === '') {
    return '';
  }

  if (!preg_match('#^data:image/(png|jpe?g);base64,#i', $raw, $m)) {
    throw new RuntimeException('Formato invalido de firma digital.');
  }

  $base64 = substr($raw, strpos($raw, ',') + 1);
  $binary = base64_decode($base64, true);
  if (!is_string($binary) || $binary === '') {
    throw new RuntimeException('No se pudo procesar la firma digital.');
  }

  if (strlen($binary) > 900 * 1024) {
    throw new RuntimeException('La firma digital supera el tamano permitido.');
  }

  $imageInfo = @getimagesizefromstring($binary);
  if (!is_array($imageInfo) || empty($imageInfo[0]) || empty($imageInfo[1])) {
    throw new RuntimeException('La firma digital no es una imagen valida.');
  }

  $width = (int)$imageInfo[0];
  $height = (int)$imageInfo[1];
  if ($width < 120 || $height < 40 || $width > 2400 || $height > 1200) {
    throw new RuntimeException('La firma digital tiene dimensiones fuera de rango.');
  }

  $extRaw = strtolower((string)($m[1] ?? 'png'));
  $ext = ($extRaw === 'jpeg' || $extRaw === 'jpg') ? 'jpg' : 'png';
  $roleSlug = ($role === 'customer') ? 'customer' : 'technician';

  $dir = service_report_signature_absolute_dir((int)$tenantCompanyId, true);
  $name = 'sig_os_' . (int)$serviceOrderId . '_tech_' . (int)$technicianId . '_' . $roleSlug . '_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
  $fullPath = $dir . DIRECTORY_SEPARATOR . $name;

  if (@file_put_contents($fullPath, $binary) === false) {
    throw new RuntimeException('No se pudo guardar la firma digital.');
  }

  return service_report_signature_relative_dir((int)$tenantCompanyId) . '/' . $name;
}

function service_report_delete_photo_file($relativePath)
{
  $rel = trim((string)$relativePath);
  if ($rel === '') {
    return;
  }

  $root = uploads_root_dir(false);
  if (!is_dir($root)) {
    return;
  }

  $normalized = ltrim(str_replace('\\', '/', $rel), '/');
  $fullPath = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $normalized);
  $realRoot = realpath($root);
  $realPath = realpath($fullPath);
  if ($realRoot === false || $realPath === false) {
    return;
  }

  if (strpos($realPath, $realRoot) !== 0) {
    return;
  }

  if (is_file($realPath)) {
    @unlink($realPath);
  }
}

function tenant_storage_used_mb($tenantCompanyId)
{
  $tenantId = (int)$tenantCompanyId;
  if ($tenantId <= 0) {
    return 0;
  }

  $root = uploads_root_dir(false);
  if (!is_dir($root)) {
    return 0;
  }

  $candidateDirs = [
    $root . DIRECTORY_SEPARATOR . 'empresa_logos' . DIRECTORY_SEPARATOR . $tenantId,
    $root . DIRECTORY_SEPARATOR . 'technician_assets' . DIRECTORY_SEPARATOR . $tenantId,
    $root . DIRECTORY_SEPARATOR . 'service_reports' . DIRECTORY_SEPARATOR . $tenantId,
  ];

  $bytes = 0;
  foreach ($candidateDirs as $dir) {
    if (!is_dir($dir)) {
      continue;
    }
    try {
      $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
      );
      foreach ($iterator as $fileInfo) {
        if ($fileInfo instanceof SplFileInfo && $fileInfo->isFile()) {
          $size = (int)$fileInfo->getSize();
          if ($size > 0) {
            $bytes += $size;
          }
        }
      }
    } catch (Throwable $e) {
      continue;
    }
  }

  if ($bytes <= 0) {
    return 0;
  }
  return (int)max(1, ceil($bytes / 1048576));
}

function service_reports_fallback_file_path($tenantCompanyId, $create = false)
{
  $dir = service_report_absolute_dir((int)$tenantCompanyId, $create);
  return $dir . DIRECTORY_SEPARATOR . 'reports_fallback.json';
}

function service_reports_fallback_load($tenantCompanyId)
{
  $path = service_reports_fallback_file_path((int)$tenantCompanyId, false);
  if (!is_file($path)) {
    return [];
  }
  $raw = @file_get_contents($path);
  if (!is_string($raw) || trim($raw) === '') {
    return [];
  }
  $decoded = json_decode($raw, true);
  if (!is_array($decoded)) {
    return [];
  }
  return array_values(array_filter($decoded, static fn($row) => is_array($row)));
}

function service_reports_fallback_append($tenantCompanyId, array $payload)
{
  $rows = service_reports_fallback_load((int)$tenantCompanyId);
  $rows[] = $payload;
  $path = service_reports_fallback_file_path((int)$tenantCompanyId, true);
  $encoded = json_encode($rows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
  if (!is_string($encoded) || @file_put_contents($path, $encoded) === false) {
    throw new RuntimeException('No se pudo guardar el reporte en almacenamiento alterno.');
  }
}

function service_reports_fallback_find($tenantCompanyId, $reportId)
{
  $targetId = trim((string)$reportId);
  if ($targetId === '') {
    return null;
  }

  $rows = service_reports_fallback_load((int)$tenantCompanyId);
  foreach ($rows as $row) {
    if (!is_array($row)) {
      continue;
    }
    if (trim((string)($row['id'] ?? '')) === $targetId) {
      return $row;
    }
  }
  return null;
}

function service_reports_fallback_update($tenantCompanyId, $reportId, array $payload)
{
  $targetId = trim((string)$reportId);
  if ($targetId === '') {
    return false;
  }

  $rows = service_reports_fallback_load((int)$tenantCompanyId);
  $updated = false;
  foreach ($rows as $idx => $row) {
    if (!is_array($row)) {
      continue;
    }
    if (trim((string)($row['id'] ?? '')) !== $targetId) {
      continue;
    }

    $rows[$idx] = array_merge($row, $payload, ['id' => $targetId]);
    $updated = true;
    break;
  }

  if (!$updated) {
    return false;
  }

  $path = service_reports_fallback_file_path((int)$tenantCompanyId, true);
  $encoded = json_encode($rows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
  if (!is_string($encoded) || @file_put_contents($path, $encoded) === false) {
    throw new RuntimeException('No se pudo actualizar el reporte en almacenamiento alterno.');
  }

  return true;
}

function service_reports_fallback_delete($tenantCompanyId, $reportId)
{
  $targetId = trim((string)$reportId);
  if ($targetId === '') {
    return null;
  }

  $rows = service_reports_fallback_load((int)$tenantCompanyId);
  $deletedRow = null;
  $nextRows = [];

  foreach ($rows as $row) {
    if (!is_array($row)) {
      continue;
    }
    if ($deletedRow === null && trim((string)($row['id'] ?? '')) === $targetId) {
      $deletedRow = $row;
      continue;
    }
    $nextRows[] = $row;
  }

  if ($deletedRow === null) {
    return null;
  }

  $path = service_reports_fallback_file_path((int)$tenantCompanyId, true);
  $encoded = json_encode($nextRows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
  if (!is_string($encoded) || @file_put_contents($path, $encoded) === false) {
    throw new RuntimeException('No se pudo eliminar el reporte en almacenamiento alterno.');
  }

  return $deletedRow;
}

function report_text_to_items($raw)
{
  $text = trim((string)$raw);
  if ($text === '') {
    return [];
  }

  $lines = preg_split('/\r\n|\r|\n/', $text) ?: [];
  $items = [];
  foreach ($lines as $line) {
    $clean = trim((string)$line);
    if ($clean === '') {
      continue;
    }
    $clean = preg_replace('/^[-*•\x{2022}\s]+/u', '', $clean);
    $clean = trim((string)$clean);
    if ($clean !== '') {
      $items[] = $clean;
    }
  }

  if (empty($items) && $text !== '') {
    $items[] = $text;
  }
  return $items;
}

function report_items_to_html($raw)
{
  $items = report_text_to_items($raw);
  if (empty($items)) {
    return '<span class="muted">-</span>';
  }

  $html = '<ul class="report-bulleted-list">';
  foreach ($items as $item) {
    $html .= '<li>' . h((string)$item) . '</li>';
  }
  $html .= '</ul>';
  return $html;
}

function service_form_field_key($label, $fallback = 'campo')
{
  $base = strtolower(trim((string)$label));
  $base = preg_replace('/[^a-z0-9]+/', '_', $base);
  $base = trim((string)$base, '_');
  if ($base === '') {
    $base = strtolower(trim((string)$fallback));
    $base = preg_replace('/[^a-z0-9]+/', '_', $base);
    $base = trim((string)$base, '_');
  }
  if ($base === '') {
    $base = 'campo';
  }
  return substr($base, 0, 60);
}

function service_form_template_fields_normalize($raw)
{
  if (is_string($raw)) {
    $decoded = json_decode($raw, true);
    if (is_array($decoded)) {
      $raw = $decoded;
    }
  }
  if (!is_array($raw)) {
    return [];
  }

  $allowedTypes = ['text_check', 'semaforo', 'texto_corto', 'texto_largo', 'imagenes'];
  $out = [];
  $usedKeys = [];

  foreach ($raw as $idx => $row) {
    if (!is_array($row)) {
      continue;
    }
    $label = trim((string)($row['label'] ?? ''));
    if ($label === '') {
      continue;
    }
    $type = strtolower(trim((string)($row['type'] ?? 'texto_corto')));
    if (!in_array($type, $allowedTypes, true)) {
      $type = 'texto_corto';
    }
    $required = ((string)($row['required'] ?? '0') === '1');
    $baseKey = service_form_field_key((string)($row['key'] ?? ''), 'campo_' . ($idx + 1));
    $key = $baseKey;
    $suffix = 1;
    while (isset($usedKeys[$key])) {
      $suffix += 1;
      $key = substr($baseKey, 0, 55) . '_' . $suffix;
    }
    $usedKeys[$key] = true;

    $normalized = [
      'key' => $key,
      'label' => $label,
      'type' => $type,
      'required' => $required ? 1 : 0,
      'check_label' => trim((string)($row['check_label'] ?? 'Conforme')),
      'semaforo_green' => trim((string)($row['semaforo_green'] ?? 'Correcto')),
      'semaforo_yellow' => trim((string)($row['semaforo_yellow'] ?? 'Advertencia')),
      'semaforo_red' => trim((string)($row['semaforo_red'] ?? 'Critico')),
    ];
    $out[] = $normalized;
  }

  return $out;
}

function service_form_response_payload_normalize($raw)
{
  if (is_string($raw)) {
    $decoded = json_decode($raw, true);
    if (is_array($decoded)) {
      $raw = $decoded;
    }
  }
  return is_array($raw) ? $raw : [];
}

function service_form_default_answer_from_field($field)
{
  $fieldType = strtolower(trim((string)($field['type'] ?? 'texto_corto')));
  if ($fieldType === '') {
    $fieldType = 'texto_corto';
  }

  return [
    'key' => trim((string)($field['key'] ?? '')),
    'label' => trim((string)($field['label'] ?? '')),
    'type' => $fieldType,
    'text' => '',
    'checked' => '0',
    'status' => '',
  ];
}

function service_form_effective_payload_for_service_order($rawPayload, $serviceOrderId, $templatesCatalogByServiceOrder)
{
  $payloadRows = service_form_response_payload_normalize($rawPayload);
  $soId = (int)$serviceOrderId;
  if ($soId <= 0 || !is_array($templatesCatalogByServiceOrder)) {
    return $payloadRows;
  }

  $assignedTemplates = $templatesCatalogByServiceOrder[$soId] ?? [];
  if (!is_array($assignedTemplates) || empty($assignedTemplates)) {
    return $payloadRows;
  }

  $payloadByTemplateId = [];
  foreach ($payloadRows as $row) {
    if (!is_array($row)) {
      continue;
    }
    $tplId = (int)($row['template_id'] ?? 0);
    if ($tplId > 0) {
      $payloadByTemplateId[$tplId] = $row;
    }
  }

  $result = [];
  $processedTemplateIds = [];

  foreach ($assignedTemplates as $tplRow) {
    if (!is_array($tplRow)) {
      continue;
    }
    $tplId = (int)($tplRow['id'] ?? 0);
    if ($tplId <= 0) {
      continue;
    }

    $fields = service_form_template_fields_normalize($tplRow['fields'] ?? []);
    $currentRow = $payloadByTemplateId[$tplId] ?? ['template_id' => $tplId, 'answers' => []];
    $currentAnswers = is_array($currentRow['answers'] ?? null) ? $currentRow['answers'] : [];
    $answersByKey = [];
    foreach ($currentAnswers as $ansRow) {
      if (!is_array($ansRow)) {
        continue;
      }
      $ansKey = trim((string)($ansRow['key'] ?? ''));
      if ($ansKey === '') {
        continue;
      }
      $answersByKey[$ansKey] = $ansRow;
    }

    $mergedAnswers = [];
    $usedKeys = [];
    foreach ($fields as $field) {
      $fieldKey = trim((string)($field['key'] ?? ''));
      if ($fieldKey === '') {
        continue;
      }
      $usedKeys[$fieldKey] = true;
      if (isset($answersByKey[$fieldKey]) && is_array($answersByKey[$fieldKey])) {
        $currentAnswer = $answersByKey[$fieldKey];
        if (!isset($currentAnswer['label']) || trim((string)$currentAnswer['label']) === '') {
          $currentAnswer['label'] = trim((string)($field['label'] ?? $fieldKey));
        }
        if (!isset($currentAnswer['type']) || trim((string)$currentAnswer['type']) === '') {
          $currentAnswer['type'] = trim((string)($field['type'] ?? 'texto_corto'));
        }
        $mergedAnswers[] = $currentAnswer;
      } else {
        $mergedAnswers[] = service_form_default_answer_from_field($field);
      }
    }

    foreach ($currentAnswers as $ansRow) {
      if (!is_array($ansRow)) {
        continue;
      }
      $ansKey = trim((string)($ansRow['key'] ?? ''));
      if ($ansKey !== '' && isset($usedKeys[$ansKey])) {
        continue;
      }
      $mergedAnswers[] = $ansRow;
    }

    $currentRow['template_id'] = $tplId;
    if (!isset($currentRow['template_name']) || trim((string)$currentRow['template_name']) === '') {
      $currentRow['template_name'] = trim((string)($tplRow['name'] ?? ('Plantilla #' . $tplId)));
    }
    $currentRow['answers'] = $mergedAnswers;
    $result[] = $currentRow;
    $processedTemplateIds[$tplId] = true;
  }

  foreach ($payloadRows as $row) {
    if (!is_array($row)) {
      continue;
    }
    $tplId = (int)($row['template_id'] ?? 0);
    if ($tplId > 0 && isset($processedTemplateIds[$tplId])) {
      continue;
    }
    $result[] = $row;
  }

  return $result;
}

function service_report_signature_encode($name, $rut)
{
  $payload = [
    'name' => trim((string)$name),
    'rut' => trim((string)$rut),
  ];
  $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  return is_string($json) ? $json : '';
}

function service_report_signature_decode($raw)
{
  $text = trim((string)$raw);
  if ($text === '') {
    return ['name' => '', 'rut' => ''];
  }

  $decoded = json_decode($text, true);
  if (is_array($decoded)) {
    return [
      'name' => trim((string)($decoded['name'] ?? '')),
      'rut' => trim((string)($decoded['rut'] ?? '')),
    ];
  }

  if (preg_match('/^(.*?)\s*\|\s*RUT\s*:\s*(.*)$/i', $text, $m)) {
    return [
      'name' => trim((string)($m[1] ?? '')),
      'rut' => trim((string)($m[2] ?? '')),
    ];
  }

  return ['name' => $text, 'rut' => ''];
}

function service_report_signature_pretty($raw)
{
  $sig = service_report_signature_decode($raw);
  $name = trim((string)($sig['name'] ?? ''));
  $rut = trim((string)($sig['rut'] ?? ''));

  if ($name === '' && $rut === '') {
    return '';
  }
  if ($name !== '' && $rut !== '') {
    return $name . ' (RUT: ' . $rut . ')';
  }
  return ($name !== '' ? $name : ('RUT: ' . $rut));
}

function technician_asset_types()
{
  return ['epp', 'cargo', 'herramientas'];
}

function technician_asset_type_normalize($type)
{
  $normalized = strtolower(trim((string)$type));
  return in_array($normalized, technician_asset_types(), true) ? $normalized : 'epp';
}

function technician_asset_state_normalize($state)
{
  $normalized = strtolower(trim((string)$state));
  return in_array($normalized, ['nuevo', 'usado'], true) ? $normalized : 'nuevo';
}

function technician_assets_empty_payload()
{
  return [
    'epp' => [],
    'cargo' => [],
    'herramientas' => [],
  ];
}

function technician_assets_directory($tenantCompanyId, $create = false)
{
  $root = uploads_root_dir($create);
  $dir = $root . DIRECTORY_SEPARATOR . 'technician_assets' . DIRECTORY_SEPARATOR . (int)$tenantCompanyId;
  if ($create && !is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
    throw new RuntimeException('No se pudo crear directorio de gestion tecnica.');
  }
  return $dir;
}

function technician_assets_file_path($tenantCompanyId, $technicianId, $create = false)
{
  $dir = technician_assets_directory((int)$tenantCompanyId, $create);
  return $dir . DIRECTORY_SEPARATOR . 'tech_' . (int)$technicianId . '.json';
}

function technician_assets_payload_normalize($payload)
{
  $base = technician_assets_empty_payload();
  if (!is_array($payload)) {
    return $base;
  }

  foreach (technician_asset_types() as $type) {
    $items = $payload[$type] ?? [];
    if (!is_array($items)) {
      continue;
    }

    foreach ($items as $item) {
      if (!is_array($item)) {
        continue;
      }
      $deliveryDate = trim((string)($item['fecha_entrega'] ?? ''));
      if ($deliveryDate === '' || strtotime($deliveryDate) === false) {
        continue;
      }

      $expirationDate = trim((string)($item['fecha_vencimiento'] ?? ''));
      if ($type !== 'epp') {
        $expirationDate = '';
      } elseif ($expirationDate !== '' && strtotime($expirationDate) === false) {
        $expirationDate = '';
      }

      $state = '';
      if ($type !== 'epp') {
        $state = technician_asset_state_normalize((string)($item['estado'] ?? 'nuevo'));
      }

      $id = trim((string)($item['id'] ?? ''));
      if ($id === '') {
        $id = bin2hex(random_bytes(6));
      }

      $base[$type][] = [
        'id' => $id,
        'descripcion' => trim((string)($item['descripcion'] ?? '')),
        'fecha_entrega' => $deliveryDate,
        'fecha_vencimiento' => $expirationDate,
        'estado' => $state,
        'creado_en' => trim((string)($item['creado_en'] ?? date('Y-m-d H:i:s'))),
      ];
    }
  }

  return $base;
}

function technician_assets_load($tenantCompanyId, $technicianId)
{
  $path = technician_assets_file_path((int)$tenantCompanyId, (int)$technicianId, false);
  if (!is_file($path)) {
    return technician_assets_empty_payload();
  }

  $raw = @file_get_contents($path);
  if ($raw === false || trim($raw) === '') {
    return technician_assets_empty_payload();
  }

  $decoded = json_decode($raw, true);
  return technician_assets_payload_normalize($decoded);
}

function technician_assets_save($tenantCompanyId, $technicianId, $payload)
{
  $normalized = technician_assets_payload_normalize($payload);
  $path = technician_assets_file_path((int)$tenantCompanyId, (int)$technicianId, true);
  $json = json_encode($normalized, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  if (!is_string($json) || @file_put_contents($path, $json, LOCK_EX) === false) {
    throw new RuntimeException('No se pudo guardar la gestion del tecnico.');
  }
}

function technician_assets_counts($payload)
{
  $normalized = technician_assets_payload_normalize($payload);
  return [
    'epp' => count((array)$normalized['epp']),
    'cargo' => count((array)$normalized['cargo']),
    'herramientas' => count((array)$normalized['herramientas']),
  ];
}

function inventory_number_from_input($value)
{
  $raw = trim((string)$value);
  if ($raw === '') {
    return 0.0;
  }
  $normalized = str_replace([' ', ','], ['', '.'], $raw);
  if (!is_numeric($normalized)) {
    return 0.0;
  }
  return (float)$normalized;
}

function inventory_type_normalize($type)
{
  $value = strtolower(trim((string)$type));
  return in_array($value, ['entrada', 'salida', 'ajuste'], true) ? $value : 'entrada';
}

function inventory_state_normalize($state)
{
  $value = strtolower(trim((string)$state));
  return in_array($value, ['activo', 'inactivo'], true) ? $value : 'activo';
}

function fetch_company_inventory_items(PDO $pdo, $tenantCompanyId)
{
  $st = $pdo->prepare(
    'SELECT id, sku, nombre, descripcion, unidad, stock_actual, stock_minimo, stock_critico, costo_unitario, estado, created_at, updated_at
       FROM tenant_inventory_items
      WHERE tenant_company_id = :tenant_company_id
        AND deleted_at IS NULL
      ORDER BY nombre ASC, id DESC'
  );
  $st->execute(['tenant_company_id' => (int)$tenantCompanyId]);
  return $st->fetchAll();
}

function fetch_company_inventory_movements(PDO $pdo, $tenantCompanyId, $limit = 200)
{
  $rowsLimit = max(1, min(500, (int)$limit));
  $st = $pdo->prepare(
    'SELECT m.id, m.item_id, m.item_sku, m.item_nombre, m.item_unidad, m.tipo, m.cantidad, m.motivo,
            m.stock_anterior, m.stock_nuevo, m.created_by, m.created_at,
            i.sku AS current_sku, i.nombre AS current_nombre, i.unidad AS current_unidad
       FROM tenant_inventory_movements m
       LEFT JOIN tenant_inventory_items i
         ON i.id = m.item_id
        AND i.tenant_company_id = m.tenant_company_id
      WHERE m.tenant_company_id = :tenant_company_id
      ORDER BY m.id DESC
      LIMIT :rows_limit'
  );
  $st->bindValue(':tenant_company_id', (int)$tenantCompanyId, PDO::PARAM_INT);
  $st->bindValue(':rows_limit', $rowsLimit, PDO::PARAM_INT);
  $st->execute();
  return $st->fetchAll();
}

function fetch_company_technicians(PDO $pdo, $tenantCompanyId)
{
  $stTechnicians = $pdo->prepare(
    'SELECT id, full_name, specialty, email, phone, is_active, created_at
       FROM tenant_technicians
      WHERE company_id = :company_id
      ORDER BY full_name ASC, id DESC'
  );
  $stTechnicians->execute(['company_id' => (int)$tenantCompanyId]);
  $technicianRows = $stTechnicians->fetchAll();

  $technicians = [];
  foreach ($technicianRows as $techRow) {
    $fullName = trim((string)($techRow['full_name'] ?? ''));
    $nameParts = preg_split('/\s+/', $fullName, 2);
    $meta = technician_meta_decode((string)($techRow['phone'] ?? ''));
    $status = strtolower(trim((string)$meta['estado']));
    if (!in_array($status, ['activo', 'inactivo'], true)) {
      $status = ((int)($techRow['is_active'] ?? 0) === 1) ? 'activo' : 'inactivo';
    }
    $joinDate = trim((string)$meta['fecha_ingreso']);
    if ($joinDate === '' || strtotime($joinDate) === false) {
      $createdAt = strtotime((string)($techRow['created_at'] ?? ''));
      $joinDate = ($createdAt !== false ? date('Y-m-d', $createdAt) : date('Y-m-d'));
    }

    $technicians[] = [
      'id' => (int)($techRow['id'] ?? 0),
      'nombre' => trim((string)($nameParts[0] ?? '')),
      'apellido' => trim((string)($nameParts[1] ?? '')),
      'cargo' => trim((string)($techRow['specialty'] ?? '')),
      'cuenta' => trim((string)($techRow['email'] ?? '')),
      'fecha_ingreso' => $joinDate,
      'estado' => $status,
      'habilidades' => technician_skills_normalize((array)($meta['habilidades'] ?? [])),
      'asset_records' => technician_assets_load((int)$tenantCompanyId, (int)($techRow['id'] ?? 0)),
    ];
  }

  return $technicians;
}

function technician_skills_catalog()
{
  return [
    'Electrico',
    'Mecanico',
    'Hidraulica',
    'Neumatica',
    'Soldador',
    'Automata',
    'Programador',
    'Intrumentista',
    'Electronica industrial',
    'PLC/SCADA',
    'Refrigeracion industrial',
    'Caldereria',
    'Metrologia',
    'Mantenimiento predictivo',
  ];
}

function technician_skills_normalize($skills)
{
  $catalog = technician_skills_catalog();
  if (!is_array($skills) || empty($skills)) {
    return [];
  }

  $selected = [];
  foreach ($skills as $skill) {
    $value = trim((string)$skill);
    if ($value !== '') {
      $selected[$value] = true;
    }
  }

  $result = [];
  foreach ($catalog as $skill) {
    if (isset($selected[$skill])) {
      $result[] = $skill;
    }
  }
  return $result;
}

function technician_skills_mask_from_list($skills)
{
  $selected = technician_skills_normalize($skills);
  if (empty($selected)) {
    return '0';
  }

  $catalog = technician_skills_catalog();
  $mask = 0;
  foreach ($catalog as $idx => $skill) {
    if (in_array($skill, $selected, true)) {
      $mask |= (1 << $idx);
    }
  }
  return strtoupper(dechex($mask));
}

function technician_skills_list_from_mask($maskHex)
{
  $maskHex = trim((string)$maskHex);
  if ($maskHex === '' || !preg_match('/^[0-9A-Fa-f]+$/', $maskHex)) {
    return [];
  }

  $mask = hexdec($maskHex);
  $catalog = technician_skills_catalog();
  $skills = [];
  foreach ($catalog as $idx => $skill) {
    if (($mask & (1 << $idx)) !== 0) {
      $skills[] = $skill;
    }
  }
  return $skills;
}

  function technician_meta_encode($fechaIngreso, $estado, $habilidades = [])
  {
    $date = trim((string)$fechaIngreso);
    if ($date === '' || strtotime($date) === false) {
      $date = date('Y-m-d');
    }
    $state = (strtolower(trim((string)$estado)) === 'inactivo') ? 'i' : 'a';
    $skillsMask = technician_skills_mask_from_list($habilidades);
    return $date . '|' . $state . '|' . $skillsMask;
  }

  function technician_meta_decode($rawPhone)
  {
    $raw = (string)$rawPhone;
    if ($raw === '') {
      return ['fecha_ingreso' => '', 'estado' => '', 'habilidades' => []];
    }

    // Formato compacto: YYYY-MM-DD|a(i)|MASKHEX
    if (preg_match('/^(\d{4}-\d{2}-\d{2})\|([ai])(?:\|([0-9A-Fa-f]+))?$/', $raw, $m)) {
      return [
        'fecha_ingreso' => (string)$m[1],
        'estado' => ((string)$m[2] === 'i' ? 'inactivo' : 'activo'),
        'habilidades' => technician_skills_list_from_mask((string)($m[3] ?? '0')),
      ];
    }

    // Compatibilidad hacia atras con formato legacy __TECH_META__<base64json>
    if (str_starts_with($raw, '__TECH_META__')) {
      $encoded = substr($raw, strlen('__TECH_META__'));
      $json = base64_decode($encoded, true);
      if ($json === false || $json === '') {
        return ['fecha_ingreso' => '', 'estado' => '', 'habilidades' => []];
      }
      $meta = json_decode($json, true);
      if (!is_array($meta)) {
        return ['fecha_ingreso' => '', 'estado' => '', 'habilidades' => []];
      }

      return [
        'fecha_ingreso' => (string)($meta['fecha_ingreso'] ?? ''),
        'estado' => (string)($meta['estado'] ?? ''),
        'habilidades' => technician_skills_normalize((array)($meta['habilidades'] ?? [])),
      ];
    }

    return ['fecha_ingreso' => '', 'estado' => '', 'habilidades' => []];
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

  function logo_data_uri($relativePath)
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

    $root = rtrim(str_replace('\\', '/', uploads_root_dir(false)), '/');
    $abs = $root . '/' . ltrim($rel, '/');
    if (!str_starts_with($abs, $root . '/')) {
      return '';
    }
    if (!is_file($abs)) {
      return '';
    }

    $bin = @file_get_contents($abs);
    if ($bin === false || $bin === '') {
      return '';
    }

    $mime = 'image/png';
    try {
      $finfo = new finfo(FILEINFO_MIME_TYPE);
      $detected = (string)$finfo->file($abs);
      if ($detected !== '') {
        $mime = $detected;
      }
    } catch (Throwable $e) {
    }

    return 'data:' . $mime . ';base64,' . base64_encode($bin);
  }

  function dashboard_module_url($module)
  {
    $safe = in_array($module, ['dashboard', 'plan', 'empresa', 'clientes', 'cotizaciones', 'papelera', 'configuracion', 'inventario', 'ordenes-servicio', 'reportes', 'formularios', 'tecnicos', 'carta-gantt'], true) ? $module : 'dashboard';
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

  function plan_display_name($planCode)
  {
    $code = normalize_plan_code((string)$planCode, 'basico');
    if ($code === 'pro') {
      return 'Heroe';
    }
    if ($code === 'enterprise') {
      return 'Semidios';
    }
    if ($code === 'olimpico') {
      return 'Olimpico';
    }
    return 'Mortal';
  }

  function normalize_plan_code($planCode, $fallback = 'basico')
  {
    $code = strtolower(trim((string)$planCode));
    if (in_array($code, ['heroe', 'pro'], true)) {
      return 'pro';
    }
    if (in_array($code, ['semidios', 'semi_dios', 'enterprise'], true)) {
      return 'enterprise';
    }
    if (in_array($code, ['olimpico'], true)) {
      return 'olimpico';
    }
    if (in_array($code, ['mortal', 'basic', 'basico'], true)) {
      return 'basico';
    }
    return (string)$fallback;
  }

  function plan_storage_limit_mb($planCode)
  {
    $code = normalize_plan_code((string)$planCode, 'basico');
    if ($code === 'basico') {
      return 100;
    }
    return 1024;
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
$sessionSignupId = (int)($_SESSION['hermes_company_id'] ?? 0);
$signupId = $sessionSignupId;
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
  'storage_limit_mb' => 100,
    'storage_used_mb' => 0,
    'percent' => 0,
];

$customers = [];
$technicians = [];
$inventoryItems = [];
$inventoryMovements = [];
$quotes = [];
$trashCustomers = [];
$trashQuotes = [];
$trashInventoryItems = [];
$serviceOrders = [];
$trashServiceOrders = [];
$trashServiceReports = [];
$serviceOrderAssignmentsByOrder = [];
$serviceOrderPartsByOrder = [];
$serviceOrderChecklistByOrder = [];
$serviceOrderFormTemplatesByOrder = [];
$serviceReports = [];
$serviceOrderOptionsByTechnician = [];
$formTemplates = [];
$reportFormTemplatesCatalogByServiceOrder = [];
$paymentHistoryRows = [];
$paymentHistoryAvailable = false;
$accountSettings = [
  'email' => '',
  'company_name' => '',
  'contact_name' => '',
  'phone' => '',
  'created_at' => '',
];
$quoteItemsByQuote = [];
$quotePreview = null;
$quotePreviewItems = [];
$serviceOrderPreview = null;
$serviceOrderPreviewAssignments = [];
$serviceOrderPreviewParts = [];
$serviceOrderPreviewChecklist = [];
$serviceOrderPreviewReportsByTechnician = [];
$serviceOrderPreviewFormTemplates = [];
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
  'payment_token' => '',
  'can_pay_renewal' => false,
];
$planUpgradeLinks = [
  'basico' => '',
  'pro' => '',
  'enterprise' => '',
];
$openCustomerModal = false;
$openTechnicianModal = false;
$openTechnicianAssetModal = false;
$openInventoryModal = false;
$openInventoryMoveModal = false;
$openQuoteModal = false;
$openQuoteEmailModal = false;
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
$technicianForm = [
  'id' => '',
  'nombre' => '',
  'apellido' => '',
  'cargo' => '',
  'cuenta' => '',
  'fecha_ingreso' => date('Y-m-d'),
  'estado' => 'activo',
  'habilidades' => [],
];
$technicianAssetForm = [
  'technician_id' => '',
  'technician_nombre' => '',
  'asset_type' => 'epp',
  'descripcion' => '',
  'fecha_entrega' => date('Y-m-d'),
  'fecha_vencimiento' => '',
  'estado' => 'nuevo',
];
$technicianAssetRecords = technician_assets_empty_payload();

$inventoryForm = [
  'id' => '',
  'sku' => '',
  'nombre' => '',
  'descripcion' => '',
  'unidad' => 'unidad',
  'stock_actual' => '0',
  'stock_minimo' => '0',
  'stock_critico' => '0',
  'costo_unitario' => '0',
  'estado' => 'activo',
];
$inventoryMoveForm = [
  'item_id' => '',
  'tipo' => 'entrada',
  'cantidad' => '1',
  'motivo' => '',
];

$serviceOrderForm = [
  'id' => '',
  'customer_id' => '',
  'codigo' => '',
  'titulo' => '',
  'descripcion' => '',
  'estado' => 'borrador',
  'prioridad' => 'normal',
  'fecha_creacion' => date('Y-m-d'),
  'observaciones' => '',
  'assignments' => [
    ['technician_id' => '', 'work_date' => '', 'start_time' => '', 'end_time' => '', 'notas' => ''],
  ],
  'parts' => [
    ['inventory_item_id' => '', 'sku' => '', 'nombre' => '', 'unidad' => 'unidad', 'cantidad' => '1', 'notas' => ''],
  ],
  'checklist' => [
    ['descripcion' => '', 'completado' => '0'],
  ],
  'form_template_ids' => [],
];
$openServiceOrderModal = false;
$openServiceReportModal = false;
$serviceReportForm = [
  'report_id' => '',
  'service_order_id' => '',
  'technician_id' => '',
  'report_date' => date('Y-m-d'),
  'work_done' => '',
  'external_purchases' => '',
  'observations' => '',
  'additional_details' => '',
  'technician_sign_name' => '',
  'technician_sign_rut' => '',
  'customer_sign_name' => '',
  'customer_sign_rut' => '',
  'technician_signature_draw' => '',
  'customer_signature_draw' => '',
  'forms_payload_json' => '[]',
  'technician_signature' => '',
  'customer_signature' => '',
  'forms_note' => '',
];

$technicianSkillCatalog = technician_skills_catalog();
$quoteForm = [
  'id' => '',
    'customer_id' => '',
    'numero_cotizacion' => '',
    'fecha_emision' => date('Y-m-d'),
    'validez_dias' => '15',
  'estado' => 'Pendiente',
    'descuento_pct' => '0',
  'validez_override' => '',
  'entrega_override' => '',
  'condicion_de_pago_override' => '',
  'moneda_override' => '',
  'terminos_condiciones_adicionales' => '',
    'observaciones' => '',
    'items' => [
      ['descripcion' => '', 'cantidad' => '1', 'precio' => '0', 'tipo' => 'normal', 'negrita' => '0'],
    ],
];
$quoteEmailForm = [
  'quote_id' => '',
  'to' => '',
  'cc' => '',
  'subject' => '',
  'message' => "Te compartimos la cotizacion solicitada.\n\nQuedo atento a tus comentarios.",
  'include_quote_attachment' => '1',
];

  if ($_SERVER['REQUEST_METHOD'] !== 'POST' && isset($_SESSION['hermes_company_postback']) && is_array($_SESSION['hermes_company_postback'])) {
    $postback = $_SESSION['hermes_company_postback'];
    unset($_SESSION['hermes_company_postback']);

    if (isset($postback['module']) && in_array((string)$postback['module'], ['dashboard', 'plan', 'empresa', 'clientes', 'cotizaciones', 'papelera', 'configuracion', 'inventario', 'ordenes-servicio', 'reportes', 'formularios', 'tecnicos', 'carta-gantt'], true)) {
      $module = (string)$postback['module'];
    }
    if (isset($postback['flash']) && is_array($postback['flash'])) {
      $flash['ok'] = (string)($postback['flash']['ok'] ?? '');
      $flash['error'] = (string)($postback['flash']['error'] ?? '');
    }
    $openCustomerModal = !empty($postback['openCustomerModal']);
    $openTechnicianModal = !empty($postback['openTechnicianModal']);
    $openTechnicianAssetModal = !empty($postback['openTechnicianAssetModal']);
    $openInventoryModal = !empty($postback['openInventoryModal']);
    $openInventoryMoveModal = !empty($postback['openInventoryMoveModal']);
    $openServiceOrderModal = !empty($postback['openServiceOrderModal']);
    $openServiceReportModal = !empty($postback['openServiceReportModal']);
    if (isset($postback['serviceOrderForm']) && is_array($postback['serviceOrderForm'])) {
      $serviceOrderForm = array_merge($serviceOrderForm, $postback['serviceOrderForm']);
    }
    if (isset($postback['serviceReportForm']) && is_array($postback['serviceReportForm'])) {
      $serviceReportForm = array_merge($serviceReportForm, $postback['serviceReportForm']);
    }
    $openQuoteModal = !empty($postback['openQuoteModal']);
    $openQuoteEmailModal = !empty($postback['openQuoteEmailModal']);

    if (isset($postback['customerForm']) && is_array($postback['customerForm'])) {
      $customerForm = array_merge($customerForm, $postback['customerForm']);
    }
    if (isset($postback['technicianForm']) && is_array($postback['technicianForm'])) {
      $technicianForm = array_merge($technicianForm, $postback['technicianForm']);
      if (!isset($technicianForm['habilidades']) || !is_array($technicianForm['habilidades'])) {
        $technicianForm['habilidades'] = [];
      }
      $technicianForm['habilidades'] = technician_skills_normalize($technicianForm['habilidades']);
    }
    if (isset($postback['technicianAssetForm']) && is_array($postback['technicianAssetForm'])) {
      $technicianAssetForm = array_merge($technicianAssetForm, $postback['technicianAssetForm']);
      $technicianAssetForm['asset_type'] = technician_asset_type_normalize((string)($technicianAssetForm['asset_type'] ?? 'epp'));
      $technicianAssetForm['estado'] = technician_asset_state_normalize((string)($technicianAssetForm['estado'] ?? 'nuevo'));
    }
    if (isset($postback['technicianAssetRecords']) && is_array($postback['technicianAssetRecords'])) {
      $technicianAssetRecords = technician_assets_payload_normalize($postback['technicianAssetRecords']);
    }
    if (isset($postback['inventoryForm']) && is_array($postback['inventoryForm'])) {
      $inventoryForm = array_merge($inventoryForm, $postback['inventoryForm']);
      $inventoryForm['estado'] = inventory_state_normalize((string)($inventoryForm['estado'] ?? 'activo'));
    }
    if (isset($postback['inventoryMoveForm']) && is_array($postback['inventoryMoveForm'])) {
      $inventoryMoveForm = array_merge($inventoryMoveForm, $postback['inventoryMoveForm']);
      $inventoryMoveForm['tipo'] = inventory_type_normalize((string)($inventoryMoveForm['tipo'] ?? 'entrada'));
    }
    if (isset($postback['quoteForm']) && is_array($postback['quoteForm'])) {
      $quoteForm = array_merge($quoteForm, $postback['quoteForm']);
      if (isset($postback['quoteForm']['items']) && is_array($postback['quoteForm']['items'])) {
        $quoteForm['items'] = $postback['quoteForm']['items'];
      }
    }
    if (isset($postback['quoteEmailForm']) && is_array($postback['quoteEmailForm'])) {
      $quoteEmailForm = array_merge($quoteEmailForm, $postback['quoteEmailForm']);
    }
  }

try {
    $cfg = require __DIR__ . '/.db_credentials.php';
    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $cfg['host'], (int)$cfg['port'], $cfg['dbname'], $cfg['charset']);
    $pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    security_ensure_tables($pdo);

    if (!table_exists($pdo, 'account_signups')) {
      $pdo->exec('CREATE TABLE account_signups (
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
    }

    if (!table_exists($pdo, 'tenant_companies')) {
      $pdo->exec('CREATE TABLE tenant_companies (
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
    }

    if (column_exists($pdo, 'tenant_companies', 'business_email') && column_exists($pdo, 'tenant_companies', 'owner_email')) {
        try {
            $pdo->exec('ALTER TABLE tenant_companies MODIFY business_email VARCHAR(190) NULL');
        } catch (Throwable $ignored) {
        }
        $pdo->exec('UPDATE tenant_companies SET business_email = owner_email WHERE (business_email IS NULL OR business_email = "") AND owner_email IS NOT NULL AND owner_email <> ""');
    }

    if (!table_exists($pdo, 'tenant_company_profiles')) {
      $pdo->exec('CREATE TABLE tenant_company_profiles (
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
    }

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

    if (!table_exists($pdo, 'tenant_customers')) {
      $pdo->exec('CREATE TABLE tenant_customers (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        tenant_company_id BIGINT UNSIGNED NOT NULL,
      company_id BIGINT UNSIGNED NULL,
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
    }

    ensure_column($pdo, 'tenant_customers', 'tenant_company_id', 'BIGINT UNSIGNED NOT NULL');
  ensure_column($pdo, 'tenant_customers', 'company_id', 'BIGINT UNSIGNED NULL');
    ensure_column($pdo, 'tenant_customers', 'customer_name', 'VARCHAR(190) NULL');
    ensure_column($pdo, 'tenant_customers', 'contact_name', 'VARCHAR(190) NULL');
    ensure_column($pdo, 'tenant_customers', 'contact_email', 'VARCHAR(190) NULL');
    ensure_column($pdo, 'tenant_customers', 'phone', 'VARCHAR(40) NULL');
    ensure_column($pdo, 'tenant_customers', 'is_active', 'TINYINT(1) NOT NULL DEFAULT 1');
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
    ensure_column($pdo, 'tenant_customers', 'deleted_at', 'DATETIME NULL');
    ensure_column($pdo, 'tenant_customers', 'deleted_by', 'VARCHAR(190) NULL');

    if (!table_exists($pdo, 'tenant_technicians')) {
      $pdo->exec('CREATE TABLE tenant_technicians (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        tenant_company_id BIGINT UNSIGNED NOT NULL,
        company_id BIGINT UNSIGNED NULL,
        full_name VARCHAR(190) NOT NULL,
        specialty VARCHAR(190) NULL,
        email VARCHAR(190) NULL,
        phone VARCHAR(60) NULL,
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        KEY idx_tenant_technicians_tenant (tenant_company_id),
        KEY idx_tenant_technicians_active (tenant_company_id, is_active)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    }

    ensure_column_best_effort($pdo, 'tenant_technicians', 'tenant_company_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column_best_effort($pdo, 'tenant_technicians', 'company_id', 'BIGINT UNSIGNED NULL');
    ensure_column_best_effort($pdo, 'tenant_technicians', 'full_name', 'VARCHAR(190) NOT NULL DEFAULT ""');
    ensure_column_best_effort($pdo, 'tenant_technicians', 'specialty', 'VARCHAR(190) NULL');
    ensure_column_best_effort($pdo, 'tenant_technicians', 'email', 'VARCHAR(190) NULL');
    ensure_column_best_effort($pdo, 'tenant_technicians', 'phone', 'VARCHAR(60) NULL');
    ensure_column_best_effort($pdo, 'tenant_technicians', 'is_active', 'TINYINT(1) NOT NULL DEFAULT 1');

    try {
    if (!table_exists($pdo, 'tenant_inventory_items')) {
      $pdo->exec('CREATE TABLE tenant_inventory_items (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        tenant_company_id BIGINT UNSIGNED NOT NULL,
        sku VARCHAR(90) NOT NULL,
        nombre VARCHAR(190) NOT NULL,
        descripcion TEXT NULL,
        unidad VARCHAR(40) NOT NULL DEFAULT "unidad",
        stock_actual DECIMAL(14,2) NOT NULL DEFAULT 0,
        stock_minimo DECIMAL(14,2) NOT NULL DEFAULT 0,
        stock_critico DECIMAL(14,2) NOT NULL DEFAULT 0,
        costo_unitario DECIMAL(14,2) NOT NULL DEFAULT 0,
        estado VARCHAR(20) NOT NULL DEFAULT "activo",
        deleted_at DATETIME NULL,
        deleted_by VARCHAR(190) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_tenant_inventory_sku (tenant_company_id, sku),
        KEY idx_tenant_inventory_lookup (tenant_company_id, estado, deleted_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    }

    ensure_column($pdo, 'tenant_inventory_items', 'tenant_company_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column($pdo, 'tenant_inventory_items', 'sku', 'VARCHAR(90) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_inventory_items', 'nombre', 'VARCHAR(190) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_inventory_items', 'descripcion', 'TEXT NULL');
    ensure_column($pdo, 'tenant_inventory_items', 'unidad', 'VARCHAR(40) NOT NULL DEFAULT "unidad"');
    ensure_column($pdo, 'tenant_inventory_items', 'stock_actual', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_inventory_items', 'stock_minimo', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_inventory_items', 'stock_critico', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_inventory_items', 'costo_unitario', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_inventory_items', 'estado', 'VARCHAR(20) NOT NULL DEFAULT "activo"');
    ensure_column($pdo, 'tenant_inventory_items', 'deleted_at', 'DATETIME NULL');
    ensure_column($pdo, 'tenant_inventory_items', 'deleted_by', 'VARCHAR(190) NULL');

    if (!table_exists($pdo, 'tenant_inventory_movements')) {
      $pdo->exec('CREATE TABLE tenant_inventory_movements (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        tenant_company_id BIGINT UNSIGNED NOT NULL,
        item_id BIGINT UNSIGNED NOT NULL,
        item_sku VARCHAR(90) NOT NULL DEFAULT "",
        item_nombre VARCHAR(190) NOT NULL DEFAULT "",
        item_unidad VARCHAR(40) NOT NULL DEFAULT "unidad",
        tipo VARCHAR(20) NOT NULL,
        cantidad DECIMAL(14,2) NOT NULL DEFAULT 0,
        motivo VARCHAR(255) NULL,
        stock_anterior DECIMAL(14,2) NOT NULL DEFAULT 0,
        stock_nuevo DECIMAL(14,2) NOT NULL DEFAULT 0,
        created_by VARCHAR(190) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_tenant_inventory_movements_item (tenant_company_id, item_id),
        KEY idx_tenant_inventory_movements_date (tenant_company_id, created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    }

    ensure_column($pdo, 'tenant_inventory_movements', 'tenant_company_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column($pdo, 'tenant_inventory_movements', 'item_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column($pdo, 'tenant_inventory_movements', 'item_sku', 'VARCHAR(90) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_inventory_movements', 'item_nombre', 'VARCHAR(190) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_inventory_movements', 'item_unidad', 'VARCHAR(40) NOT NULL DEFAULT "unidad"');
    ensure_column($pdo, 'tenant_inventory_movements', 'tipo', 'VARCHAR(20) NOT NULL DEFAULT "entrada"');
    ensure_column($pdo, 'tenant_inventory_movements', 'cantidad', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_inventory_movements', 'motivo', 'VARCHAR(255) NULL');
    ensure_column($pdo, 'tenant_inventory_movements', 'stock_anterior', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_inventory_movements', 'stock_nuevo', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_inventory_movements', 'created_by', 'VARCHAR(190) NULL');
    } catch (Throwable $invSchemaErr) {
      error_log('HERMES_INVENTORY_SCHEMA_WARN: ' . $invSchemaErr->getMessage());
    }

    if (!table_exists($pdo, 'tenant_quotes')) {
      $pdo->exec('CREATE TABLE tenant_quotes (
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
      validez_override TEXT NULL,
      entrega_override TEXT NULL,
      condicion_de_pago_override TEXT NULL,
      moneda_override VARCHAR(10) NULL,
      observaciones TEXT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uq_tenant_quotes_numero (tenant_company_id, numero_cotizacion),
      KEY idx_tenant_quotes_customer (tenant_company_id, customer_id),
      KEY idx_tenant_quotes_estado (tenant_company_id, estado)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    }

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
    ensure_column($pdo, 'tenant_quotes', 'validez_override', 'TEXT NULL');
    ensure_column($pdo, 'tenant_quotes', 'entrega_override', 'TEXT NULL');
    ensure_column($pdo, 'tenant_quotes', 'condicion_de_pago_override', 'TEXT NULL');
    ensure_column($pdo, 'tenant_quotes', 'moneda_override', 'VARCHAR(10) NULL');
    ensure_column($pdo, 'tenant_quotes', 'observaciones', 'TEXT NULL');
    ensure_column($pdo, 'tenant_quotes', 'deleted_at', 'DATETIME NULL');
    ensure_column($pdo, 'tenant_quotes', 'deleted_by', 'VARCHAR(190) NULL');

    if (!table_exists($pdo, 'tenant_quote_items')) {
      $pdo->exec('CREATE TABLE tenant_quote_items (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      tenant_quote_id BIGINT UNSIGNED NOT NULL,
      orden INT UNSIGNED NOT NULL DEFAULT 1,
      descripcion VARCHAR(255) NOT NULL,
      item_type VARCHAR(20) NOT NULL DEFAULT "normal",
      is_bold TINYINT(1) NOT NULL DEFAULT 0,
      cantidad DECIMAL(14,2) NOT NULL DEFAULT 1,
      precio_unitario DECIMAL(14,2) NOT NULL DEFAULT 0,
      total_linea DECIMAL(14,2) NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      KEY idx_tenant_quote_items_quote (tenant_quote_id, orden)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    }

    ensure_column($pdo, 'tenant_quote_items', 'tenant_quote_id', 'BIGINT UNSIGNED NOT NULL');
    ensure_column($pdo, 'tenant_quote_items', 'orden', 'INT UNSIGNED NOT NULL DEFAULT 1');
    ensure_column($pdo, 'tenant_quote_items', 'descripcion', 'VARCHAR(255) NOT NULL DEFAULT ""');
    ensure_column($pdo, 'tenant_quote_items', 'item_type', 'VARCHAR(20) NOT NULL DEFAULT "normal"');
    ensure_column($pdo, 'tenant_quote_items', 'is_bold', 'TINYINT(1) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_quote_items', 'cantidad', 'DECIMAL(14,2) NOT NULL DEFAULT 1');
    ensure_column($pdo, 'tenant_quote_items', 'precio_unitario', 'DECIMAL(14,2) NOT NULL DEFAULT 0');
    ensure_column($pdo, 'tenant_quote_items', 'total_linea', 'DECIMAL(14,2) NOT NULL DEFAULT 0');

    try {
      if (!table_exists($pdo, 'tenant_service_orders')) {
        $pdo->exec('CREATE TABLE tenant_service_orders (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          tenant_company_id BIGINT UNSIGNED NOT NULL,
          customer_id BIGINT UNSIGNED NOT NULL,
          codigo VARCHAR(40) NOT NULL,
          titulo VARCHAR(190) NOT NULL,
          descripcion TEXT NULL,
          estado VARCHAR(30) NOT NULL DEFAULT "borrador",
          prioridad VARCHAR(20) NOT NULL DEFAULT "normal",
          fecha_creacion DATE NULL,
          observaciones TEXT NULL,
          created_by VARCHAR(190) NULL,
          deleted_at DATETIME NULL,
          deleted_by VARCHAR(190) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY uq_tenant_service_orders_code (tenant_company_id, codigo),
          KEY idx_tenant_service_orders_lookup (tenant_company_id, estado, deleted_at),
          KEY idx_tenant_service_orders_customer (tenant_company_id, customer_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
      }
      if (!table_exists($pdo, 'tenant_service_order_assignments')) {
        $pdo->exec('CREATE TABLE tenant_service_order_assignments (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          tenant_company_id BIGINT UNSIGNED NOT NULL,
          service_order_id BIGINT UNSIGNED NOT NULL,
          technician_id BIGINT UNSIGNED NOT NULL,
          technician_nombre VARCHAR(190) NOT NULL DEFAULT "",
          work_date DATE NOT NULL,
          start_time TIME NULL,
          end_time TIME NULL,
          notas VARCHAR(255) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY uq_so_assignment_order_tech_date (service_order_id, technician_id, work_date),
          KEY idx_so_assignment_tech_date (tenant_company_id, technician_id, work_date),
          KEY idx_so_assignment_order (service_order_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
      }
      if (!table_exists($pdo, 'tenant_service_order_parts')) {
        $pdo->exec('CREATE TABLE tenant_service_order_parts (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          tenant_company_id BIGINT UNSIGNED NOT NULL,
          service_order_id BIGINT UNSIGNED NOT NULL,
          inventory_item_id BIGINT UNSIGNED NULL,
          sku VARCHAR(90) NOT NULL DEFAULT "",
          nombre VARCHAR(190) NOT NULL DEFAULT "",
          unidad VARCHAR(40) NOT NULL DEFAULT "unidad",
          cantidad DECIMAL(14,2) NOT NULL DEFAULT 1,
          notas VARCHAR(255) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_so_parts_order (service_order_id),
          KEY idx_so_parts_inv (tenant_company_id, inventory_item_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
      }
      if (!table_exists($pdo, 'tenant_service_order_checklist')) {
        $pdo->exec('CREATE TABLE tenant_service_order_checklist (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          tenant_company_id BIGINT UNSIGNED NOT NULL,
          service_order_id BIGINT UNSIGNED NOT NULL,
          orden INT UNSIGNED NOT NULL DEFAULT 1,
          descripcion VARCHAR(255) NOT NULL,
          completado TINYINT(1) NOT NULL DEFAULT 0,
          completado_at DATETIME NULL,
          completado_by VARCHAR(190) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_so_checklist_order (service_order_id, orden)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
      }
      if (!table_exists($pdo, 'tenant_service_reports')) {
        $pdo->exec('CREATE TABLE tenant_service_reports (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          tenant_company_id BIGINT UNSIGNED NOT NULL,
          service_order_id BIGINT UNSIGNED NOT NULL,
          technician_id BIGINT UNSIGNED NOT NULL,
          report_date DATE NOT NULL,
          work_done TEXT NOT NULL,
          external_purchases TEXT NULL,
          observations TEXT NULL,
          additional_details TEXT NULL,
          forms_note VARCHAR(255) NULL,
          forms_payload LONGTEXT NULL,
          photo_records LONGTEXT NULL,
          form_photo_records LONGTEXT NULL,
          technician_signature VARCHAR(190) NULL,
          customer_signature VARCHAR(190) NULL,
          technician_signature_draw VARCHAR(255) NULL,
          customer_signature_draw VARCHAR(255) NULL,
          created_by VARCHAR(190) NULL,
          deleted_at DATETIME NULL,
          deleted_by VARCHAR(190) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_service_reports_lookup (tenant_company_id, service_order_id, technician_id, report_date),
          KEY idx_service_reports_created (tenant_company_id, created_at),
          KEY idx_service_reports_deleted (tenant_company_id, deleted_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
      }
      ensure_column($pdo, 'tenant_service_reports', 'tenant_company_id', 'BIGINT UNSIGNED NOT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'service_order_id', 'BIGINT UNSIGNED NOT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'technician_id', 'BIGINT UNSIGNED NOT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'report_date', 'DATE NOT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'work_done', 'TEXT NOT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'external_purchases', 'TEXT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'observations', 'TEXT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'additional_details', 'TEXT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'forms_note', 'VARCHAR(255) NULL');
      ensure_column($pdo, 'tenant_service_reports', 'forms_payload', 'LONGTEXT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'photo_records', 'LONGTEXT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'form_photo_records', 'LONGTEXT NULL');
      ensure_column($pdo, 'tenant_service_reports', 'technician_signature', 'VARCHAR(190) NULL');
      ensure_column($pdo, 'tenant_service_reports', 'customer_signature', 'VARCHAR(190) NULL');
      ensure_column($pdo, 'tenant_service_reports', 'technician_signature_draw', 'VARCHAR(255) NULL');
      ensure_column($pdo, 'tenant_service_reports', 'customer_signature_draw', 'VARCHAR(255) NULL');
      ensure_column($pdo, 'tenant_service_reports', 'created_by', 'VARCHAR(190) NULL');
      ensure_column($pdo, 'tenant_service_reports', 'deleted_at', 'DATETIME NULL');
      ensure_column($pdo, 'tenant_service_reports', 'deleted_by', 'VARCHAR(190) NULL');

      if (!table_exists($pdo, 'tenant_form_templates')) {
        $pdo->exec('CREATE TABLE tenant_form_templates (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          tenant_company_id BIGINT UNSIGNED NOT NULL,
          name VARCHAR(190) NOT NULL,
          description TEXT NULL,
          fields_json LONGTEXT NOT NULL,
          is_active TINYINT(1) NOT NULL DEFAULT 1,
          created_by VARCHAR(190) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_form_templates_tenant_active (tenant_company_id, is_active),
          KEY idx_form_templates_created (tenant_company_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
      }

      if (!table_exists($pdo, 'tenant_service_order_form_templates')) {
        $pdo->exec('CREATE TABLE tenant_service_order_form_templates (
          id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          tenant_company_id BIGINT UNSIGNED NOT NULL,
          service_order_id BIGINT UNSIGNED NOT NULL,
          form_template_id BIGINT UNSIGNED NOT NULL,
          sort_order INT UNSIGNED NOT NULL DEFAULT 1,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          KEY idx_so_form_templates_order (service_order_id, sort_order),
          KEY idx_so_form_templates_template (form_template_id),
          UNIQUE KEY uq_so_form_templates (service_order_id, form_template_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
      }
    } catch (Throwable $soSchemaErr) {
      error_log('HERMES_SERVICE_ORDERS_SCHEMA_WARN: ' . $soSchemaErr->getMessage());
    }

    if (!table_exists($pdo, 'tenant_plan_usage')) {
      $pdo->exec('CREATE TABLE tenant_plan_usage (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        tenant_company_id BIGINT UNSIGNED NOT NULL,
        plan_code VARCHAR(40) NOT NULL DEFAULT "basico",
      storage_limit_mb INT UNSIGNED NOT NULL DEFAULT 100,
        storage_used_mb INT UNSIGNED NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_usage_company (tenant_company_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    }

      ensure_column($pdo, 'account_signups', 'billing_cycle', 'VARCHAR(20) NOT NULL DEFAULT "monthly"');
      ensure_column($pdo, 'account_signups', 'password_reset_token_hash', 'VARCHAR(255) NULL');
      ensure_column($pdo, 'account_signups', 'password_reset_expires_at', 'DATETIME NULL');
      ensure_column($pdo, 'account_signups', 'password_reset_requested_at', 'DATETIME NULL');
      ensure_column($pdo, 'tenant_companies', 'billing_cycle', 'VARCHAR(20) NOT NULL DEFAULT "monthly"');

      if (filter_var($accountLoginEmail, FILTER_VALIDATE_EMAIL)) {
        $stSignupByEmail = $pdo->prepare('SELECT id FROM account_signups WHERE LOWER(email) = LOWER(:email) LIMIT 1');
        $stSignupByEmail->execute(['email' => $accountLoginEmail]);
        $resolvedSignupId = (int)$stSignupByEmail->fetchColumn();
        if ($resolvedSignupId > 0) {
          $signupId = $resolvedSignupId;
          if ($sessionSignupId !== $resolvedSignupId) {
            $_SESSION['hermes_company_id'] = $resolvedSignupId;
          }
        }
      }

    if ($signupId > 0) {
        $stSignup = $pdo->prepare('SELECT id, company_name, contact_name, phone, email, tenant_company_id, payment_status, plan_code, billing_cycle, activated_at, created_at, payment_access_token, payment_access_expires_at FROM account_signups WHERE id = :id LIMIT 1');
        $stSignup->execute(['id' => $signupId]);
        $signup = $stSignup->fetch();
        if ($signup) {
            $companyName = (string)($signup['company_name'] ?? $companyName);
        $accountLoginEmail = (string)($signup['email'] ?? $accountLoginEmail);
        $accountSettings['email'] = $accountLoginEmail;
        $accountSettings['company_name'] = (string)($signup['company_name'] ?? '');
        $accountSettings['contact_name'] = (string)($signup['contact_name'] ?? '');
        $accountSettings['phone'] = (string)($signup['phone'] ?? '');
        $accountSettings['created_at'] = (string)($signup['created_at'] ?? '');
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
            if ($token === '' || $expiresTs === false || $expiresTs <= time()) {
              $token = issue_company_payment_token($pdo, (int)$signup['id']);
            }
            if ($token !== '') {
              $planBilling['payment_token'] = $token;
              $planBilling['payment_url'] = '/pagar-plan/?pt=' . rawurlencode($token);
              $planBilling['can_pay_renewal'] = true;
              $planUpgradeLinks['basico'] = '/pagar-plan/?pt=' . rawurlencode($token) . '&tp=basico';
              $planUpgradeLinks['pro'] = '/pagar-plan/?pt=' . rawurlencode($token) . '&tp=pro';
              $planUpgradeLinks['enterprise'] = '/pagar-plan/?pt=' . rawurlencode($token) . '&tp=enterprise';
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
            if ($planBilling['plan_status'] === 'paid') {
              $planBilling['payment_status'] = 'paid';
            }
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
            if ($planBilling['plan_status'] === 'paid') {
              $planBilling['payment_status'] = 'paid';
            }
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
        ensure_service_forms_tables($pdo);
        $isAjaxPost = ((string)($_POST['ajax'] ?? '') === '1')
          || (strtolower((string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest');
        $ajaxTechnicianActions = [
          'add_technician',
          'update_technician',
          'delete_technician',
          'add_technician_asset',
          'update_technician_asset',
          'delete_technician_asset',
        ];
        $ajaxTechnicianFocusId = 0;

        if (!security_validate_csrf($_POST['csrf_token'] ?? '')) {
            if ($isAjaxPost) {
              http_response_code(400);
              header('Content-Type: application/json; charset=UTF-8');
              echo json_encode([
                'ok' => false,
                'message' => 'Solicitud no valida. Recarga la pagina e intenta nuevamente.',
                'flash' => ['ok' => '', 'error' => 'Solicitud no valida. Recarga la pagina e intenta nuevamente.'],
              ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
              exit;
            }
            $flash['error'] = 'Solicitud no valida. Recarga la pagina e intenta nuevamente.';
            $module = (string)($_GET['module'] ?? $module);
            $_SESSION['hermes_company_postback'] = [
              'module' => $module,
              'flash' => $flash,
              'openCustomerModal' => $openCustomerModal,
              'openTechnicianModal' => $openTechnicianModal,
              'openTechnicianAssetModal' => $openTechnicianAssetModal,
              'openQuoteModal' => $openQuoteModal,
              'openQuoteEmailModal' => $openQuoteEmailModal,
              'openServiceReportModal' => $openServiceReportModal,
              'customerForm' => $customerForm,
              'technicianForm' => $technicianForm,
              'technicianAssetForm' => $technicianAssetForm,
              'technicianAssetRecords' => $technicianAssetRecords,
              'serviceReportForm' => $serviceReportForm,
              'quoteForm' => $quoteForm,
              'quoteEmailForm' => $quoteEmailForm,
            ];
            header('Location: ' . dashboard_module_url($module));
            exit;
        }

        $writeActions = [
          'save_company_logo', 'send_password_recovery_link', 'save_company_profile',
          'add_technician', 'update_technician', 'delete_technician', 'add_technician_asset', 'update_technician_asset', 'delete_technician_asset',
          'add_inventory_item', 'update_inventory_item', 'delete_inventory_item', 'add_inventory_movement',
          'restore_inventory_item', 'purge_inventory_item',
          'add_service_order', 'update_service_order', 'delete_service_order',
          'restore_service_order', 'purge_service_order', 'toggle_service_order_checklist', 'save_service_order_assignments',
          'save_form_template', 'delete_form_template',
          'add_service_report', 'update_service_report', 'delete_service_report', 'move_service_report_to_trash', 'restore_service_report', 'purge_service_report',
          'add_customer', 'update_customer', 'delete_customer', 'move_customer_to_trash',
          'delete_quote', 'move_quote_to_trash', 'restore_customer', 'restore_quote',
          'purge_quote', 'purge_customer', 'quick_update_quote_status', 'add_quote', 'update_quote', 'send_quote_email',
        ];

        if ($action === '' || !in_array($action, $writeActions, true)) {
          $flash['error'] = 'Accion no permitida.';
          $action = '';
        }

        $ownerAdminOnlyActions = [
          'save_company_logo',
          'save_company_profile',
          'send_password_recovery_link',
          'purge_quote',
          'purge_customer',
          'purge_inventory_item',
          'restore_customer',
          'restore_quote',
          'restore_inventory_item',
          'restore_service_order',
          'purge_service_order',
          'purge_service_report',
        ];
        if ($action !== '' && $role === 'company_user' && in_array($action, $ownerAdminOnlyActions, true)) {
          $flash['error'] = 'Tu rol no tiene permisos para ejecutar esta accion.';
          $action = '';
        }

        if ($action !== '' && in_array($action, $writeActions, true)) {
          $rateKey = 'dashboard-write:' . (string)$tenantCompanyId . ':' . strtolower((string)$accountLoginEmail);
          $rate = security_rate_limit_check($pdo, $rateKey, 30, 60);
          if (!$rate['allowed']) {
            if ($isAjaxPost) {
              http_response_code(429);
              header('Content-Type: application/json; charset=UTF-8');
              echo json_encode([
                'ok' => false,
                'message' => 'Se detectaron demasiadas acciones seguidas. Espera 1 minuto para continuar.',
                'flash' => ['ok' => '', 'error' => 'Se detectaron demasiadas acciones seguidas. Espera 1 minuto para continuar.'],
                'retry_after' => (int)$rate['retry_after'],
              ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
              exit;
            }
            $flash['error'] = 'Se detectaron demasiadas acciones seguidas. Espera 1 minuto para continuar.';
            $module = (string)($_GET['module'] ?? $module);
            $_SESSION['hermes_company_postback'] = [
              'module' => $module,
              'flash' => $flash,
              'openCustomerModal' => $openCustomerModal,
              'openTechnicianModal' => $openTechnicianModal,
              'openTechnicianAssetModal' => $openTechnicianAssetModal,
              'openQuoteModal' => $openQuoteModal,
              'openQuoteEmailModal' => $openQuoteEmailModal,
              'customerForm' => $customerForm,
              'technicianForm' => $technicianForm,
              'technicianAssetForm' => $technicianAssetForm,
              'technicianAssetRecords' => $technicianAssetRecords,
              'quoteForm' => $quoteForm,
              'quoteEmailForm' => $quoteEmailForm,
            ];
            security_audit_log($pdo, [
              'tenant_company_id' => $tenantCompanyId,
              'actor_email' => $accountLoginEmail,
              'actor_role' => $role,
              'action_name' => 'dashboard_rate_limited',
              'entity_name' => 'dashboard_action',
              'entity_id' => $action,
              'result_status' => 'blocked',
              'detail' => ['retry_after' => (int)$rate['retry_after']],
            ]);
            header('Location: ' . dashboard_module_url($module));
            exit;
          }
        }

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

          if ($action === 'send_password_recovery_link') {
            $module = 'configuracion';
            if ($signupId <= 0) {
              $flash['error'] = 'No se pudo identificar la cuenta para enviar la recuperacion.';
            } else {
              $recipientEmail = trim((string)$accountLoginEmail);
              if (!filter_var($recipientEmail, FILTER_VALIDATE_EMAIL)) {
                $flash['error'] = 'Tu cuenta no tiene un email valido para recuperar clave.';
              } else {
                $mailCfg = load_mail_credentials();
                if ($mailCfg === null) {
                  $flash['error'] = 'No hay configuracion SMTP disponible en el servidor.';
                } else {
                  try {
                    $plainToken = bin2hex(random_bytes(32));
                    $tokenHash = hash('sha256', $plainToken);
                    $expiresAt = date('Y-m-d H:i:s', time() + 3600);

                    $upReset = $pdo->prepare('UPDATE account_signups SET password_reset_token_hash = :hash, password_reset_expires_at = :expires_at, password_reset_requested_at = NOW() WHERE id = :id LIMIT 1');
                    $upReset->execute([
                      'hash' => $tokenHash,
                      'expires_at' => $expiresAt,
                      'id' => $signupId,
                    ]);

                    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                    $host = (string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost');
                    $resetLink = $scheme . '://' . $host . '/restablecer-clave/?t=' . rawurlencode($plainToken);
                    $recipientName = trim((string)($signup['contact_name'] ?? ''));
                    if ($recipientName === '') {
                      $recipientName = trim((string)($signup['company_name'] ?? 'Usuario'));
                    }

                    $sent = send_password_recovery_email_smtp($mailCfg, $recipientEmail, $recipientName, $resetLink);
                    if ($sent) {
                      $flash['ok'] = 'Se envio un enlace de recuperacion a tu correo de cuenta.';
                    } else {
                      $flash['error'] = 'No fue posible enviar el correo de recuperacion. Intenta nuevamente.';
                    }
                  } catch (Throwable $e) {
                    $flash['error'] = 'No se pudo generar el enlace de recuperacion.';
                  }
                }
              }
            }
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
                     SET company_id = :company_id,
                       customer_name = :customer_name,
                       contact_name = :contact_name,
                       contact_email = :contact_email,
                       phone = :phone,
                       is_active = 1,
                       rut = :rut,
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
                  $legacyCustomerPayload = [
                    'company_id' => $tenantCompanyId,
                    'customer_name' => ($customerInput['razon_social'] !== '' ? $customerInput['razon_social'] : $customerInput['rut']),
                    'contact_name' => ($customerInput['contacto'] !== '' ? $customerInput['contacto'] : null),
                    'contact_email' => ($customerInput['email'] !== '' ? $customerInput['email'] : null),
                    'phone' => ($customerInput['telefono'] !== '' ? $customerInput['telefono'] : ($customerInput['celular'] !== '' ? $customerInput['celular'] : null)),
                  ];
                  $upCustomer->execute(array_merge([
                    'id' => $customerId,
                    'tenant_company_id' => $tenantCompanyId,
                  ], $legacyCustomerPayload, $customerInput));
                  $flash['ok'] = 'Cliente actualizado correctamente.';
                } else {
                  $stRut = $pdo->prepare(
                    'SELECT id, deleted_at
                     FROM tenant_customers
                     WHERE tenant_company_id = :tenant_company_id
                       AND rut = :rut
                     LIMIT 1'
                  );
                  $stRut->execute([
                    'tenant_company_id' => $tenantCompanyId,
                    'rut' => $customerInput['rut'],
                  ]);
                  $existingByRut = $stRut->fetch();

                  if ($existingByRut) {
                    $existingId = (int)$existingByRut['id'];
                    $existingDeletedAt = (string)($existingByRut['deleted_at'] ?? '');
                    if ($existingDeletedAt !== '') {
                      $restoreCustomerByRut = $pdo->prepare(
                        'UPDATE tenant_customers
                         SET company_id = :company_id,
                           customer_name = :customer_name,
                           contact_name = :contact_name,
                           contact_email = :contact_email,
                           phone = :phone,
                           is_active = 1,
                           razon_social = :razon_social,
                           nombre_fantasia = :nombre_fantasia,
                           direccion = :direccion,
                           comuna = :comuna,
                           ciudad = :ciudad,
                           telefono = :telefono,
                           celular = :celular,
                           email = :email,
                           contacto = :contacto,
                           notas_internas = :notas_internas,
                           estado = 1,
                           deleted_at = NULL,
                           deleted_by = NULL
                         WHERE id = :id
                           AND tenant_company_id = :tenant_company_id'
                      );
                      $legacyCustomerPayload = [
                        'company_id' => $tenantCompanyId,
                        'customer_name' => ($customerInput['razon_social'] !== '' ? $customerInput['razon_social'] : $customerInput['rut']),
                        'contact_name' => ($customerInput['contacto'] !== '' ? $customerInput['contacto'] : null),
                        'contact_email' => ($customerInput['email'] !== '' ? $customerInput['email'] : null),
                        'phone' => ($customerInput['telefono'] !== '' ? $customerInput['telefono'] : ($customerInput['celular'] !== '' ? $customerInput['celular'] : null)),
                      ];
                      $restoreCustomerByRut->execute(array_merge([
                        'id' => $existingId,
                        'tenant_company_id' => $tenantCompanyId,
                      ], $legacyCustomerPayload, $customerInput));
                      $flash['ok'] = 'Cliente restaurado desde papelera y actualizado correctamente.';
                    } else {
                      throw new RuntimeException('Ya existe un cliente activo con ese RUT.');
                    }
                  } else {
                    $insCustomer = $pdo->prepare(
                      'INSERT INTO tenant_customers (
                        tenant_company_id, company_id, customer_name, contact_name, contact_email, phone, is_active,
                        rut, razon_social, nombre_fantasia, direccion, comuna, ciudad, telefono, celular, email, contacto, notas_internas, estado
                       ) VALUES (
                        :tenant_company_id, :company_id, :customer_name, :contact_name, :contact_email, :phone, 1,
                        :rut, :razon_social, :nombre_fantasia, :direccion, :comuna, :ciudad, :telefono, :celular, :email, :contacto, :notas_internas, 1
                       )'
                    );
                    $legacyCustomerPayload = [
                      'customer_name' => ($customerInput['razon_social'] !== '' ? $customerInput['razon_social'] : $customerInput['rut']),
                      'contact_name' => ($customerInput['contacto'] !== '' ? $customerInput['contacto'] : null),
                      'contact_email' => ($customerInput['email'] !== '' ? $customerInput['email'] : null),
                      'phone' => ($customerInput['telefono'] !== '' ? $customerInput['telefono'] : ($customerInput['celular'] !== '' ? $customerInput['celular'] : null)),
                    ];
                    $insCustomer->execute(array_merge([
                      'tenant_company_id' => $tenantCompanyId,
                      'company_id' => $tenantCompanyId,
                    ], $legacyCustomerPayload, $customerInput));
                    $flash['ok'] = 'Cliente agregado correctamente.';
                  }
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
                  $err = trim((string)$e->getMessage());
                  if ($err !== '') {
                    $flash['error'] = $err;
                  } else {
                    $flash['error'] = 'No se pudo guardar el cliente. Verifica si el RUT ya existe.';
                  }
                    $openCustomerModal = true;
                }
                $module = 'clientes';
            }
        }

        if ($action === 'add_technician' || $action === 'update_technician') {
          $isEditTechnician = $action === 'update_technician';
          $technicianId = (int)($_POST['technician_id'] ?? 0);
          $ajaxTechnicianFocusId = $technicianId;
          $technicianInput = [
            'nombre' => trim((string)($_POST['nombre'] ?? '')),
            'apellido' => trim((string)($_POST['apellido'] ?? '')),
            'cargo' => trim((string)($_POST['cargo'] ?? '')),
            'cuenta' => trim((string)($_POST['cuenta'] ?? '')),
            'fecha_ingreso' => trim((string)($_POST['fecha_ingreso'] ?? '')),
            'estado' => strtolower(trim((string)($_POST['estado'] ?? 'activo'))),
            'habilidades' => technician_skills_normalize($_POST['habilidades'] ?? []),
          ];
          if (!in_array($technicianInput['estado'], ['activo', 'inactivo'], true)) {
            $technicianInput['estado'] = 'activo';
          }
          $technicianForm = array_merge(['id' => (string)$technicianId], $technicianInput);

          if ($technicianInput['nombre'] === '' || $technicianInput['apellido'] === '' || $technicianInput['cargo'] === '' || $technicianInput['fecha_ingreso'] === '') {
            $flash['error'] = 'Completa nombre, apellido, cargo y fecha de ingreso del tecnico.';
            $openTechnicianModal = true;
          } elseif (strtotime($technicianInput['fecha_ingreso']) === false) {
            $flash['error'] = 'La fecha de ingreso no es valida.';
            $openTechnicianModal = true;
          } else {
            try {
              if ($isEditTechnician) {
                if ($technicianId <= 0) {
                  throw new RuntimeException('Tecnico invalido para editar.');
                }

                $stOwnTechnician = $pdo->prepare(
                  'SELECT id
                   FROM tenant_technicians
                   WHERE id = :id
                     AND company_id = :company_id
                   LIMIT 1'
                );
                $stOwnTechnician->execute([
                  'id' => $technicianId,
                  'company_id' => $tenantCompanyId,
                ]);
                if (!$stOwnTechnician->fetchColumn()) {
                  throw new RuntimeException('El tecnico no pertenece a tu empresa.');
                }

                $upTechnician = $pdo->prepare(
                  'UPDATE tenant_technicians
                   SET company_id = :company_id,
                       full_name = :full_name,
                       specialty = :specialty,
                       email = :email,
                       phone = :phone,
                       is_active = :is_active
                   WHERE id = :id
                     AND company_id = :company_id'
                );
                $upTechnician->execute([
                  'company_id' => $tenantCompanyId,
                  'full_name' => trim($technicianInput['nombre'] . ' ' . $technicianInput['apellido']),
                  'specialty' => $technicianInput['cargo'],
                  'email' => ($technicianInput['cuenta'] !== '' ? $technicianInput['cuenta'] : null),
                  'phone' => technician_meta_encode($technicianInput['fecha_ingreso'], $technicianInput['estado'], $technicianInput['habilidades']),
                  'is_active' => ($technicianInput['estado'] === 'activo' ? 1 : 0),
                  'id' => $technicianId,
                ]);
                $flash['ok'] = 'Tecnico actualizado correctamente.';
              } else {
                $insTechnician = $pdo->prepare(
                  'INSERT INTO tenant_technicians (
                    company_id, full_name, specialty, email, phone, is_active
                   ) VALUES (
                    :company_id, :full_name, :specialty, :email, :phone, :is_active
                   )'
                );
                $insTechnician->execute([
                  'company_id' => $tenantCompanyId,
                  'full_name' => trim($technicianInput['nombre'] . ' ' . $technicianInput['apellido']),
                  'specialty' => $technicianInput['cargo'],
                  'email' => ($technicianInput['cuenta'] !== '' ? $technicianInput['cuenta'] : null),
                  'phone' => technician_meta_encode($technicianInput['fecha_ingreso'], $technicianInput['estado'], $technicianInput['habilidades']),
                  'is_active' => ($technicianInput['estado'] === 'activo' ? 1 : 0),
                ]);
                $ajaxTechnicianFocusId = (int)$pdo->lastInsertId();
                $flash['ok'] = 'Tecnico agregado correctamente.';
              }

              $technicianForm = [
                'id' => '',
                'nombre' => '',
                'apellido' => '',
                'cargo' => '',
                'cuenta' => '',
                'fecha_ingreso' => date('Y-m-d'),
                'estado' => 'activo',
                'habilidades' => [],
              ];
            } catch (Throwable $e) {
              $err = trim((string)$e->getMessage());
              $flash['error'] = ($err !== '' ? $err : 'No se pudo guardar el tecnico.');
              $openTechnicianModal = true;
            }
            $module = 'tecnicos';
          }
        }

        if ($action === 'add_technician_asset') {
          $module = 'tecnicos';
          $technicianId = (int)($_POST['technician_id'] ?? 0);
          $ajaxTechnicianFocusId = $technicianId;
          $assetType = technician_asset_type_normalize((string)($_POST['asset_type'] ?? 'epp'));
          $assetInput = [
            'descripcion' => trim((string)($_POST['descripcion'] ?? '')),
            'fecha_entrega' => trim((string)($_POST['fecha_entrega'] ?? '')),
            'fecha_vencimiento' => trim((string)($_POST['fecha_vencimiento'] ?? '')),
            'estado' => technician_asset_state_normalize((string)($_POST['estado'] ?? 'nuevo')),
          ];

          $technicianAssetForm = [
            'technician_id' => (string)$technicianId,
            'technician_nombre' => '',
            'asset_type' => $assetType,
            'descripcion' => $assetInput['descripcion'],
            'fecha_entrega' => $assetInput['fecha_entrega'],
            'fecha_vencimiento' => $assetInput['fecha_vencimiento'],
            'estado' => $assetInput['estado'],
          ];
          $openTechnicianAssetModal = true;

          try {
            if ($technicianId <= 0) {
              throw new RuntimeException('Selecciona un tecnico valido para gestionar elementos.');
            }

            $stOwnTechnician = $pdo->prepare(
              'SELECT id, full_name
                 FROM tenant_technicians
                WHERE id = :id
                  AND company_id = :company_id
                LIMIT 1'
            );
            $stOwnTechnician->execute([
              'id' => $technicianId,
              'company_id' => $tenantCompanyId,
            ]);
            $ownedTechnician = $stOwnTechnician->fetch();
            if (!$ownedTechnician) {
              throw new RuntimeException('El tecnico no pertenece a tu empresa.');
            }

            $technicianAssetForm['technician_nombre'] = trim((string)($ownedTechnician['full_name'] ?? ''));

            if ($assetInput['descripcion'] === '') {
              throw new RuntimeException('Debes indicar el elemento a registrar.');
            }
            if ($assetInput['fecha_entrega'] === '' || strtotime($assetInput['fecha_entrega']) === false) {
              throw new RuntimeException('La fecha de entrega no es valida.');
            }
            if ($assetType === 'epp') {
              if ($assetInput['fecha_vencimiento'] === '' || strtotime($assetInput['fecha_vencimiento']) === false) {
                throw new RuntimeException('Para EPP debes indicar una fecha de vencimiento valida.');
              }
            } else {
              $assetInput['fecha_vencimiento'] = '';
            }

            $payload = technician_assets_load($tenantCompanyId, $technicianId);
            $payload[$assetType][] = [
              'id' => bin2hex(random_bytes(6)),
              'descripcion' => $assetInput['descripcion'],
              'fecha_entrega' => $assetInput['fecha_entrega'],
              'fecha_vencimiento' => $assetInput['fecha_vencimiento'],
              'estado' => ($assetType === 'epp' ? '' : $assetInput['estado']),
              'creado_en' => date('Y-m-d H:i:s'),
            ];
            technician_assets_save($tenantCompanyId, $technicianId, $payload);
            $technicianAssetRecords = technician_assets_load($tenantCompanyId, $technicianId);

            $assetLabelMap = ['epp' => 'EPP', 'cargo' => 'Cargo', 'herramientas' => 'Herramienta'];
            $flash['ok'] = ($assetLabelMap[$assetType] ?? 'Elemento') . ' registrado correctamente para el tecnico.';
            $technicianAssetForm['descripcion'] = '';
            $technicianAssetForm['fecha_entrega'] = date('Y-m-d');
            $technicianAssetForm['fecha_vencimiento'] = '';
            $technicianAssetForm['estado'] = 'nuevo';
          } catch (Throwable $e) {
            $flash['error'] = trim((string)$e->getMessage()) !== '' ? trim((string)$e->getMessage()) : 'No se pudo registrar la gestion del tecnico.';
            if ($technicianId > 0) {
              $technicianAssetRecords = technician_assets_load($tenantCompanyId, $technicianId);
            }
          }
        }

        if ($action === 'update_technician_asset') {
          $module = 'tecnicos';
          $technicianId = (int)($_POST['technician_id'] ?? 0);
          $ajaxTechnicianFocusId = $technicianId;
          $assetType = technician_asset_type_normalize((string)($_POST['asset_type'] ?? 'epp'));
          $assetId = trim((string)($_POST['asset_id'] ?? ''));
          $assetInput = [
            'descripcion' => trim((string)($_POST['descripcion'] ?? '')),
            'fecha_entrega' => trim((string)($_POST['fecha_entrega'] ?? '')),
            'fecha_vencimiento' => trim((string)($_POST['fecha_vencimiento'] ?? '')),
            'estado' => technician_asset_state_normalize((string)($_POST['estado'] ?? 'nuevo')),
          ];

          $technicianAssetForm = [
            'technician_id' => (string)$technicianId,
            'technician_nombre' => '',
            'asset_type' => $assetType,
            'descripcion' => $assetInput['descripcion'],
            'fecha_entrega' => $assetInput['fecha_entrega'],
            'fecha_vencimiento' => $assetInput['fecha_vencimiento'],
            'estado' => $assetInput['estado'],
          ];
          $openTechnicianAssetModal = true;

          try {
            if ($technicianId <= 0) {
              throw new RuntimeException('Selecciona un tecnico valido para gestionar elementos.');
            }
            if ($assetId === '') {
              throw new RuntimeException('Elemento invalido para editar.');
            }

            $stOwnTechnician = $pdo->prepare(
              'SELECT id, full_name
                 FROM tenant_technicians
                WHERE id = :id
                  AND company_id = :company_id
                LIMIT 1'
            );
            $stOwnTechnician->execute([
              'id' => $technicianId,
              'company_id' => $tenantCompanyId,
            ]);
            $ownedTechnician = $stOwnTechnician->fetch();
            if (!$ownedTechnician) {
              throw new RuntimeException('El tecnico no pertenece a tu empresa.');
            }

            $technicianAssetForm['technician_nombre'] = trim((string)($ownedTechnician['full_name'] ?? ''));
            if ($assetInput['descripcion'] === '') {
              throw new RuntimeException('Debes indicar el elemento a registrar.');
            }
            if ($assetInput['fecha_entrega'] === '' || strtotime($assetInput['fecha_entrega']) === false) {
              throw new RuntimeException('La fecha de entrega no es valida.');
            }
            if ($assetType === 'epp') {
              if ($assetInput['fecha_vencimiento'] === '' || strtotime($assetInput['fecha_vencimiento']) === false) {
                throw new RuntimeException('Para EPP debes indicar una fecha de vencimiento valida.');
              }
            } else {
              $assetInput['fecha_vencimiento'] = '';
            }

            $payload = technician_assets_load($tenantCompanyId, $technicianId);
            $found = false;
            foreach ((array)$payload[$assetType] as $idx => $item) {
              if ((string)($item['id'] ?? '') !== $assetId) {
                continue;
              }
              $payload[$assetType][$idx]['descripcion'] = $assetInput['descripcion'];
              $payload[$assetType][$idx]['fecha_entrega'] = $assetInput['fecha_entrega'];
              $payload[$assetType][$idx]['fecha_vencimiento'] = $assetInput['fecha_vencimiento'];
              $payload[$assetType][$idx]['estado'] = ($assetType === 'epp' ? '' : $assetInput['estado']);
              $payload[$assetType][$idx]['actualizado_en'] = date('Y-m-d H:i:s');
              $found = true;
              break;
            }
            if (!$found) {
              throw new RuntimeException('No se encontro el elemento a editar.');
            }

            technician_assets_save($tenantCompanyId, $technicianId, $payload);
            $technicianAssetRecords = technician_assets_load($tenantCompanyId, $technicianId);
            $flash['ok'] = 'Elemento actualizado correctamente.';
            $technicianAssetForm['descripcion'] = '';
            $technicianAssetForm['fecha_entrega'] = date('Y-m-d');
            $technicianAssetForm['fecha_vencimiento'] = '';
            $technicianAssetForm['estado'] = 'nuevo';
          } catch (Throwable $e) {
            $flash['error'] = trim((string)$e->getMessage()) !== '' ? trim((string)$e->getMessage()) : 'No se pudo actualizar la gestion del tecnico.';
            if ($technicianId > 0) {
              $technicianAssetRecords = technician_assets_load($tenantCompanyId, $technicianId);
            }
          }
        }

        if ($action === 'delete_technician_asset') {
          $module = 'tecnicos';
          $technicianId = (int)($_POST['technician_id'] ?? 0);
          $ajaxTechnicianFocusId = $technicianId;
          $assetType = technician_asset_type_normalize((string)($_POST['asset_type'] ?? 'epp'));
          $assetId = trim((string)($_POST['asset_id'] ?? ''));

          try {
            if ($technicianId <= 0 || $assetId === '') {
              throw new RuntimeException('Elemento invalido para eliminar.');
            }

            $stOwnTechnician = $pdo->prepare(
              'SELECT id
                 FROM tenant_technicians
                WHERE id = :id
                  AND company_id = :company_id
                LIMIT 1'
            );
            $stOwnTechnician->execute([
              'id' => $technicianId,
              'company_id' => $tenantCompanyId,
            ]);
            if (!$stOwnTechnician->fetchColumn()) {
              throw new RuntimeException('El tecnico no pertenece a tu empresa.');
            }

            $payload = technician_assets_load($tenantCompanyId, $technicianId);
            $before = count((array)$payload[$assetType]);
            $payload[$assetType] = array_values(array_filter(
              (array)$payload[$assetType],
              static function ($item) use ($assetId) {
                return (string)($item['id'] ?? '') !== $assetId;
              }
            ));

            if (count((array)$payload[$assetType]) === $before) {
              throw new RuntimeException('No se encontro el elemento a eliminar.');
            }

            technician_assets_save($tenantCompanyId, $technicianId, $payload);
            $flash['ok'] = 'Elemento eliminado correctamente.';
            $technicianAssetRecords = technician_assets_load($tenantCompanyId, $technicianId);
          } catch (Throwable $e) {
            $flash['error'] = trim((string)$e->getMessage()) !== '' ? trim((string)$e->getMessage()) : 'No se pudo eliminar la gestion del tecnico.';
            if ($technicianId > 0) {
              $technicianAssetRecords = technician_assets_load($tenantCompanyId, $technicianId);
            }
          }
        }

        if ($action === 'delete_technician') {
          $technicianId = (int)($_POST['technician_id'] ?? 0);
          $ajaxTechnicianFocusId = $technicianId;
          if ($technicianId > 0) {
            $delTechnician = $pdo->prepare(
              'DELETE FROM tenant_technicians
               WHERE id = :id
                 AND company_id = :company_id'
            );
            $delTechnician->execute([
              'id' => $technicianId,
              'company_id' => $tenantCompanyId,
            ]);
            if ($delTechnician->rowCount() > 0) {
              $flash['ok'] = 'Tecnico eliminado correctamente.';
            }
          }
          $module = 'tecnicos';
        }

        if ($action === 'add_inventory_item' || $action === 'update_inventory_item') {
          $module = 'inventario';
          $isEditInventory = ($action === 'update_inventory_item');
          $inventoryId = (int)($_POST['inventory_item_id'] ?? 0);
          $inventoryInput = [
            'sku' => trim((string)($_POST['sku'] ?? '')),
            'nombre' => trim((string)($_POST['nombre'] ?? '')),
            'descripcion' => trim((string)($_POST['descripcion'] ?? '')),
            'unidad' => trim((string)($_POST['unidad'] ?? 'unidad')),
            'stock_actual' => inventory_number_from_input($_POST['stock_actual'] ?? '0'),
            'stock_minimo' => inventory_number_from_input($_POST['stock_minimo'] ?? '0'),
            'stock_critico' => inventory_number_from_input($_POST['stock_critico'] ?? '0'),
            'costo_unitario' => inventory_number_from_input($_POST['costo_unitario'] ?? '0'),
            'estado' => inventory_state_normalize((string)($_POST['estado'] ?? 'activo')),
          ];

          $inventoryForm = [
            'id' => (string)$inventoryId,
            'sku' => $inventoryInput['sku'],
            'nombre' => $inventoryInput['nombre'],
            'descripcion' => $inventoryInput['descripcion'],
            'unidad' => $inventoryInput['unidad'],
            'stock_actual' => (string)$inventoryInput['stock_actual'],
            'stock_minimo' => (string)$inventoryInput['stock_minimo'],
            'stock_critico' => (string)$inventoryInput['stock_critico'],
            'costo_unitario' => (string)$inventoryInput['costo_unitario'],
            'estado' => $inventoryInput['estado'],
          ];

          if ($inventoryInput['sku'] === '' || $inventoryInput['nombre'] === '') {
            $flash['error'] = 'SKU y nombre son obligatorios.';
            $openInventoryModal = true;
          } elseif (
            $inventoryInput['stock_actual'] < 0
            || $inventoryInput['stock_minimo'] < 0
            || $inventoryInput['stock_critico'] < 0
            || $inventoryInput['costo_unitario'] < 0
          ) {
            $flash['error'] = 'Stock y costos no pueden ser negativos.';
            $openInventoryModal = true;
          } else {
            if ($inventoryInput['unidad'] === '') {
              $inventoryInput['unidad'] = 'unidad';
            }

            try {
              $pdo->beginTransaction();

              if ($isEditInventory) {
                if ($inventoryId <= 0) {
                  throw new RuntimeException('Item invalido para editar.');
                }

                $stCurrent = $pdo->prepare(
                  'SELECT id, sku, nombre, unidad, stock_actual
                     FROM tenant_inventory_items
                    WHERE id = :id
                      AND tenant_company_id = :tenant_company_id
                      AND deleted_at IS NULL
                    LIMIT 1'
                );
                $stCurrent->execute([
                  'id' => $inventoryId,
                  'tenant_company_id' => $tenantCompanyId,
                ]);
                $currentItem = $stCurrent->fetch();
                if (!$currentItem) {
                  throw new RuntimeException('El item no pertenece a tu empresa.');
                }

                $upItem = $pdo->prepare(
                  'UPDATE tenant_inventory_items
                      SET sku = :sku,
                          nombre = :nombre,
                          descripcion = :descripcion,
                          unidad = :unidad,
                          stock_actual = :stock_actual,
                          stock_minimo = :stock_minimo,
                          stock_critico = :stock_critico,
                          costo_unitario = :costo_unitario,
                          estado = :estado
                    WHERE id = :id
                      AND tenant_company_id = :tenant_company_id'
                );
                $upItem->execute([
                  'sku' => $inventoryInput['sku'],
                  'nombre' => $inventoryInput['nombre'],
                  'descripcion' => ($inventoryInput['descripcion'] !== '' ? $inventoryInput['descripcion'] : null),
                  'unidad' => $inventoryInput['unidad'],
                  'stock_actual' => $inventoryInput['stock_actual'],
                  'stock_minimo' => $inventoryInput['stock_minimo'],
                  'stock_critico' => $inventoryInput['stock_critico'],
                  'costo_unitario' => $inventoryInput['costo_unitario'],
                  'estado' => $inventoryInput['estado'],
                  'id' => $inventoryId,
                  'tenant_company_id' => $tenantCompanyId,
                ]);

                $diff = (float)$inventoryInput['stock_actual'] - (float)$currentItem['stock_actual'];
                if (abs($diff) > 0.0001) {
                  $movementType = ($diff > 0 ? 'entrada' : 'salida');
                  $movementAmount = abs($diff);
                  $movementReason = 'Ajuste manual de item en inventario';
                  $insAutoMovement = $pdo->prepare(
                    'INSERT INTO tenant_inventory_movements (
                      tenant_company_id, item_id, item_sku, item_nombre, item_unidad,
                      tipo, cantidad, motivo, stock_anterior, stock_nuevo, created_by
                     ) VALUES (
                      :tenant_company_id, :item_id, :item_sku, :item_nombre, :item_unidad,
                      :tipo, :cantidad, :motivo, :stock_anterior, :stock_nuevo, :created_by
                     )'
                  );
                  $insAutoMovement->execute([
                    'tenant_company_id' => $tenantCompanyId,
                    'item_id' => $inventoryId,
                    'item_sku' => $inventoryInput['sku'],
                    'item_nombre' => $inventoryInput['nombre'],
                    'item_unidad' => $inventoryInput['unidad'],
                    'tipo' => $movementType,
                    'cantidad' => $movementAmount,
                    'motivo' => $movementReason,
                    'stock_anterior' => (float)$currentItem['stock_actual'],
                    'stock_nuevo' => (float)$inventoryInput['stock_actual'],
                    'created_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : null),
                  ]);
                }

                $flash['ok'] = 'Item de inventario actualizado correctamente.';
              } else {
                $insItem = $pdo->prepare(
                  'INSERT INTO tenant_inventory_items (
                    tenant_company_id, sku, nombre, descripcion, unidad,
                    stock_actual, stock_minimo, stock_critico, costo_unitario, estado
                   ) VALUES (
                    :tenant_company_id, :sku, :nombre, :descripcion, :unidad,
                    :stock_actual, :stock_minimo, :stock_critico, :costo_unitario, :estado
                   )'
                );
                $insItem->execute([
                  'tenant_company_id' => $tenantCompanyId,
                  'sku' => $inventoryInput['sku'],
                  'nombre' => $inventoryInput['nombre'],
                  'descripcion' => ($inventoryInput['descripcion'] !== '' ? $inventoryInput['descripcion'] : null),
                  'unidad' => $inventoryInput['unidad'],
                  'stock_actual' => $inventoryInput['stock_actual'],
                  'stock_minimo' => $inventoryInput['stock_minimo'],
                  'stock_critico' => $inventoryInput['stock_critico'],
                  'costo_unitario' => $inventoryInput['costo_unitario'],
                  'estado' => $inventoryInput['estado'],
                ]);
                $newInventoryId = (int)$pdo->lastInsertId();

                if ($inventoryInput['stock_actual'] > 0) {
                  $insInitMovement = $pdo->prepare(
                    'INSERT INTO tenant_inventory_movements (
                      tenant_company_id, item_id, item_sku, item_nombre, item_unidad,
                      tipo, cantidad, motivo, stock_anterior, stock_nuevo, created_by
                     ) VALUES (
                      :tenant_company_id, :item_id, :item_sku, :item_nombre, :item_unidad,
                      :tipo, :cantidad, :motivo, :stock_anterior, :stock_nuevo, :created_by
                     )'
                  );
                  $insInitMovement->execute([
                    'tenant_company_id' => $tenantCompanyId,
                    'item_id' => $newInventoryId,
                    'item_sku' => $inventoryInput['sku'],
                    'item_nombre' => $inventoryInput['nombre'],
                    'item_unidad' => $inventoryInput['unidad'],
                    'tipo' => 'entrada',
                    'cantidad' => (float)$inventoryInput['stock_actual'],
                    'motivo' => 'Carga inicial de stock',
                    'stock_anterior' => 0,
                    'stock_nuevo' => (float)$inventoryInput['stock_actual'],
                    'created_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : null),
                  ]);
                }

                $flash['ok'] = 'Item de inventario agregado correctamente.';
              }

              $pdo->commit();
              $inventoryForm = [
                'id' => '',
                'sku' => '',
                'nombre' => '',
                'descripcion' => '',
                'unidad' => 'unidad',
                'stock_actual' => '0',
                'stock_minimo' => '0',
                'stock_critico' => '0',
                'costo_unitario' => '0',
                'estado' => 'activo',
              ];
            } catch (Throwable $e) {
              if ($pdo->inTransaction()) {
                $pdo->rollBack();
              }
              $err = trim((string)$e->getMessage());
              if ($err === '' && stripos((string)$e->getMessage(), 'Duplicate') !== false) {
                $err = 'El SKU ya existe en tu inventario.';
              }
              $flash['error'] = ($err !== '' ? $err : 'No se pudo guardar el item de inventario.');
              $openInventoryModal = true;
            }
          }
        }

        if ($action === 'delete_inventory_item') {
          $module = 'inventario';
          $inventoryId = (int)($_POST['inventory_item_id'] ?? 0);
          if ($inventoryId > 0) {
            $delItem = $pdo->prepare(
              'UPDATE tenant_inventory_items
                  SET deleted_at = NOW(),
                      deleted_by = :deleted_by,
                      estado = "inactivo"
                WHERE id = :id
                  AND tenant_company_id = :tenant_company_id
                  AND deleted_at IS NULL'
            );
            $delItem->execute([
              'id' => $inventoryId,
              'tenant_company_id' => $tenantCompanyId,
              'deleted_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : 'owner@local.invalid'),
            ]);
            if ($delItem->rowCount() > 0) {
              $flash['ok'] = 'Item de inventario eliminado correctamente.';
            }
          }
        }

        if ($action === 'restore_inventory_item') {
          $module = 'papelera';
          $inventoryId = (int)($_POST['inventory_item_id'] ?? 0);
          if ($inventoryId > 0) {
            $stOwn = $pdo->prepare(
              'SELECT id FROM tenant_inventory_items
                WHERE id = :id AND tenant_company_id = :tenant_company_id AND deleted_at IS NOT NULL LIMIT 1'
            );
            $stOwn->execute(['id' => $inventoryId, 'tenant_company_id' => $tenantCompanyId]);
            if ($stOwn->fetchColumn()) {
              $upRestore = $pdo->prepare(
                'UPDATE tenant_inventory_items
                    SET deleted_at = NULL,
                        deleted_by = NULL,
                        estado = "activo"
                  WHERE id = :id AND tenant_company_id = :tenant_company_id'
              );
              $upRestore->execute(['id' => $inventoryId, 'tenant_company_id' => $tenantCompanyId]);
              if ($upRestore->rowCount() > 0) {
                $flash['ok'] = 'Item de inventario restaurado correctamente.';
              } else {
                $flash['error'] = 'No se pudo restaurar el item.';
              }
            } else {
              $flash['error'] = 'No se encontro el item en papelera.';
            }
          }
        }

        if ($action === 'purge_inventory_item') {
          $module = 'papelera';
          $inventoryId = (int)($_POST['inventory_item_id'] ?? 0);
          if ($inventoryId > 0) {
            $stOwn = $pdo->prepare(
              'SELECT id FROM tenant_inventory_items
                WHERE id = :id AND tenant_company_id = :tenant_company_id AND deleted_at IS NOT NULL LIMIT 1'
            );
            $stOwn->execute(['id' => $inventoryId, 'tenant_company_id' => $tenantCompanyId]);
            if ($stOwn->fetchColumn()) {
              $pdo->beginTransaction();
              try {
                $delMov = $pdo->prepare(
                  'DELETE FROM tenant_inventory_movements
                    WHERE tenant_company_id = :tenant_company_id AND item_id = :item_id'
                );
                $delMov->execute(['tenant_company_id' => $tenantCompanyId, 'item_id' => $inventoryId]);

                $delInv = $pdo->prepare(
                  'DELETE FROM tenant_inventory_items
                    WHERE id = :id AND tenant_company_id = :tenant_company_id'
                );
                $delInv->execute(['id' => $inventoryId, 'tenant_company_id' => $tenantCompanyId]);

                $pdo->commit();
                $flash['ok'] = 'Item eliminado de forma definitiva.';
              } catch (Throwable $e) {
                $pdo->rollBack();
                $flash['error'] = 'No se pudo eliminar definitivamente el item.';
              }
            } else {
              $flash['error'] = 'No se encontro el item en papelera.';
            }
          }
        }

        if ($action === 'save_form_template' || $action === 'delete_form_template') {
          $module = 'formularios';
          $canUseReportForms = in_array(normalize_plan_code((string)$usage['plan_code'], 'basico'), ['pro', 'enterprise', 'olimpico'], true);
          if (!$canUseReportForms) {
            $flash['error'] = 'Tu plan actual no habilita el modulo de Formularios.';
          } elseif ($action === 'save_form_template') {
            $templateId = (int)($_POST['form_template_id'] ?? 0);
            $templateName = trim((string)($_POST['template_name'] ?? ''));
            $templateDescription = trim((string)($_POST['template_description'] ?? ''));
            $fields = service_form_template_fields_normalize($_POST['template_fields'] ?? '[]');
            if ($templateName === '') {
              $flash['error'] = 'El nombre de la plantilla es obligatorio.';
            } elseif (empty($fields)) {
              $flash['error'] = 'Debes agregar al menos un campo en la plantilla.';
            } else {
              try {
                if ($templateId > 0) {
                  $upTpl = $pdo->prepare(
                    'UPDATE tenant_form_templates
                        SET name = :name,
                            description = :description,
                            fields_json = :fields_json,
                            is_active = 1
                      WHERE id = :id AND tenant_company_id = :tc'
                  );
                  $upTpl->execute([
                    'name' => $templateName,
                    'description' => ($templateDescription !== '' ? $templateDescription : null),
                    'fields_json' => json_encode($fields, JSON_UNESCAPED_UNICODE),
                    'id' => $templateId,
                    'tc' => $tenantCompanyId,
                  ]);
                  if ($upTpl->rowCount() <= 0) {
                    throw new RuntimeException('No se pudo actualizar la plantilla seleccionada.');
                  }
                  $flash['ok'] = 'Plantilla actualizada correctamente.';
                } else {
                  $insTpl = $pdo->prepare(
                    'INSERT INTO tenant_form_templates (
                      tenant_company_id, name, description, fields_json, is_active, created_by
                    ) VALUES (
                      :tc, :name, :description, :fields_json, 1, :created_by
                    )'
                  );
                  $insTpl->execute([
                    'tc' => $tenantCompanyId,
                    'name' => $templateName,
                    'description' => ($templateDescription !== '' ? $templateDescription : null),
                    'fields_json' => json_encode($fields, JSON_UNESCAPED_UNICODE),
                    'created_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : null),
                  ]);
                  $flash['ok'] = 'Plantilla creada correctamente.';
                }
              } catch (Throwable $e) {
                $flash['error'] = trim((string)$e->getMessage()) !== '' ? trim((string)$e->getMessage()) : 'No se pudo guardar la plantilla.';
              }
            }
          } else {
            $templateId = (int)($_POST['form_template_id'] ?? 0);
            if ($templateId > 0) {
              $delTpl = $pdo->prepare(
                'UPDATE tenant_form_templates
                    SET is_active = 0
                  WHERE id = :id AND tenant_company_id = :tc'
              );
              $delTpl->execute([
                'id' => $templateId,
                'tc' => $tenantCompanyId,
              ]);
              if ($delTpl->rowCount() > 0) {
                $flash['ok'] = 'Plantilla desactivada correctamente.';
              }
            }
          }
        }

        if ($action === 'add_service_order' || $action === 'update_service_order') {
          $module = 'ordenes-servicio';
          $isEditSO = ($action === 'update_service_order');
          $soId = (int)($_POST['service_order_id'] ?? 0);
          $soInput = [
            'customer_id' => (int)($_POST['customer_id'] ?? 0),
            'codigo' => trim((string)($_POST['codigo'] ?? '')),
            'titulo' => trim((string)($_POST['titulo'] ?? '')),
            'descripcion' => trim((string)($_POST['descripcion'] ?? '')),
            'estado' => trim((string)($_POST['estado'] ?? 'borrador')),
            'prioridad' => trim((string)($_POST['prioridad'] ?? 'normal')),
            'fecha_creacion' => trim((string)($_POST['fecha_creacion'] ?? date('Y-m-d'))),
            'observaciones' => trim((string)($_POST['observaciones'] ?? '')),
          ];
          $rawFormTemplateIds = $_POST['form_template_ids'] ?? [];
          $formTemplateIds = [];
          if (is_array($rawFormTemplateIds)) {
            foreach ($rawFormTemplateIds as $fid) {
              $intFid = (int)$fid;
              if ($intFid > 0) {
                $formTemplateIds[] = $intFid;
              }
            }
          }
          $formTemplateIds = array_values(array_unique($formTemplateIds));
          $validStates = ['borrador', 'programada', 'en_curso', 'completada', 'cancelada'];
          if (!in_array($soInput['estado'], $validStates, true)) { $soInput['estado'] = 'borrador'; }
          $validPriorities = ['baja', 'normal', 'alta', 'urgente'];
          if (!in_array($soInput['prioridad'], $validPriorities, true)) { $soInput['prioridad'] = 'normal'; }
          if ($soInput['fecha_creacion'] === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $soInput['fecha_creacion'])) {
            $soInput['fecha_creacion'] = date('Y-m-d');
          }

          $rawAssignments = $_POST['assignments'] ?? [];
          $rawParts = $_POST['parts'] ?? [];
          $rawChecklist = $_POST['checklist'] ?? [];

          $assignmentsParsed = [];
          if (is_array($rawAssignments)) {
            foreach ($rawAssignments as $rA) {
              if (!is_array($rA)) continue;
              $tId = (int)($rA['technician_id'] ?? 0);
              $wDate = trim((string)($rA['work_date'] ?? ''));
              if ($tId <= 0 || $wDate === '') continue;
              if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $wDate)) continue;
              $assignmentsParsed[] = [
                'technician_id' => $tId,
                'work_date' => $wDate,
                'start_time' => trim((string)($rA['start_time'] ?? '')),
                'end_time' => trim((string)($rA['end_time'] ?? '')),
                'notas' => trim((string)($rA['notas'] ?? '')),
              ];
            }
          }
          $partsParsed = [];
          if (is_array($rawParts)) {
            foreach ($rawParts as $rP) {
              if (!is_array($rP)) continue;
              $invId = (int)($rP['inventory_item_id'] ?? 0);
              $nombre = trim((string)($rP['nombre'] ?? ''));
              $sku = trim((string)($rP['sku'] ?? ''));
              if ($invId <= 0 && $nombre === '' && $sku === '') continue;
              $cant = inventory_number_from_input((string)($rP['cantidad'] ?? '1'));
              if ($cant <= 0) $cant = 1;
              $partsParsed[] = [
                'inventory_item_id' => ($invId > 0 ? $invId : null),
                'sku' => $sku,
                'nombre' => $nombre,
                'unidad' => trim((string)($rP['unidad'] ?? 'unidad')) ?: 'unidad',
                'cantidad' => $cant,
                'notas' => trim((string)($rP['notas'] ?? '')),
              ];
            }
          }
          $checklistParsed = [];
          if (is_array($rawChecklist)) {
            $idx = 0;
            foreach ($rawChecklist as $rC) {
              if (!is_array($rC)) continue;
              $desc = trim((string)($rC['descripcion'] ?? ''));
              if ($desc === '') continue;
              $idx++;
              $checklistParsed[] = [
                'orden' => $idx,
                'descripcion' => $desc,
                'completado' => (int)((string)($rC['completado'] ?? '0') === '1' ? 1 : 0),
              ];
            }
          }

          $serviceOrderForm = [
            'id' => (string)$soId,
            'customer_id' => (string)$soInput['customer_id'],
            'codigo' => $soInput['codigo'],
            'titulo' => $soInput['titulo'],
            'descripcion' => $soInput['descripcion'],
            'estado' => $soInput['estado'],
            'prioridad' => $soInput['prioridad'],
            'fecha_creacion' => $soInput['fecha_creacion'],
            'observaciones' => $soInput['observaciones'],
            'assignments' => array_map(static fn($a) => [
              'technician_id' => (string)$a['technician_id'],
              'work_date' => $a['work_date'],
              'start_time' => $a['start_time'],
              'end_time' => $a['end_time'],
              'notas' => $a['notas'],
            ], $assignmentsParsed),
            'parts' => array_map(static fn($p) => [
              'inventory_item_id' => $p['inventory_item_id'] !== null ? (string)$p['inventory_item_id'] : '',
              'sku' => $p['sku'],
              'nombre' => $p['nombre'],
              'unidad' => $p['unidad'],
              'cantidad' => (string)$p['cantidad'],
              'notas' => $p['notas'],
            ], $partsParsed),
            'checklist' => array_map(static fn($c) => [
              'descripcion' => $c['descripcion'],
              'completado' => (string)$c['completado'],
            ], $checklistParsed),
            'form_template_ids' => array_map(static fn($fid) => (string)$fid, $formTemplateIds),
          ];

          if ($soInput['customer_id'] <= 0) {
            $flash['error'] = 'Debes seleccionar un cliente.';
            $openServiceOrderModal = true;
          } elseif ($soInput['titulo'] === '') {
            $flash['error'] = 'El titulo de la orden es obligatorio.';
            $openServiceOrderModal = true;
          } else {
            // validacion: dias unicos dentro de la orden por par (tecnico, dia)
            $seenPair = [];
            $hasDuplicate = false;
            foreach ($assignmentsParsed as $a) {
              $k = $a['technician_id'] . '|' . $a['work_date'];
              if (isset($seenPair[$k])) { $hasDuplicate = true; break; }
              $seenPair[$k] = true;
            }
            if ($hasDuplicate) {
              $flash['error'] = 'No puedes repetir el mismo tecnico en la misma fecha dentro de la orden.';
              $openServiceOrderModal = true;
            } else {
              // validar cliente pertenece al tenant
              $stCust = $pdo->prepare('SELECT id FROM tenant_customers WHERE id = :id AND tenant_company_id = :tc AND deleted_at IS NULL LIMIT 1');
              $stCust->execute(['id' => $soInput['customer_id'], 'tc' => $tenantCompanyId]);
              if (!$stCust->fetchColumn()) {
                $flash['error'] = 'El cliente seleccionado no pertenece a tu empresa.';
                $openServiceOrderModal = true;
              } else {
                // validar tecnicos pertenecen al tenant y obtener nombres
                $techNames = [];
                if (!empty($assignmentsParsed)) {
                  $techIds = array_values(array_unique(array_map(static fn($a) => $a['technician_id'], $assignmentsParsed)));
                  $ph = implode(',', array_fill(0, count($techIds), '?'));
                  $stTech = $pdo->prepare("SELECT id, full_name FROM tenant_technicians WHERE company_id = ? AND id IN ($ph)");
                  $stTech->execute(array_merge([$tenantCompanyId], $techIds));
                  foreach ($stTech->fetchAll() as $tr) {
                    $techNames[(int)$tr['id']] = (string)$tr['full_name'];
                  }
                  $missingTech = false;
                  foreach ($techIds as $tid) {
                    if (!isset($techNames[(int)$tid])) { $missingTech = true; break; }
                  }
                  if ($missingTech) {
                    $flash['error'] = 'Uno o mas tecnicos no pertenecen a tu empresa.';
                    $openServiceOrderModal = true;
                  }
                }
                // validar choques globales (mismo tecnico, mismo dia en OTRA orden activa)
                if ($flash['error'] === '' && !empty($assignmentsParsed)) {
                  foreach ($assignmentsParsed as $a) {
                    $stClash = $pdo->prepare(
                      'SELECT sa.service_order_id, so.codigo, so.titulo
                         FROM tenant_service_order_assignments sa
                         INNER JOIN tenant_service_orders so ON so.id = sa.service_order_id AND so.deleted_at IS NULL
                        WHERE sa.tenant_company_id = :tc
                          AND sa.technician_id = :tid
                          AND sa.work_date = :wd
                          AND sa.service_order_id != :soid
                        LIMIT 1'
                    );
                    $stClash->execute([
                      'tc' => $tenantCompanyId,
                      'tid' => $a['technician_id'],
                      'wd' => $a['work_date'],
                      'soid' => ($isEditSO ? $soId : 0),
                    ]);
                    $clash = $stClash->fetch();
                    if ($clash) {
                      $techDisplay = $techNames[(int)$a['technician_id']] ?? ('ID ' . $a['technician_id']);
                      $flash['error'] = 'El tecnico ' . $techDisplay . ' ya esta asignado el ' . $a['work_date'] . ' en la orden ' . ($clash['codigo'] ?: ('#' . $clash['service_order_id'])) . '.';
                      $openServiceOrderModal = true;
                      break;
                    }
                  }
                }
                $activeTemplateMap = [];
                if ($flash['error'] === '' && !empty($formTemplateIds)) {
                  $phTpl = implode(',', array_fill(0, count($formTemplateIds), '?'));
                  $stTpl = $pdo->prepare("SELECT id FROM tenant_form_templates WHERE tenant_company_id = ? AND is_active = 1 AND id IN ($phTpl)");
                  $stTpl->execute(array_merge([$tenantCompanyId], $formTemplateIds));
                  foreach ($stTpl->fetchAll(PDO::FETCH_COLUMN) as $tplId) {
                    $activeTemplateMap[(int)$tplId] = true;
                  }
                  foreach ($formTemplateIds as $tplId) {
                    if (!isset($activeTemplateMap[(int)$tplId])) {
                      $flash['error'] = 'Una o mas plantillas seleccionadas no estan disponibles.';
                      $openServiceOrderModal = true;
                      break;
                    }
                  }
                }
                if ($flash['error'] === '') {
                  try {
                    $pdo->beginTransaction();
                    if ($isEditSO) {
                      if ($soId <= 0) { throw new RuntimeException('Orden invalida para editar.'); }
                      $stOwn = $pdo->prepare('SELECT id, codigo FROM tenant_service_orders WHERE id = :id AND tenant_company_id = :tc AND deleted_at IS NULL LIMIT 1');
                      $stOwn->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
                      $existingSo = $stOwn->fetch();
                      if (!$existingSo) { throw new RuntimeException('La orden no pertenece a tu empresa.'); }
                      // generar codigo si vacio
                      if ($soInput['codigo'] === '') { $soInput['codigo'] = (string)$existingSo['codigo']; }
                      $upSo = $pdo->prepare(
                        'UPDATE tenant_service_orders
                            SET customer_id = :customer_id,
                                codigo = :codigo,
                                titulo = :titulo,
                                descripcion = :descripcion,
                                estado = :estado,
                                prioridad = :prioridad,
                                fecha_creacion = :fecha_creacion,
                                observaciones = :observaciones
                          WHERE id = :id AND tenant_company_id = :tc'
                      );
                      $upSo->execute([
                        'customer_id' => $soInput['customer_id'],
                        'codigo' => $soInput['codigo'],
                        'titulo' => $soInput['titulo'],
                        'descripcion' => ($soInput['descripcion'] !== '' ? $soInput['descripcion'] : null),
                        'estado' => $soInput['estado'],
                        'prioridad' => $soInput['prioridad'],
                        'fecha_creacion' => $soInput['fecha_creacion'],
                        'observaciones' => ($soInput['observaciones'] !== '' ? $soInput['observaciones'] : null),
                        'id' => $soId,
                        'tc' => $tenantCompanyId,
                      ]);
                      $finalSoId = $soId;
                      // borrar hijos para reinsertar
                      $pdo->prepare('DELETE FROM tenant_service_order_assignments WHERE service_order_id = :soid AND tenant_company_id = :tc')
                        ->execute(['soid' => $finalSoId, 'tc' => $tenantCompanyId]);
                      $pdo->prepare('DELETE FROM tenant_service_order_parts WHERE service_order_id = :soid AND tenant_company_id = :tc')
                        ->execute(['soid' => $finalSoId, 'tc' => $tenantCompanyId]);
                      $pdo->prepare('DELETE FROM tenant_service_order_checklist WHERE service_order_id = :soid AND tenant_company_id = :tc')
                        ->execute(['soid' => $finalSoId, 'tc' => $tenantCompanyId]);
                      $pdo->prepare('DELETE FROM tenant_service_order_form_templates WHERE service_order_id = :soid AND tenant_company_id = :tc')
                        ->execute(['soid' => $finalSoId, 'tc' => $tenantCompanyId]);
                    } else {
                      if ($soInput['codigo'] === '') {
                        // autogenerar codigo correlativo: OS-YYYYMM-NN
                        $prefix = 'OS-' . date('Ym') . '-';
                        $stMax = $pdo->prepare(
                          "SELECT codigo FROM tenant_service_orders
                            WHERE tenant_company_id = :tc AND codigo LIKE :pfx
                            ORDER BY id DESC LIMIT 1"
                        );
                        $stMax->execute(['tc' => $tenantCompanyId, 'pfx' => $prefix . '%']);
                        $lastCode = (string)($stMax->fetchColumn() ?: '');
                        $seq = 1;
                        if ($lastCode !== '' && preg_match('/-(\d+)$/', $lastCode, $mm)) {
                          $seq = ((int)$mm[1]) + 1;
                        }
                        $soInput['codigo'] = $prefix . str_pad((string)$seq, 3, '0', STR_PAD_LEFT);
                      }
                      $insSo = $pdo->prepare(
                        'INSERT INTO tenant_service_orders (
                          tenant_company_id, customer_id, codigo, titulo, descripcion,
                          estado, prioridad, fecha_creacion, observaciones, created_by
                         ) VALUES (
                          :tc, :customer_id, :codigo, :titulo, :descripcion,
                          :estado, :prioridad, :fecha_creacion, :observaciones, :created_by
                         )'
                      );
                      $insSo->execute([
                        'tc' => $tenantCompanyId,
                        'customer_id' => $soInput['customer_id'],
                        'codigo' => $soInput['codigo'],
                        'titulo' => $soInput['titulo'],
                        'descripcion' => ($soInput['descripcion'] !== '' ? $soInput['descripcion'] : null),
                        'estado' => $soInput['estado'],
                        'prioridad' => $soInput['prioridad'],
                        'fecha_creacion' => $soInput['fecha_creacion'],
                        'observaciones' => ($soInput['observaciones'] !== '' ? $soInput['observaciones'] : null),
                        'created_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : null),
                      ]);
                      $finalSoId = (int)$pdo->lastInsertId();
                    }

                    // insertar assignments
                    if (!empty($assignmentsParsed)) {
                      $insA = $pdo->prepare(
                        'INSERT INTO tenant_service_order_assignments (
                          tenant_company_id, service_order_id, technician_id, technician_nombre,
                          work_date, start_time, end_time, notas
                         ) VALUES (
                          :tc, :soid, :tid, :tname, :wd, :st, :et, :notas
                         )'
                      );
                      foreach ($assignmentsParsed as $a) {
                        $insA->execute([
                          'tc' => $tenantCompanyId,
                          'soid' => $finalSoId,
                          'tid' => $a['technician_id'],
                          'tname' => $techNames[(int)$a['technician_id']] ?? '',
                          'wd' => $a['work_date'],
                          'st' => ($a['start_time'] !== '' ? $a['start_time'] : null),
                          'et' => ($a['end_time'] !== '' ? $a['end_time'] : null),
                          'notas' => ($a['notas'] !== '' ? $a['notas'] : null),
                        ]);
                      }
                    }

                    // insertar parts: si vienen con inventory_item_id, copiar sku/nombre/unidad del inventario
                    if (!empty($partsParsed)) {
                      $invCache = [];
                      $invIds = array_values(array_unique(array_filter(array_map(static fn($p) => $p['inventory_item_id'], $partsParsed), static fn($v) => $v !== null)));
                      if (!empty($invIds)) {
                        $phI = implode(',', array_fill(0, count($invIds), '?'));
                        $stI = $pdo->prepare("SELECT id, sku, nombre, unidad FROM tenant_inventory_items WHERE tenant_company_id = ? AND id IN ($phI)");
                        $stI->execute(array_merge([$tenantCompanyId], $invIds));
                        foreach ($stI->fetchAll() as $ir) {
                          $invCache[(int)$ir['id']] = $ir;
                        }
                      }
                      $insP = $pdo->prepare(
                        'INSERT INTO tenant_service_order_parts (
                          tenant_company_id, service_order_id, inventory_item_id, sku, nombre, unidad, cantidad, notas
                         ) VALUES (
                          :tc, :soid, :inv_id, :sku, :nombre, :unidad, :cantidad, :notas
                         )'
                      );
                      foreach ($partsParsed as $p) {
                        $invId = $p['inventory_item_id'];
                        $sku = $p['sku'];
                        $nombre = $p['nombre'];
                        $unidad = $p['unidad'];
                        if ($invId !== null && isset($invCache[(int)$invId])) {
                          $sku = (string)$invCache[(int)$invId]['sku'];
                          $nombre = (string)$invCache[(int)$invId]['nombre'];
                          $unidad = (string)$invCache[(int)$invId]['unidad'];
                        }
                        $insP->execute([
                          'tc' => $tenantCompanyId,
                          'soid' => $finalSoId,
                          'inv_id' => $invId,
                          'sku' => $sku,
                          'nombre' => $nombre,
                          'unidad' => $unidad ?: 'unidad',
                          'cantidad' => $p['cantidad'],
                          'notas' => ($p['notas'] !== '' ? $p['notas'] : null),
                        ]);
                      }
                    }

                    // insertar checklist
                    if (!empty($checklistParsed)) {
                      $insC = $pdo->prepare(
                        'INSERT INTO tenant_service_order_checklist (
                          tenant_company_id, service_order_id, orden, descripcion, completado, completado_at, completado_by
                         ) VALUES (
                          :tc, :soid, :orden, :descripcion, :completado, :cat, :cby
                         )'
                      );
                      foreach ($checklistParsed as $c) {
                        $insC->execute([
                          'tc' => $tenantCompanyId,
                          'soid' => $finalSoId,
                          'orden' => $c['orden'],
                          'descripcion' => $c['descripcion'],
                          'completado' => $c['completado'],
                          'cat' => ($c['completado'] ? date('Y-m-d H:i:s') : null),
                          'cby' => ($c['completado'] && $accountLoginEmail !== '' ? $accountLoginEmail : null),
                        ]);
                      }
                    }

                    if (!empty($formTemplateIds)) {
                      $insSoTpl = $pdo->prepare(
                        'INSERT INTO tenant_service_order_form_templates (
                          tenant_company_id, service_order_id, form_template_id, sort_order
                        ) VALUES (
                          :tc, :soid, :template_id, :sort_order
                        )'
                      );
                      foreach ($formTemplateIds as $idxTpl => $tplId) {
                        $insSoTpl->execute([
                          'tc' => $tenantCompanyId,
                          'soid' => $finalSoId,
                          'template_id' => $tplId,
                          'sort_order' => $idxTpl + 1,
                        ]);
                      }
                    }

                    $pdo->commit();
                    $flash['ok'] = $isEditSO ? 'Orden de servicio actualizada correctamente.' : 'Orden de servicio creada correctamente.';
                    $serviceOrderForm = [
                      'id' => '', 'customer_id' => '', 'codigo' => '', 'titulo' => '', 'descripcion' => '',
                      'estado' => 'borrador', 'prioridad' => 'normal', 'fecha_creacion' => date('Y-m-d'), 'observaciones' => '',
                      'assignments' => [['technician_id' => '', 'work_date' => '', 'start_time' => '', 'end_time' => '', 'notas' => '']],
                      'parts' => [['inventory_item_id' => '', 'sku' => '', 'nombre' => '', 'unidad' => 'unidad', 'cantidad' => '1', 'notas' => '']],
                      'checklist' => [['descripcion' => '', 'completado' => '0']],
                      'form_template_ids' => [],
                    ];
                  } catch (Throwable $e) {
                    if ($pdo->inTransaction()) { $pdo->rollBack(); }
                    $err = (string)$e->getMessage();
                    if (stripos($err, 'Duplicate') !== false && stripos($err, 'uq_tenant_service_orders_code') !== false) {
                      $flash['error'] = 'El codigo de orden ya existe.';
                    } else {
                      $flash['error'] = $err !== '' ? $err : 'No se pudo guardar la orden de servicio.';
                    }
                    $openServiceOrderModal = true;
                  }
                }
              }
            }
          }
        }

        if ($action === 'delete_service_order') {
          $module = 'ordenes-servicio';
          $soId = (int)($_POST['service_order_id'] ?? 0);
          if ($soId > 0) {
            $delSo = $pdo->prepare(
              'UPDATE tenant_service_orders
                  SET deleted_at = NOW(), deleted_by = :deleted_by
                WHERE id = :id AND tenant_company_id = :tc AND deleted_at IS NULL'
            );
            $delSo->execute([
              'id' => $soId,
              'tc' => $tenantCompanyId,
              'deleted_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : 'owner@local.invalid'),
            ]);
            if ($delSo->rowCount() > 0) {
              $flash['ok'] = 'Orden de servicio enviada a la papelera.';
            }
          }
        }

        if ($action === 'restore_service_order') {
          $module = 'papelera';
          $soId = (int)($_POST['service_order_id'] ?? 0);
          if ($soId > 0) {
            $stOwn = $pdo->prepare('SELECT id FROM tenant_service_orders WHERE id = :id AND tenant_company_id = :tc AND deleted_at IS NOT NULL LIMIT 1');
            $stOwn->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
            if ($stOwn->fetchColumn()) {
              $upR = $pdo->prepare('UPDATE tenant_service_orders SET deleted_at = NULL, deleted_by = NULL WHERE id = :id AND tenant_company_id = :tc');
              $upR->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
              $flash['ok'] = 'Orden restaurada desde la papelera.';
            } else {
              $flash['error'] = 'No se encontro la orden en papelera.';
            }
          }
        }

        if ($action === 'purge_service_order') {
          $module = 'papelera';
          $soId = (int)($_POST['service_order_id'] ?? 0);
          if ($soId > 0) {
            $stOwn = $pdo->prepare('SELECT id FROM tenant_service_orders WHERE id = :id AND tenant_company_id = :tc AND deleted_at IS NOT NULL LIMIT 1');
            $stOwn->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
            if ($stOwn->fetchColumn()) {
              try {
                $pdo->beginTransaction();
                $pdo->prepare('DELETE FROM tenant_service_order_assignments WHERE service_order_id = :id AND tenant_company_id = :tc')->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
                $pdo->prepare('DELETE FROM tenant_service_order_parts WHERE service_order_id = :id AND tenant_company_id = :tc')->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
                $pdo->prepare('DELETE FROM tenant_service_order_checklist WHERE service_order_id = :id AND tenant_company_id = :tc')->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
                $pdo->prepare('DELETE FROM tenant_service_order_form_templates WHERE service_order_id = :id AND tenant_company_id = :tc')->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
                $pdo->prepare('DELETE FROM tenant_service_orders WHERE id = :id AND tenant_company_id = :tc')->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
                $pdo->commit();
                $flash['ok'] = 'Orden eliminada de forma definitiva.';
              } catch (Throwable $e) {
                $pdo->rollBack();
                $flash['error'] = 'No se pudo eliminar definitivamente la orden.';
              }
            } else {
              $flash['error'] = 'No se encontro la orden en papelera.';
            }
          }
        }

        if ($action === 'toggle_service_order_checklist') {
          $module = 'ordenes-servicio';
          $clItemId = (int)($_POST['checklist_item_id'] ?? 0);
          $newState = ((string)($_POST['completado'] ?? '0') === '1') ? 1 : 0;
          if ($clItemId > 0) {
            $upC = $pdo->prepare(
              'UPDATE tenant_service_order_checklist
                  SET completado = :c,
                      completado_at = :cat,
                      completado_by = :cby
                WHERE id = :id AND tenant_company_id = :tc'
            );
            $upC->execute([
              'c' => $newState,
              'cat' => ($newState ? date('Y-m-d H:i:s') : null),
              'cby' => ($newState && $accountLoginEmail !== '' ? $accountLoginEmail : null),
              'id' => $clItemId,
              'tc' => $tenantCompanyId,
            ]);
            if ($upC->rowCount() > 0) {
              $flash['ok'] = 'Checklist actualizado.';
            }
          }
        }

        if ($action === 'save_service_order_assignments') {
          $module = 'ordenes-servicio';
          $soId = (int)($_POST['service_order_id'] ?? 0);
          $rawAssignments = $_POST['assignments'] ?? [];
          $assignmentsParsed = [];
          if (is_array($rawAssignments)) {
            foreach ($rawAssignments as $rA) {
              if (!is_array($rA)) {
                continue;
              }
              $tId = (int)($rA['technician_id'] ?? 0);
              $wDate = trim((string)($rA['work_date'] ?? ''));
              if ($tId <= 0 || $wDate === '') {
                continue;
              }
              if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $wDate)) {
                continue;
              }
              $assignmentsParsed[] = [
                'technician_id' => $tId,
                'work_date' => $wDate,
                'start_time' => trim((string)($rA['start_time'] ?? '')),
                'end_time' => trim((string)($rA['end_time'] ?? '')),
                'notas' => trim((string)($rA['notas'] ?? '')),
              ];
            }
          }

          if ($soId <= 0) {
            $flash['error'] = 'Orden de servicio invalida.';
          } else {
            $stOwnSo = $pdo->prepare('SELECT id, codigo FROM tenant_service_orders WHERE id = :id AND tenant_company_id = :tc AND deleted_at IS NULL LIMIT 1');
            $stOwnSo->execute(['id' => $soId, 'tc' => $tenantCompanyId]);
            $soRow = $stOwnSo->fetch();
            if (!$soRow) {
              $flash['error'] = 'La orden no pertenece a tu empresa o esta en papelera.';
            } else {
              $seenPair = [];
              $hasDuplicate = false;
              foreach ($assignmentsParsed as $a) {
                $k = $a['technician_id'] . '|' . $a['work_date'];
                if (isset($seenPair[$k])) {
                  $hasDuplicate = true;
                  break;
                }
                $seenPair[$k] = true;
              }

              if ($hasDuplicate) {
                $flash['error'] = 'No puedes repetir el mismo tecnico en la misma fecha dentro de la orden.';
              } else {
                $techNames = [];
                if (!empty($assignmentsParsed)) {
                  $techIds = array_values(array_unique(array_map(static fn($a) => $a['technician_id'], $assignmentsParsed)));
                  $ph = implode(',', array_fill(0, count($techIds), '?'));
                  $stTech = $pdo->prepare("SELECT id, full_name FROM tenant_technicians WHERE company_id = ? AND id IN ($ph)");
                  $stTech->execute(array_merge([$tenantCompanyId], $techIds));
                  foreach ($stTech->fetchAll() as $tr) {
                    $techNames[(int)$tr['id']] = (string)$tr['full_name'];
                  }
                  foreach ($techIds as $tid) {
                    if (!isset($techNames[(int)$tid])) {
                      $flash['error'] = 'Uno o mas tecnicos no pertenecen a tu empresa.';
                      break;
                    }
                  }
                }

                if ($flash['error'] === '' && !empty($assignmentsParsed)) {
                  foreach ($assignmentsParsed as $a) {
                    $stClash = $pdo->prepare(
                      'SELECT sa.service_order_id, so.codigo
                         FROM tenant_service_order_assignments sa
                         INNER JOIN tenant_service_orders so ON so.id = sa.service_order_id AND so.deleted_at IS NULL
                        WHERE sa.tenant_company_id = :tc
                          AND sa.technician_id = :tid
                          AND sa.work_date = :wd
                          AND sa.service_order_id != :soid
                        LIMIT 1'
                    );
                    $stClash->execute([
                      'tc' => $tenantCompanyId,
                      'tid' => $a['technician_id'],
                      'wd' => $a['work_date'],
                      'soid' => $soId,
                    ]);
                    $clash = $stClash->fetch();
                    if ($clash) {
                      $techDisplay = $techNames[(int)$a['technician_id']] ?? ('ID ' . $a['technician_id']);
                      $flash['error'] = 'El tecnico ' . $techDisplay . ' ya esta asignado el ' . $a['work_date'] . ' en la orden ' . ((string)($clash['codigo'] ?? '#'.$clash['service_order_id'])) . '.';
                      break;
                    }
                  }
                }

                if ($flash['error'] === '') {
                  try {
                    $pdo->beginTransaction();
                    $pdo->prepare('DELETE FROM tenant_service_order_assignments WHERE service_order_id = :soid AND tenant_company_id = :tc')
                      ->execute(['soid' => $soId, 'tc' => $tenantCompanyId]);

                    if (!empty($assignmentsParsed)) {
                      $insA = $pdo->prepare(
                        'INSERT INTO tenant_service_order_assignments (
                          tenant_company_id, service_order_id, technician_id, technician_nombre,
                          work_date, start_time, end_time, notas
                         ) VALUES (
                          :tc, :soid, :tid, :tname, :wd, :st, :et, :notas
                         )'
                      );
                      foreach ($assignmentsParsed as $a) {
                        $insA->execute([
                          'tc' => $tenantCompanyId,
                          'soid' => $soId,
                          'tid' => $a['technician_id'],
                          'tname' => $techNames[(int)$a['technician_id']] ?? '',
                          'wd' => $a['work_date'],
                          'st' => ($a['start_time'] !== '' ? $a['start_time'] : null),
                          'et' => ($a['end_time'] !== '' ? $a['end_time'] : null),
                          'notas' => ($a['notas'] !== '' ? $a['notas'] : null),
                        ]);
                      }
                    }

                    $pdo->commit();
                    $flash['ok'] = 'Asignaciones de la orden actualizadas correctamente.';
                  } catch (Throwable $e) {
                    if ($pdo->inTransaction()) {
                      $pdo->rollBack();
                    }
                    $flash['error'] = 'No se pudieron actualizar las asignaciones.';
                  }
                }
              }
            }
          }
        }

        if ($action === 'add_service_report' || $action === 'update_service_report') {
          $module = 'reportes';
          $openServiceReportModal = true;
          $isEditServiceReport = ($action === 'update_service_report');
          $canUseReportForms = in_array(normalize_plan_code((string)$usage['plan_code'], 'basico'), ['pro', 'enterprise', 'olimpico'], true);
          $rawFormsNoteRequest = trim((string)($_POST['forms_note'] ?? ''));
          $rawFormsPayloadRequest = trim((string)($_POST['forms_payload_json'] ?? '[]'));
          $formsPayload = ($canUseReportForms ? service_form_response_payload_normalize($rawFormsPayloadRequest) : []);
          $reportIdRaw = trim((string)($_POST['report_id'] ?? ''));
          $technicianSignName = trim((string)($_POST['technician_sign_name'] ?? ''));
          $technicianSignRut = trim((string)($_POST['technician_sign_rut'] ?? ''));
          $customerSignName = trim((string)($_POST['customer_sign_name'] ?? ''));
          $customerSignRut = trim((string)($_POST['customer_sign_rut'] ?? ''));
          $technicianSignatureData = trim((string)($_POST['technician_signature_data'] ?? ''));
          $customerSignatureData = trim((string)($_POST['customer_signature_data'] ?? ''));
          $technicianSignatureExisting = trim((string)($_POST['technician_signature_existing'] ?? ''));
          $customerSignatureExisting = trim((string)($_POST['customer_signature_existing'] ?? ''));

          $serviceReportForm = [
            'report_id' => $reportIdRaw,
            'service_order_id' => (string)((int)($_POST['service_order_id'] ?? 0)),
            'technician_id' => (string)((int)($_POST['technician_id'] ?? 0)),
            'report_date' => trim((string)($_POST['report_date'] ?? date('Y-m-d'))),
            'work_done' => trim((string)($_POST['work_done'] ?? '')),
            'external_purchases' => trim((string)($_POST['external_purchases'] ?? '')),
            'observations' => trim((string)($_POST['observations'] ?? '')),
            'additional_details' => trim((string)($_POST['additional_details'] ?? '')),
            'technician_sign_name' => $technicianSignName,
            'technician_sign_rut' => $technicianSignRut,
            'customer_sign_name' => $customerSignName,
            'customer_sign_rut' => $customerSignRut,
            'technician_signature_draw' => $technicianSignatureExisting,
            'customer_signature_draw' => $customerSignatureExisting,
            'technician_signature' => service_report_signature_encode($technicianSignName, $technicianSignRut),
            'customer_signature' => service_report_signature_encode($customerSignName, $customerSignRut),
            'forms_note' => ($canUseReportForms ? trim((string)($_POST['forms_note'] ?? '')) : ''),
            'forms_payload_json' => json_encode($formsPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
          ];

          $reportSoId = (int)$serviceReportForm['service_order_id'];
          $reportTechId = (int)$serviceReportForm['technician_id'];

          if ($isEditServiceReport && $reportIdRaw === '') {
            $flash['error'] = 'Reporte invalido para editar.';
          } elseif ($reportSoId <= 0) {
            $flash['error'] = 'Debes seleccionar una OS asociada.';
          } elseif ($reportTechId <= 0) {
            $flash['error'] = 'Debes seleccionar un tecnico.';
          } elseif ($serviceReportForm['report_date'] === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $serviceReportForm['report_date'])) {
            $flash['error'] = 'La fecha del reporte no es valida.';
          } elseif ($serviceReportForm['work_done'] === '') {
            $flash['error'] = 'Debes completar el trabajo realizado.';
          } elseif ($serviceReportForm['technician_sign_name'] === '' || $serviceReportForm['technician_sign_rut'] === '') {
            $flash['error'] = 'Debes registrar nombre y RUT del tecnico.';
          } elseif ($serviceReportForm['customer_sign_name'] === '' || $serviceReportForm['customer_sign_rut'] === '') {
            $flash['error'] = 'Debes registrar nombre y RUT del cliente que recepciona.';
          } elseif (!$canUseReportForms && $rawFormsNoteRequest !== '') {
            $flash['error'] = 'Tu plan actual no habilita el modulo de Formularios en reportes.';
          } elseif ($technicianSignatureData === '' && $serviceReportForm['technician_signature_draw'] === '') {
            $flash['error'] = 'Debes dibujar la firma digital del tecnico.';
          } elseif ($customerSignatureData === '' && $serviceReportForm['customer_signature_draw'] === '') {
            $flash['error'] = 'Debes dibujar la firma digital del cliente.';
          } else {
            $stSoOwn = $pdo->prepare('SELECT id FROM tenant_service_orders WHERE id = :id AND tenant_company_id = :tc AND deleted_at IS NULL LIMIT 1');
            $stSoOwn->execute(['id' => $reportSoId, 'tc' => $tenantCompanyId]);
            $ownedSo = $stSoOwn->fetchColumn();

            if (!$ownedSo) {
              $flash['error'] = 'La OS seleccionada no existe o no pertenece a tu empresa.';
            } else {
              $stAsgOwn = $pdo->prepare(
                'SELECT 1
                   FROM tenant_service_order_assignments
                  WHERE tenant_company_id = :tc
                    AND service_order_id = :so
                    AND technician_id = :tech
                  LIMIT 1'
              );
              $stAsgOwn->execute([
                'tc' => $tenantCompanyId,
                'so' => $reportSoId,
                'tech' => $reportTechId,
              ]);

              if (!$stAsgOwn->fetchColumn()) {
                $flash['error'] = 'El tecnico solo puede reportar OS que tenga asignadas.';
              } else {
                try {
                  $existingPhotoRecords = [];
                  $existingFormPhotoRecords = [];
                  $storedTechnicianSignatureDraw = $serviceReportForm['technician_signature_draw'];
                  $storedCustomerSignatureDraw = $serviceReportForm['customer_signature_draw'];
                  if ($isEditServiceReport) {
                    if (table_exists($pdo, 'tenant_service_reports')) {
                      $reportId = (int)$reportIdRaw;
                      if ($reportId <= 0) {
                        throw new RuntimeException('Reporte invalido para editar.');
                      }
                      $stOwnReport = $pdo->prepare(
                        'SELECT id, photo_records, form_photo_records, technician_signature_draw, customer_signature_draw
                           FROM tenant_service_reports
                          WHERE id = :id
                            AND tenant_company_id = :tc
                          LIMIT 1'
                      );
                      $stOwnReport->execute([
                        'id' => $reportId,
                        'tc' => $tenantCompanyId,
                      ]);
                      $ownReport = $stOwnReport->fetch();
                      if (!$ownReport) {
                        throw new RuntimeException('El reporte no pertenece a tu empresa.');
                      }
                      $existingPhotoRecords = service_report_photo_records_normalize($ownReport['photo_records'] ?? null);
                      $existingFormPhotoRecords = service_report_photo_records_normalize($ownReport['form_photo_records'] ?? null);
                      $storedTechnicianSignatureDraw = trim((string)($ownReport['technician_signature_draw'] ?? ''));
                      $storedCustomerSignatureDraw = trim((string)($ownReport['customer_signature_draw'] ?? ''));
                    } else {
                      $fallbackOwn = service_reports_fallback_find($tenantCompanyId, $reportIdRaw);
                      if (!is_array($fallbackOwn)) {
                        throw new RuntimeException('No se encontro el reporte para editar.');
                      }
                      $existingPhotoRecords = service_report_photo_records_normalize($fallbackOwn['photo_records'] ?? null);
                      $existingFormPhotoRecords = service_report_photo_records_normalize($fallbackOwn['form_photo_records'] ?? null);
                      $storedTechnicianSignatureDraw = trim((string)($fallbackOwn['technician_signature_draw'] ?? ''));
                      $storedCustomerSignatureDraw = trim((string)($fallbackOwn['customer_signature_draw'] ?? ''));
                    }
                  }

                  $finalTechnicianSignatureDraw = $storedTechnicianSignatureDraw;
                  if ($technicianSignatureData !== '') {
                    $newTechSignaturePath = store_service_report_signature_drawing(
                      $technicianSignatureData,
                      $tenantCompanyId,
                      $reportSoId,
                      $reportTechId,
                      'technician'
                    );
                    if ($newTechSignaturePath !== '') {
                      if ($storedTechnicianSignatureDraw !== '' && $storedTechnicianSignatureDraw !== $newTechSignaturePath) {
                        service_report_delete_photo_file($storedTechnicianSignatureDraw);
                      }
                      $finalTechnicianSignatureDraw = $newTechSignaturePath;
                    }
                  }

                  $finalCustomerSignatureDraw = $storedCustomerSignatureDraw;
                  if ($customerSignatureData !== '') {
                    $newCustomerSignaturePath = store_service_report_signature_drawing(
                      $customerSignatureData,
                      $tenantCompanyId,
                      $reportSoId,
                      $reportTechId,
                      'customer'
                    );
                    if ($newCustomerSignaturePath !== '') {
                      if ($storedCustomerSignatureDraw !== '' && $storedCustomerSignatureDraw !== $newCustomerSignaturePath) {
                        service_report_delete_photo_file($storedCustomerSignatureDraw);
                      }
                      $finalCustomerSignatureDraw = $newCustomerSignaturePath;
                    }
                  }

                  if ($finalTechnicianSignatureDraw === '') {
                    throw new RuntimeException('Debes dibujar la firma digital del tecnico.');
                  }
                  if ($finalCustomerSignatureDraw === '') {
                    throw new RuntimeException('Debes dibujar la firma digital del cliente que recepciona.');
                  }

                  $serviceReportForm['technician_signature_draw'] = $finalTechnicianSignatureDraw;
                  $serviceReportForm['customer_signature_draw'] = $finalCustomerSignatureDraw;

                  $keptExistingPhotoRecords = $existingPhotoRecords;
                  if ($isEditServiceReport) {
                    $rawExistingJson = trim((string)($_POST['existing_photos_json'] ?? ''));
                    $postedExisting = [];
                    if ($rawExistingJson !== '') {
                      $decodedExisting = json_decode($rawExistingJson, true);
                      if (!is_array($decodedExisting)) {
                        throw new RuntimeException('Formato invalido en fotos existentes del reporte.');
                      }
                      $postedExisting = $decodedExisting;
                    }

                    $existingByPath = [];
                    foreach ($existingPhotoRecords as $row) {
                      $pathKey = trim((string)($row['path'] ?? ''));
                      if ($pathKey === '') {
                        continue;
                      }
                      $existingByPath[$pathKey] = $row;
                    }

                    $keptExistingPhotoRecords = [];
                    foreach ($postedExisting as $postedRow) {
                      if (!is_array($postedRow)) {
                        continue;
                      }
                      $postedPath = trim((string)($postedRow['path'] ?? ''));
                      if ($postedPath === '' || !isset($existingByPath[$postedPath])) {
                        continue;
                      }
                      $base = $existingByPath[$postedPath];
                      $newName = trim((string)($postedRow['name'] ?? ''));
                      if ($newName === '') {
                        $newName = trim((string)($base['name'] ?? ''));
                      }
                      $keptExistingPhotoRecords[] = [
                        'path' => $postedPath,
                        'name' => $newName,
                        'size' => (int)($base['size'] ?? 0),
                        'uploaded_at' => (string)($base['uploaded_at'] ?? ''),
                      ];
                    }

                    $keptMap = [];
                    foreach ($keptExistingPhotoRecords as $keptRow) {
                      $p = trim((string)($keptRow['path'] ?? ''));
                      if ($p !== '') {
                        $keptMap[$p] = true;
                      }
                    }
                    foreach ($existingPhotoRecords as $oldRow) {
                      $oldPath = trim((string)($oldRow['path'] ?? ''));
                      if ($oldPath === '' || isset($keptMap[$oldPath])) {
                        continue;
                      }
                      service_report_delete_photo_file($oldPath);
                    }
                  }

                  $uploadedPhotos = service_report_collect_uploaded_photos(
                    $_FILES['report_photos'] ?? null,
                    $tenantCompanyId,
                    $reportSoId,
                    $reportTechId
                  );
                  $finalPhotoRecords = array_values(array_merge($keptExistingPhotoRecords, $uploadedPhotos));

                  $keptExistingFormPhotoRecords = $existingFormPhotoRecords;
                  if ($isEditServiceReport) {
                    $rawExistingFormsJson = trim((string)($_POST['existing_form_photos_json'] ?? ''));
                    if ($rawExistingFormsJson !== '') {
                      $decodedFormExisting = json_decode($rawExistingFormsJson, true);
                      if (!is_array($decodedFormExisting)) {
                        throw new RuntimeException('Formato invalido en imagenes de formularios existentes.');
                      }
                      $existingFormByPath = [];
                      foreach ($existingFormPhotoRecords as $row) {
                        $pathKey = trim((string)($row['path'] ?? ''));
                        if ($pathKey !== '') {
                          $existingFormByPath[$pathKey] = $row;
                        }
                      }
                      $keptExistingFormPhotoRecords = [];
                      foreach ($decodedFormExisting as $postedRow) {
                        if (!is_array($postedRow)) {
                          continue;
                        }
                        $postedPath = trim((string)($postedRow['path'] ?? ''));
                        if ($postedPath === '' || !isset($existingFormByPath[$postedPath])) {
                          continue;
                        }
                        $base = $existingFormByPath[$postedPath];
                        $keptExistingFormPhotoRecords[] = [
                          'path' => $postedPath,
                          'name' => trim((string)($base['name'] ?? '')),
                          'size' => (int)($base['size'] ?? 0),
                          'uploaded_at' => (string)($base['uploaded_at'] ?? ''),
                          'template_id' => (int)($base['template_id'] ?? 0),
                          'field_key' => (string)($base['field_key'] ?? ''),
                        ];
                      }

                      $keptFormMap = [];
                      foreach ($keptExistingFormPhotoRecords as $keptRow) {
                        $kPath = trim((string)($keptRow['path'] ?? ''));
                        if ($kPath !== '') {
                          $keptFormMap[$kPath] = true;
                        }
                      }
                      foreach ($existingFormPhotoRecords as $oldRow) {
                        $oldPath = trim((string)($oldRow['path'] ?? ''));
                        if ($oldPath === '' || isset($keptFormMap[$oldPath])) {
                          continue;
                        }
                        service_report_delete_photo_file($oldPath);
                      }
                    }
                  }

                  $uploadedFormPhotos = service_report_collect_uploaded_form_photos(
                    $_FILES['form_images'] ?? null,
                    $tenantCompanyId,
                    $reportSoId,
                    $reportTechId
                  );
                  $finalFormPhotoRecords = array_values(array_merge($keptExistingFormPhotoRecords, $uploadedFormPhotos));

                  if (table_exists($pdo, 'tenant_service_reports')) {
                    if ($isEditServiceReport) {
                      $reportId = (int)$reportIdRaw;
                      $upReport = $pdo->prepare(
                        'UPDATE tenant_service_reports
                            SET service_order_id = :so,
                                technician_id = :tech,
                                report_date = :rdate,
                                work_done = :work_done,
                                external_purchases = :external_purchases,
                                observations = :observations,
                                additional_details = :additional_details,
                                forms_note = :forms_note,
                                forms_payload = :forms_payload,
                                photo_records = :photo_records,
                                form_photo_records = :form_photo_records,
                                technician_signature = :technician_signature,
                                customer_signature = :customer_signature,
                                technician_signature_draw = :technician_signature_draw,
                                customer_signature_draw = :customer_signature_draw,
                                created_by = :created_by
                          WHERE id = :id
                            AND tenant_company_id = :tc'
                      );
                      $upReport->execute([
                        'so' => $reportSoId,
                        'tech' => $reportTechId,
                        'rdate' => $serviceReportForm['report_date'],
                        'work_done' => $serviceReportForm['work_done'],
                        'external_purchases' => ($serviceReportForm['external_purchases'] !== '' ? $serviceReportForm['external_purchases'] : null),
                        'observations' => ($serviceReportForm['observations'] !== '' ? $serviceReportForm['observations'] : null),
                        'additional_details' => ($serviceReportForm['additional_details'] !== '' ? $serviceReportForm['additional_details'] : null),
                        'forms_note' => ($serviceReportForm['forms_note'] !== '' ? $serviceReportForm['forms_note'] : null),
                        'forms_payload' => (!empty($formsPayload) ? json_encode($formsPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null),
                        'photo_records' => (!empty($finalPhotoRecords) ? json_encode($finalPhotoRecords, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null),
                        'form_photo_records' => (!empty($finalFormPhotoRecords) ? json_encode($finalFormPhotoRecords, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null),
                        'technician_signature' => $serviceReportForm['technician_signature'],
                        'customer_signature' => $serviceReportForm['customer_signature'],
                        'technician_signature_draw' => ($serviceReportForm['technician_signature_draw'] !== '' ? $serviceReportForm['technician_signature_draw'] : null),
                        'customer_signature_draw' => ($serviceReportForm['customer_signature_draw'] !== '' ? $serviceReportForm['customer_signature_draw'] : null),
                        'created_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : null),
                        'id' => $reportId,
                        'tc' => $tenantCompanyId,
                      ]);
                    } else {
                      $insReport = $pdo->prepare(
                        'INSERT INTO tenant_service_reports (
                          tenant_company_id, service_order_id, technician_id, report_date,
                          work_done, external_purchases, observations, additional_details,
                          forms_note, forms_payload, photo_records, form_photo_records, technician_signature, customer_signature,
                          technician_signature_draw, customer_signature_draw, created_by
                        ) VALUES (
                          :tc, :so, :tech, :rdate,
                          :work_done, :external_purchases, :observations, :additional_details,
                          :forms_note, :forms_payload, :photo_records, :form_photo_records, :technician_signature, :customer_signature,
                          :technician_signature_draw, :customer_signature_draw, :created_by
                        )'
                      );
                      $insReport->execute([
                        'tc' => $tenantCompanyId,
                        'so' => $reportSoId,
                        'tech' => $reportTechId,
                        'rdate' => $serviceReportForm['report_date'],
                        'work_done' => $serviceReportForm['work_done'],
                        'external_purchases' => ($serviceReportForm['external_purchases'] !== '' ? $serviceReportForm['external_purchases'] : null),
                        'observations' => ($serviceReportForm['observations'] !== '' ? $serviceReportForm['observations'] : null),
                        'additional_details' => ($serviceReportForm['additional_details'] !== '' ? $serviceReportForm['additional_details'] : null),
                        'forms_note' => ($serviceReportForm['forms_note'] !== '' ? $serviceReportForm['forms_note'] : null),
                        'forms_payload' => (!empty($formsPayload) ? json_encode($formsPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null),
                        'photo_records' => (!empty($finalPhotoRecords) ? json_encode($finalPhotoRecords, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null),
                        'form_photo_records' => (!empty($finalFormPhotoRecords) ? json_encode($finalFormPhotoRecords, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null),
                        'technician_signature' => $serviceReportForm['technician_signature'],
                        'customer_signature' => $serviceReportForm['customer_signature'],
                        'technician_signature_draw' => ($serviceReportForm['technician_signature_draw'] !== '' ? $serviceReportForm['technician_signature_draw'] : null),
                        'customer_signature_draw' => ($serviceReportForm['customer_signature_draw'] !== '' ? $serviceReportForm['customer_signature_draw'] : null),
                        'created_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : null),
                      ]);
                    }
                  } else {
                    if ($isEditServiceReport) {
                      $updatedFallback = service_reports_fallback_update($tenantCompanyId, $reportIdRaw, [
                        'service_order_id' => $reportSoId,
                        'technician_id' => $reportTechId,
                        'report_date' => $serviceReportForm['report_date'],
                        'work_done' => $serviceReportForm['work_done'],
                        'external_purchases' => $serviceReportForm['external_purchases'],
                        'observations' => $serviceReportForm['observations'],
                        'additional_details' => $serviceReportForm['additional_details'],
                        'forms_note' => $serviceReportForm['forms_note'],
                        'forms_payload' => $formsPayload,
                        'photo_records' => $finalPhotoRecords,
                        'form_photo_records' => $finalFormPhotoRecords,
                        'technician_signature' => $serviceReportForm['technician_signature'],
                        'customer_signature' => $serviceReportForm['customer_signature'],
                        'technician_signature_draw' => $serviceReportForm['technician_signature_draw'],
                        'customer_signature_draw' => $serviceReportForm['customer_signature_draw'],
                        'created_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : null),
                      ]);
                      if (!$updatedFallback) {
                        throw new RuntimeException('No se encontro el reporte para actualizar.');
                      }
                    } else {
                      service_reports_fallback_append($tenantCompanyId, [
                        'id' => 'fb_' . date('YmdHis') . '_' . bin2hex(random_bytes(4)),
                        'service_order_id' => $reportSoId,
                        'technician_id' => $reportTechId,
                        'report_date' => $serviceReportForm['report_date'],
                        'work_done' => $serviceReportForm['work_done'],
                        'external_purchases' => $serviceReportForm['external_purchases'],
                        'observations' => $serviceReportForm['observations'],
                        'additional_details' => $serviceReportForm['additional_details'],
                        'forms_note' => $serviceReportForm['forms_note'],
                        'forms_payload' => $formsPayload,
                        'photo_records' => $finalPhotoRecords,
                        'form_photo_records' => $finalFormPhotoRecords,
                        'technician_signature' => $serviceReportForm['technician_signature'],
                        'customer_signature' => $serviceReportForm['customer_signature'],
                        'technician_signature_draw' => $serviceReportForm['technician_signature_draw'],
                        'customer_signature_draw' => $serviceReportForm['customer_signature_draw'],
                        'created_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : null),
                        'created_at' => date('Y-m-d H:i:s'),
                      ]);
                    }
                  }

                  $flash['ok'] = $isEditServiceReport ? 'Reporte actualizado correctamente.' : 'Reporte registrado correctamente.';
                  $openServiceReportModal = false;
                  $serviceReportForm = [
                    'report_id' => '',
                    'service_order_id' => '',
                    'technician_id' => '',
                    'report_date' => date('Y-m-d'),
                    'work_done' => '',
                    'external_purchases' => '',
                    'observations' => '',
                    'additional_details' => '',
                    'technician_sign_name' => '',
                    'technician_sign_rut' => '',
                    'customer_sign_name' => '',
                    'customer_sign_rut' => '',
                    'technician_signature_draw' => '',
                    'customer_signature_draw' => '',
                    'technician_signature' => '',
                    'customer_signature' => '',
                    'forms_note' => '',
                    'forms_payload_json' => '[]',
                  ];
                } catch (Throwable $reportErr) {
                  $msg = trim((string)$reportErr->getMessage());
                  $flash['error'] = ($msg !== '' ? $msg : 'No se pudo registrar el reporte.');
                }
              }
            }
          }
        }

        if ($action === 'delete_service_report' || $action === 'move_service_report_to_trash') {
          $module = 'reportes';
          $reportIdRaw = trim((string)($_POST['report_id'] ?? ''));
          if ($reportIdRaw === '') {
            $flash['error'] = 'Reporte invalido para mover a papelera.';
          } else {
            try {
              if (table_exists($pdo, 'tenant_service_reports')) {
                $reportId = (int)$reportIdRaw;
                if ($reportId <= 0) {
                  throw new RuntimeException('Reporte invalido para mover a papelera.');
                }

                $moveReport = $pdo->prepare(
                  'UPDATE tenant_service_reports
                      SET deleted_at = NOW(), deleted_by = :deleted_by
                    WHERE id = :id
                      AND tenant_company_id = :tc
                      AND deleted_at IS NULL'
                );
                $moveReport->execute([
                  'id' => $reportId,
                  'tc' => $tenantCompanyId,
                  'deleted_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : 'owner@local.invalid'),
                ]);
                if ($moveReport->rowCount() <= 0) {
                  throw new RuntimeException('No se encontro el reporte para mover a papelera.');
                }
              } else {
                $updatedFallback = service_reports_fallback_update($tenantCompanyId, $reportIdRaw, [
                  'deleted_at' => date('Y-m-d H:i:s'),
                  'deleted_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : 'owner@local.invalid'),
                ]);
                if (!$updatedFallback) {
                  throw new RuntimeException('No se encontro el reporte para mover a papelera.');
                }
              }

              $flash['ok'] = 'Reporte enviado a la papelera.';
            } catch (Throwable $deleteReportErr) {
              $msg = trim((string)$deleteReportErr->getMessage());
              $flash['error'] = ($msg !== '' ? $msg : 'No se pudo mover el reporte a papelera.');
            }
          }
        }

        if ($action === 'restore_service_report') {
          $module = 'papelera';
          $reportIdRaw = trim((string)($_POST['report_id'] ?? ''));
          if ($reportIdRaw === '') {
            $flash['error'] = 'Reporte invalido para restaurar.';
          } else {
            try {
              if (table_exists($pdo, 'tenant_service_reports')) {
                $reportId = (int)$reportIdRaw;
                if ($reportId <= 0) {
                  throw new RuntimeException('Reporte invalido para restaurar.');
                }
                $restoreReport = $pdo->prepare(
                  'UPDATE tenant_service_reports
                      SET deleted_at = NULL, deleted_by = NULL
                    WHERE id = :id
                      AND tenant_company_id = :tc
                      AND deleted_at IS NOT NULL'
                );
                $restoreReport->execute([
                  'id' => $reportId,
                  'tc' => $tenantCompanyId,
                ]);
                if ($restoreReport->rowCount() <= 0) {
                  throw new RuntimeException('No se encontro el reporte en papelera para restaurar.');
                }
              } else {
                $updatedFallback = service_reports_fallback_update($tenantCompanyId, $reportIdRaw, [
                  'deleted_at' => null,
                  'deleted_by' => null,
                ]);
                if (!$updatedFallback) {
                  throw new RuntimeException('No se encontro el reporte en papelera para restaurar.');
                }
              }

              $flash['ok'] = 'Reporte restaurado desde la papelera.';
            } catch (Throwable $restoreReportErr) {
              $msg = trim((string)$restoreReportErr->getMessage());
              $flash['error'] = ($msg !== '' ? $msg : 'No se pudo restaurar el reporte.');
            }
          }
        }

        if ($action === 'purge_service_report') {
          $module = 'papelera';
          $reportIdRaw = trim((string)($_POST['report_id'] ?? ''));
          if ($reportIdRaw === '') {
            $flash['error'] = 'Reporte invalido para eliminar definitivamente.';
          } else {
            try {
              $photoRecordsToDelete = [];
              $formPhotoRecordsToDelete = [];
              if (table_exists($pdo, 'tenant_service_reports')) {
                $reportId = (int)$reportIdRaw;
                if ($reportId <= 0) {
                  throw new RuntimeException('Reporte invalido para eliminar definitivamente.');
                }

                $stReport = $pdo->prepare(
                  'SELECT id, photo_records, form_photo_records
                     FROM tenant_service_reports
                    WHERE id = :id
                      AND tenant_company_id = :tc
                      AND deleted_at IS NOT NULL
                    LIMIT 1'
                );
                $stReport->execute([
                  'id' => $reportId,
                  'tc' => $tenantCompanyId,
                ]);
                $reportRow = $stReport->fetch();
                if (!$reportRow) {
                  throw new RuntimeException('No se encontro el reporte en papelera para eliminar.');
                }

                $photoRecordsToDelete = service_report_photo_records_normalize($reportRow['photo_records'] ?? null);
                $formPhotoRecordsToDelete = service_report_photo_records_normalize($reportRow['form_photo_records'] ?? null);

                $delReport = $pdo->prepare(
                  'DELETE FROM tenant_service_reports
                    WHERE id = :id
                      AND tenant_company_id = :tc
                      AND deleted_at IS NOT NULL
                    LIMIT 1'
                );
                $delReport->execute([
                  'id' => $reportId,
                  'tc' => $tenantCompanyId,
                ]);
                if ($delReport->rowCount() <= 0) {
                  throw new RuntimeException('No se pudo eliminar definitivamente el reporte.');
                }
              } else {
                $fallbackOwn = service_reports_fallback_find($tenantCompanyId, $reportIdRaw);
                if (!is_array($fallbackOwn) || trim((string)($fallbackOwn['deleted_at'] ?? '')) === '') {
                  throw new RuntimeException('No se encontro el reporte en papelera para eliminar.');
                }
                $photoRecordsToDelete = service_report_photo_records_normalize($fallbackOwn['photo_records'] ?? null);
                $formPhotoRecordsToDelete = service_report_photo_records_normalize($fallbackOwn['form_photo_records'] ?? null);
                $deletedFallback = service_reports_fallback_delete($tenantCompanyId, $reportIdRaw);
                if (!is_array($deletedFallback)) {
                  throw new RuntimeException('No se pudo eliminar definitivamente el reporte.');
                }
              }

              foreach ($photoRecordsToDelete as $photoRow) {
                $photoPath = trim((string)($photoRow['path'] ?? ''));
                if ($photoPath !== '') {
                  service_report_delete_photo_file($photoPath);
                }
              }
              foreach ($formPhotoRecordsToDelete as $photoRow) {
                $photoPath = trim((string)($photoRow['path'] ?? ''));
                if ($photoPath !== '') {
                  service_report_delete_photo_file($photoPath);
                }
              }

              $flash['ok'] = 'Reporte eliminado de forma definitiva.';
            } catch (Throwable $deleteReportErr) {
              $msg = trim((string)$deleteReportErr->getMessage());
              $flash['error'] = ($msg !== '' ? $msg : 'No se pudo eliminar definitivamente el reporte.');
            }
          }
        }

        if ($action === 'add_inventory_movement') {
          $module = 'inventario';
          $inventoryMoveForm = [
            'item_id' => (string)((int)($_POST['movement_item_id'] ?? 0)),
            'tipo' => inventory_type_normalize((string)($_POST['movement_tipo'] ?? 'entrada')),
            'cantidad' => trim((string)($_POST['movement_cantidad'] ?? '1')),
            'motivo' => trim((string)($_POST['movement_motivo'] ?? '')),
          ];

          $movementItemId = (int)$inventoryMoveForm['item_id'];
          $movementType = inventory_type_normalize($inventoryMoveForm['tipo']);
          $movementQty = inventory_number_from_input($inventoryMoveForm['cantidad']);
          $movementReason = trim((string)$inventoryMoveForm['motivo']);

          if ($movementItemId <= 0) {
            $flash['error'] = 'Debes seleccionar un item de inventario.';
            $openInventoryMoveModal = true;
          } elseif ($movementQty <= 0) {
            $flash['error'] = 'La cantidad del movimiento debe ser mayor a cero.';
            $openInventoryMoveModal = true;
          } elseif ($movementReason === '') {
            $flash['error'] = 'Debes indicar un motivo para la entrada/salida.';
            $openInventoryMoveModal = true;
          } else {
            try {
              $pdo->beginTransaction();

              $stItem = $pdo->prepare(
                'SELECT id, sku, nombre, unidad, stock_actual
                   FROM tenant_inventory_items
                  WHERE id = :id
                    AND tenant_company_id = :tenant_company_id
                    AND deleted_at IS NULL
                  LIMIT 1'
              );
              $stItem->execute([
                'id' => $movementItemId,
                'tenant_company_id' => $tenantCompanyId,
              ]);
              $itemRow = $stItem->fetch();
              if (!$itemRow) {
                throw new RuntimeException('El item seleccionado no pertenece a tu empresa.');
              }

              $stockBefore = (float)$itemRow['stock_actual'];
              $stockAfter = ($movementType === 'entrada')
                ? ($stockBefore + $movementQty)
                : ($stockBefore - $movementQty);

              if ($stockAfter < 0) {
                throw new RuntimeException('La salida supera el stock disponible.');
              }

              $upStock = $pdo->prepare(
                'UPDATE tenant_inventory_items
                    SET stock_actual = :stock_actual
                  WHERE id = :id
                    AND tenant_company_id = :tenant_company_id
                    AND deleted_at IS NULL'
              );
              $upStock->execute([
                'stock_actual' => $stockAfter,
                'id' => $movementItemId,
                'tenant_company_id' => $tenantCompanyId,
              ]);

              $insMovement = $pdo->prepare(
                'INSERT INTO tenant_inventory_movements (
                  tenant_company_id, item_id, item_sku, item_nombre, item_unidad,
                  tipo, cantidad, motivo, stock_anterior, stock_nuevo, created_by
                 ) VALUES (
                  :tenant_company_id, :item_id, :item_sku, :item_nombre, :item_unidad,
                  :tipo, :cantidad, :motivo, :stock_anterior, :stock_nuevo, :created_by
                 )'
              );
              $insMovement->execute([
                'tenant_company_id' => $tenantCompanyId,
                'item_id' => $movementItemId,
                'item_sku' => (string)$itemRow['sku'],
                'item_nombre' => (string)$itemRow['nombre'],
                'item_unidad' => (string)$itemRow['unidad'],
                'tipo' => $movementType,
                'cantidad' => $movementQty,
                'motivo' => $movementReason,
                'stock_anterior' => $stockBefore,
                'stock_nuevo' => $stockAfter,
                'created_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : null),
              ]);

              $pdo->commit();
              $flash['ok'] = 'Movimiento registrado correctamente.';
              $inventoryMoveForm = [
                'item_id' => '',
                'tipo' => 'entrada',
                'cantidad' => '1',
                'motivo' => '',
              ];
            } catch (Throwable $e) {
              if ($pdo->inTransaction()) {
                $pdo->rollBack();
              }
              $err = trim((string)$e->getMessage());
              $flash['error'] = ($err !== '' ? $err : 'No se pudo registrar el movimiento de inventario.');
              $openInventoryMoveModal = true;
            }
          }
        }

        if ($action === 'delete_customer' || $action === 'move_customer_to_trash') {
            $customerId = (int)($_POST['customer_id'] ?? 0);
            if ($customerId > 0) {
                $toTrash = $pdo->prepare(
                  'UPDATE tenant_customers
                   SET deleted_at = NOW(), deleted_by = :deleted_by, estado = 0, is_active = 0
                   WHERE id = :id
                     AND tenant_company_id = :tenant_company_id
                     AND deleted_at IS NULL'
                );
                $toTrash->execute([
                  'id' => $customerId,
                  'tenant_company_id' => $tenantCompanyId,
                  'deleted_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : 'owner@local.invalid'),
                ]);
                if ($toTrash->rowCount() > 0) {
                  $flash['ok'] = 'Cliente movido a papelera.';
                }
            }
            $module = 'clientes';
        }

        if ($action === 'delete_quote' || $action === 'move_quote_to_trash') {
          $module = 'cotizaciones';
          $quoteId = (int)($_POST['quote_id'] ?? 0);
          if ($quoteId > 0) {
            $stOwnQuote = $pdo->prepare(
              'SELECT id FROM tenant_quotes WHERE id = :id AND tenant_company_id = :tenant_company_id AND deleted_at IS NULL LIMIT 1'
            );
            $stOwnQuote->execute(['id' => $quoteId, 'tenant_company_id' => $tenantCompanyId]);
            if ($stOwnQuote->fetchColumn()) {
              $toTrash = $pdo->prepare(
                'UPDATE tenant_quotes
                 SET deleted_at = NOW(), deleted_by = :deleted_by
                 WHERE id = :id
                   AND tenant_company_id = :tenant_company_id
                   AND deleted_at IS NULL'
              );
              $toTrash->execute([
                'id' => $quoteId,
                'tenant_company_id' => $tenantCompanyId,
                'deleted_by' => ($accountLoginEmail !== '' ? $accountLoginEmail : 'owner@local.invalid'),
              ]);
              if ($toTrash->rowCount() > 0) {
                $flash['ok'] = 'Cotizacion movida a papelera.';
              }
            } else {
              $flash['error'] = 'La cotizacion no pertenece a tu empresa.';
            }
          }
        }

        if ($action === 'restore_customer') {
          $module = 'papelera';
          $customerId = (int)($_POST['customer_id'] ?? 0);
          if ($customerId > 0) {
            try {
              $restoreCustomer = $pdo->prepare(
                'UPDATE tenant_customers
                 SET deleted_at = NULL, deleted_by = NULL, estado = 1, is_active = 1
                 WHERE id = :id
                   AND tenant_company_id = :tenant_company_id
                   AND deleted_at IS NOT NULL'
              );
              $restoreCustomer->execute(['id' => $customerId, 'tenant_company_id' => $tenantCompanyId]);
              if ($restoreCustomer->rowCount() > 0) {
                $flash['ok'] = 'Cliente restaurado desde papelera.';
              } else {
                $flash['error'] = 'No se encontro el cliente en papelera para restaurar.';
              }
            } catch (Throwable $e) {
              $flash['error'] = 'No se pudo restaurar el cliente. Verifica si existe conflicto con datos activos.';
            }
          }
        }

        if ($action === 'restore_quote') {
          $module = 'papelera';
          $quoteId = (int)($_POST['quote_id'] ?? 0);
          if ($quoteId > 0) {
            $stOwnQuote = $pdo->prepare(
              'SELECT id, customer_id
               FROM tenant_quotes
               WHERE id = :id
                 AND tenant_company_id = :tenant_company_id
                 AND deleted_at IS NOT NULL
               LIMIT 1'
            );
            $stOwnQuote->execute(['id' => $quoteId, 'tenant_company_id' => $tenantCompanyId]);
            $quoteRow = $stOwnQuote->fetch();

            if (!$quoteRow) {
              $flash['error'] = 'No se encontro la cotizacion en papelera para restaurar.';
            } else {
              $stActiveCustomer = $pdo->prepare(
                'SELECT id
                 FROM tenant_customers
                 WHERE id = :customer_id
                   AND tenant_company_id = :tenant_company_id
                   AND deleted_at IS NULL
                 LIMIT 1'
              );
              $stActiveCustomer->execute([
                'customer_id' => (int)$quoteRow['customer_id'],
                'tenant_company_id' => $tenantCompanyId,
              ]);
              if (!$stActiveCustomer->fetchColumn()) {
                $flash['error'] = 'No se puede restaurar la cotizacion mientras el cliente siga en papelera.';
              } else {
                $restoreQuote = $pdo->prepare(
                  'UPDATE tenant_quotes
                   SET deleted_at = NULL, deleted_by = NULL
                   WHERE id = :id
                     AND tenant_company_id = :tenant_company_id
                     AND deleted_at IS NOT NULL'
                );
                $restoreQuote->execute(['id' => $quoteId, 'tenant_company_id' => $tenantCompanyId]);
                if ($restoreQuote->rowCount() > 0) {
                  $flash['ok'] = 'Cotizacion restaurada desde papelera.';
                } else {
                  $flash['error'] = 'No se pudo restaurar la cotizacion.';
                }
              }
            }
          }
        }

        if ($action === 'purge_quote') {
          $module = 'papelera';
          $quoteId = (int)($_POST['quote_id'] ?? 0);
          if ($quoteId > 0) {
            $stOwnQuote = $pdo->prepare(
              'SELECT id FROM tenant_quotes WHERE id = :id AND tenant_company_id = :tenant_company_id AND deleted_at IS NOT NULL LIMIT 1'
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
                $flash['ok'] = 'Cotizacion eliminada de forma definitiva.';
              } catch (Throwable $e) {
                $pdo->rollBack();
                $flash['error'] = 'No se pudo eliminar definitivamente la cotizacion.';
              }
            } else {
              $flash['error'] = 'No se encontro la cotizacion en papelera.';
            }
          }
        }

        if ($action === 'purge_customer') {
          $module = 'papelera';
          $customerId = (int)($_POST['customer_id'] ?? 0);
          if ($customerId > 0) {
            $stOwnCustomer = $pdo->prepare(
              'SELECT id FROM tenant_customers WHERE id = :id AND tenant_company_id = :tenant_company_id AND deleted_at IS NOT NULL LIMIT 1'
            );
            $stOwnCustomer->execute(['id' => $customerId, 'tenant_company_id' => $tenantCompanyId]);
            if ($stOwnCustomer->fetchColumn()) {
              $pdo->beginTransaction();
              try {
                $stRelatedQuotes = $pdo->prepare(
                  'SELECT id FROM tenant_quotes WHERE tenant_company_id = :tenant_company_id AND customer_id = :customer_id'
                );
                $stRelatedQuotes->execute(['tenant_company_id' => $tenantCompanyId, 'customer_id' => $customerId]);
                $relatedIds = array_map(static fn($r) => (int)$r['id'], $stRelatedQuotes->fetchAll());
                $relatedIds = array_values(array_filter($relatedIds, static fn($id) => $id > 0));

                if (!empty($relatedIds)) {
                  $placeholders = implode(',', array_fill(0, count($relatedIds), '?'));
                  $delItems = $pdo->prepare("DELETE FROM tenant_quote_items WHERE tenant_quote_id IN ($placeholders)");
                  $delItems->execute($relatedIds);
                }

                $delQuotes = $pdo->prepare(
                  'DELETE FROM tenant_quotes WHERE tenant_company_id = :tenant_company_id AND customer_id = :customer_id'
                );
                $delQuotes->execute(['tenant_company_id' => $tenantCompanyId, 'customer_id' => $customerId]);

                $delCustomer = $pdo->prepare(
                  'DELETE FROM tenant_customers WHERE id = :id AND tenant_company_id = :tenant_company_id'
                );
                $delCustomer->execute(['id' => $customerId, 'tenant_company_id' => $tenantCompanyId]);

                $pdo->commit();
                $flash['ok'] = 'Cliente y datos relacionados eliminados de forma definitiva.';
              } catch (Throwable $e) {
                $pdo->rollBack();
                $flash['error'] = 'No se pudo completar la eliminacion definitiva del cliente.';
              }
            } else {
              $flash['error'] = 'No se encontro el cliente en papelera.';
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

        if ($action === 'send_quote_email') {
          $module = 'cotizaciones';
          $quoteId = (int)($_POST['quote_id'] ?? 0);

          $quoteEmailForm = [
            'quote_id' => (string)$quoteId,
            'to' => trim((string)($_POST['quote_email_to'] ?? '')),
            'cc' => trim((string)($_POST['quote_email_cc'] ?? '')),
            'subject' => trim((string)($_POST['quote_email_subject'] ?? '')),
            'message' => trim((string)($_POST['quote_email_message'] ?? '')),
            'include_quote_attachment' => isset($_POST['include_quote_attachment']) ? '1' : '0',
          ];
          $openQuoteEmailModal = true;

          if ($quoteId <= 0) {
            $flash['error'] = 'Debes seleccionar una cotizacion valida para enviar.';
          } else {
            $stQuote = $pdo->prepare(
                  'SELECT q.id, q.customer_id, q.numero_cotizacion, q.fecha_emision, q.validez_dias,
                    q.descuento_pct, q.subtotal, q.total, q.estado, q.terminos_condiciones_adicionales,
                    q.validez_override, q.entrega_override, q.condicion_de_pago_override, q.moneda_override,
                    q.observaciones,
                      c.razon_social AS customer_name,
                    c.rut AS customer_rut,
                      c.contacto AS customer_contact,
                      c.contact_name AS customer_contact_name,
                      c.email AS customer_email
               FROM tenant_quotes q
               INNER JOIN tenant_customers c
                 ON c.id = q.customer_id
                AND c.tenant_company_id = q.tenant_company_id
               WHERE q.id = :id
                 AND q.tenant_company_id = :tenant_company_id
                 AND q.deleted_at IS NULL
               LIMIT 1'
            );
            $stQuote->execute(['id' => $quoteId, 'tenant_company_id' => $tenantCompanyId]);
            $quoteRow = $stQuote->fetch();

            if (!$quoteRow) {
              $flash['error'] = 'La cotizacion seleccionada no pertenece a tu empresa.';
            } else {
              $companyProfileEmail = '';
              $stCompanyMail = $pdo->prepare(
                'SELECT email_principal
                 FROM tenant_company_profiles
                 WHERE tenant_company_id = :tenant_company_id
                 LIMIT 1'
              );
              $stCompanyMail->execute(['tenant_company_id' => $tenantCompanyId]);
              $companyMailRow = $stCompanyMail->fetch();
              if ($companyMailRow) {
                $companyProfileEmail = trim((string)($companyMailRow['email_principal'] ?? ''));
              }

              if ($quoteEmailForm['to'] === '' && !empty($quoteRow['customer_email'])) {
                $quoteEmailForm['to'] = trim((string)$quoteRow['customer_email']);
              }

              $toList = parse_email_list($quoteEmailForm['to'], 10);
              $ccList = parse_email_list($quoteEmailForm['cc'], 10);

              $companyReviewRecipients = parse_email_list([
                (string)($accountSettings['email'] ?? ''),
                (string)($companyEmail ?? ''),
                (string)$companyProfileEmail,
                (string)$accountLoginEmail,
              ], 10);
              foreach ($companyReviewRecipients as $reviewEmail) {
                if (!in_array($reviewEmail, $toList, true) && !in_array($reviewEmail, $ccList, true)) {
                  $ccList[] = $reviewEmail;
                }
              }

              if (count($ccList) > 10) {
                $ccList = array_slice($ccList, 0, 10);
              }

              if (empty($toList)) {
                $flash['error'] = 'Ingresa al menos un correo valido en el campo Para.';
              } else {
                $mailCfg = load_mail_credentials();
                if ($mailCfg === null) {
                  $flash['error'] = 'No hay configuracion SMTP disponible en el servidor.';
                } else {
                  $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                  $host = (string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost');
                  $previewUrl = $scheme . '://' . $host . '/empresa/dashboard/?module=cotizaciones&view_quote_id=' . (int)$quoteRow['id'] . '&quote_embed=1';

                  if ($quoteEmailForm['subject'] === '') {
                    $quoteEmailForm['subject'] = 'Cotizacion ' . (string)$quoteRow['numero_cotizacion'];
                  }
                  $customerContact = trim((string)($quoteRow['customer_contact'] ?? ''));
                  if ($customerContact === '') {
                    $customerContact = trim((string)($quoteRow['customer_contact_name'] ?? ''));
                  }
                  if ($customerContact === '') {
                    $customerContact = trim((string)($quoteRow['customer_name'] ?? ''));
                  }

                  if ($quoteEmailForm['message'] === '') {
                    $quoteEmailForm['message'] = "Te compartimos la cotizacion " . (string)$quoteRow['numero_cotizacion'] . ".\n\nQuedo atento a tus comentarios.";
                  }

                  $attachments = [];
                  $totalUploadBytes = 0;
                  $maxUploadBytes = 25 * 1024 * 1024;

                  if ($quoteEmailForm['include_quote_attachment'] === '1') {
                    $profileForPdf = [
                      'nombre' => '',
                      'rut' => '',
                      'direccion' => '',
                      'telefono' => '',
                      'email_principal' => '',
                      'condicion_de_pago' => '',
                      'entrega' => '',
                      'validez' => '',
                      'moneda' => 'CLP',
                    ];
                    $logoPublicUrlForPdf = '';

                    $stProfileForPdf = $pdo->prepare(
                      'SELECT nombre, rut, direccion, telefono, email_principal, condicion_de_pago, entrega, validez, moneda, logo_filename
                       FROM tenant_company_profiles
                       WHERE tenant_company_id = :tenant_company_id
                       LIMIT 1'
                    );
                    $stProfileForPdf->execute(['tenant_company_id' => $tenantCompanyId]);
                    $profileRowForPdf = $stProfileForPdf->fetch();
                    if ($profileRowForPdf) {
                      $logoRelativePathForPdf = (string)($profileRowForPdf['logo_filename'] ?? '');
                      foreach ($profileForPdf as $k => $v) {
                        if (array_key_exists($k, $profileRowForPdf)) {
                          $profileForPdf[$k] = (string)$profileRowForPdf[$k];
                        }
                      }
                      $logoPublicUrlForPdf = logo_data_uri($logoRelativePathForPdf);
                      if ($logoPublicUrlForPdf === '') {
                        $logoPublicUrlForPdf = logo_public_url($logoRelativePathForPdf);
                        if ($logoPublicUrlForPdf !== '' && strpos($logoPublicUrlForPdf, 'http://') !== 0 && strpos($logoPublicUrlForPdf, 'https://') !== 0) {
                          $logoPublicUrlForPdf = $scheme . '://' . $host . '/' . ltrim($logoPublicUrlForPdf, '/');
                        }
                      }
                    }

                    $stQuoteItems = $pdo->prepare(
                      'SELECT descripcion, item_type, is_bold, cantidad, precio_unitario, total_linea
                       FROM tenant_quote_items
                       WHERE tenant_quote_id = :tenant_quote_id
                       ORDER BY orden ASC, id ASC'
                    );
                    $stQuoteItems->execute(['tenant_quote_id' => $quoteId]);
                    $quoteItemsForMail = $stQuoteItems->fetchAll();
                    try {
                      $attachments[] = build_quote_pdf_attachment((string)$companyName, $previewUrl, $quoteRow, $quoteItemsForMail, $profileForPdf, $logoPublicUrlForPdf);
                    } catch (Throwable $pdfBuildError) {
                      $flash['error'] = 'No fue posible generar el PDF de la cotizacion con formato. Intenta nuevamente en unos segundos.';
                      error_log('HERMES_QUOTE_PDF_BUILD_ERROR: ' . $pdfBuildError->getMessage());
                    }
                  }

                  if (isset($_FILES['quote_email_files']) && is_array($_FILES['quote_email_files'])) {
                    $files = $_FILES['quote_email_files'];
                    $names = is_array($files['name'] ?? null) ? $files['name'] : [];
                    $types = is_array($files['type'] ?? null) ? $files['type'] : [];
                    $tmpNames = is_array($files['tmp_name'] ?? null) ? $files['tmp_name'] : [];
                    $errors = is_array($files['error'] ?? null) ? $files['error'] : [];
                    $sizes = is_array($files['size'] ?? null) ? $files['size'] : [];

                    $fileCount = min(count($names), count($tmpNames), count($errors), count($sizes));
                    $maxUserFiles = 5;
                    if ($fileCount > $maxUserFiles) {
                      $fileCount = $maxUserFiles;
                    }

                    for ($i = 0; $i < $fileCount; $i++) {
                      $errCode = (int)($errors[$i] ?? UPLOAD_ERR_NO_FILE);
                      if ($errCode === UPLOAD_ERR_NO_FILE) {
                        continue;
                      }
                      if ($errCode !== UPLOAD_ERR_OK) {
                        $flash['error'] = 'Uno de los archivos adjuntos no pudo cargarse correctamente.';
                        break;
                      }

                      $tmpPath = (string)($tmpNames[$i] ?? '');
                      $size = (int)($sizes[$i] ?? 0);
                      if ($tmpPath === '' || !is_uploaded_file($tmpPath) || $size <= 0) {
                        $flash['error'] = 'Uno de los archivos adjuntos es invalido.';
                        break;
                      }
                      if ($size > (8 * 1024 * 1024)) {
                        $flash['error'] = 'Cada adjunto debe pesar como maximo 8 MB.';
                        break;
                      }

                      $totalUploadBytes += $size;
                      if ($totalUploadBytes > $maxUploadBytes) {
                        $flash['error'] = 'El tamano total de adjuntos supera 25 MB.';
                        break;
                      }

                      $content = @file_get_contents($tmpPath);
                      if ($content === false) {
                        $flash['error'] = 'No se pudo leer uno de los archivos adjuntos.';
                        break;
                      }

                      $name = sanitize_attachment_name((string)($names[$i] ?? ''), 'archivo_' . ($i + 1) . '.bin');
                      $mime = trim((string)($types[$i] ?? 'application/octet-stream'));
                      if ($mime === '') {
                        $mime = 'application/octet-stream';
                      }
                      $attachments[] = [
                        'name' => $name,
                        'mime' => $mime,
                        'content' => $content,
                      ];
                    }
                  }

                  if ($flash['error'] === '') {
                    $safeMessageHtml = nl2br(htmlspecialchars($quoteEmailForm['message'], ENT_QUOTES, 'UTF-8'));
                    $safePreviewUrl = htmlspecialchars($previewUrl, ENT_QUOTES, 'UTF-8');
                    $safeQuoteNumber = htmlspecialchars((string)$quoteRow['numero_cotizacion'], ENT_QUOTES, 'UTF-8');
                    $safeCustomerName = htmlspecialchars((string)($quoteRow['customer_name'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $safeCompanyName = htmlspecialchars((string)($companyName !== '' ? $companyName : 'GesMan HERMES'), ENT_QUOTES, 'UTF-8');
                    $safeCustomerContact = htmlspecialchars($customerContact !== '' ? $customerContact : 'cliente', ENT_QUOTES, 'UTF-8');
                    $greetingText = 'Hola ' . ($customerContact !== '' ? $customerContact : 'cliente') . ',';
                    $messageStartsWithHola = (bool)preg_match('/^\s*hola\b/i', (string)$quoteEmailForm['message']);

                    $htmlBody = '';
                    if (!$messageStartsWithHola) {
                      $htmlBody .= '<p>Hola ' . $safeCustomerContact . ',</p>';
                    }

                    $htmlBody .= '<p>' . $safeMessageHtml . '</p>'
                      . '<p><strong>Cotizacion:</strong> ' . $safeQuoteNumber . '<br>'
                      . '<strong>Cliente:</strong> ' . $safeCustomerName . '</p>'
                      . '<p>Saludos,<br>' . $safeCompanyName . '</p>';

                    $textBody = ($messageStartsWithHola ? $quoteEmailForm['message'] : ($greetingText . "\n\n" . $quoteEmailForm['message']))
                      . "\n\nCotizacion: " . (string)$quoteRow['numero_cotizacion']
                      . "\nCliente: " . (string)($quoteRow['customer_name'] ?? '');

                    $sent = send_quote_email_smtp(
                      $mailCfg,
                      $toList,
                      $ccList,
                      $quoteEmailForm['subject'],
                      $textBody,
                      $htmlBody,
                      $attachments
                    );

                    if ($sent) {
                      $flash['ok'] = 'Cotizacion enviada por correo correctamente.';
                      security_audit_log($pdo, [
                        'tenant_company_id' => $tenantCompanyId,
                        'actor_email' => $accountLoginEmail,
                        'actor_role' => $role,
                        'action_name' => 'send_quote_email',
                        'entity_name' => 'quote',
                        'entity_id' => (string)$quoteId,
                        'result_status' => 'success',
                        'detail' => [
                          'to_count' => count($toList),
                          'cc_count' => count($ccList),
                          'attachment_count' => count($attachments),
                        ],
                      ]);
                      $openQuoteEmailModal = false;
                      $quoteEmailForm = [
                        'quote_id' => '',
                        'to' => '',
                        'cc' => '',
                        'subject' => '',
                        'message' => "Te compartimos la cotizacion solicitada.\n\nQuedo atento a tus comentarios.",
                        'include_quote_attachment' => '1',
                      ];
                    } else {
                      $flash['error'] = 'No fue posible enviar el correo de la cotizacion.';
                      security_audit_log($pdo, [
                        'tenant_company_id' => $tenantCompanyId,
                        'actor_email' => $accountLoginEmail,
                        'actor_role' => $role,
                        'action_name' => 'send_quote_email',
                        'entity_name' => 'quote',
                        'entity_id' => (string)$quoteId,
                        'result_status' => 'failed',
                        'detail' => [
                          'to_count' => count($toList),
                          'cc_count' => count($ccList),
                          'attachment_count' => count($attachments),
                        ],
                      ]);
                    }
                  }
                }
              }
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
            'validez_override' => trim((string)($_POST['validez_override'] ?? '')),
            'entrega_override' => trim((string)($_POST['entrega_override'] ?? '')),
            'condicion_de_pago_override' => trim((string)($_POST['condicion_de_pago_override'] ?? '')),
            'moneda_override' => strtoupper(trim((string)($_POST['moneda_override'] ?? ''))),
            'terminos_condiciones_adicionales' => trim((string)($_POST['terminos_condiciones_adicionales'] ?? '')),
            'observaciones' => trim((string)($_POST['observaciones'] ?? '')),
            'items' => [],
          ];

          $rawDesc = $_POST['item_descripcion'] ?? [];
          $rawQty = $_POST['item_cantidad'] ?? [];
          $rawPrice = $_POST['item_precio'] ?? [];
          $rawType = $_POST['item_tipo'] ?? [];
          $rawBold = $_POST['item_negrita'] ?? [];
          if (!is_array($rawDesc)) {
            $rawDesc = [];
          }
          if (!is_array($rawQty)) {
            $rawQty = [];
          }
          if (!is_array($rawPrice)) {
            $rawPrice = [];
          }
          if (!is_array($rawType)) {
            $rawType = [];
          }
          if (!is_array($rawBold)) {
            $rawBold = [];
          }

          $rows = max(count($rawDesc), count($rawQty), count($rawPrice), count($rawType), count($rawBold));
          $itemsToInsert = [];
          $subtotal = 0.0;

          for ($i = 0; $i < $rows; $i++) {
            $descripcion = trim((string)($rawDesc[$i] ?? ''));
            $cantidadInputRaw = isset($rawQty[$i]) ? trim((string)$rawQty[$i]) : '';
            $precioInputRaw = isset($rawPrice[$i]) ? trim((string)$rawPrice[$i]) : '';
            $cantidadRaw = str_replace(',', '.', ($cantidadInputRaw === '' ? '0' : $cantidadInputRaw));
            $precioRaw = str_replace(',', '.', ($precioInputRaw === '' ? '0' : $precioInputRaw));

            $itemTypeRaw = strtolower(trim((string)($rawType[$i] ?? '')));
            if ($itemTypeRaw === '') {
              $itemType = ($cantidadInputRaw === '' && $precioInputRaw === '') ? 'text' : 'normal';
            } else {
              $itemType = $itemTypeRaw;
            }
            if (!in_array($itemType, ['normal', 'text'], true)) {
              $itemType = 'normal';
            }
            $isBold = ((string)($rawBold[$i] ?? '0') === '1') ? 1 : 0;
            $cantidad = (float)$cantidadRaw;
            $precio = (float)$precioRaw;

            if ($descripcion === '' && $cantidad <= 0 && $precio <= 0) {
              continue;
            }

            $quoteFormInput['items'][] = [
              'descripcion' => $descripcion,
              'cantidad' => ($cantidadRaw === '' ? '0' : $cantidadRaw),
              'precio' => ($precioRaw === '' ? '0' : $precioRaw),
              'tipo' => $itemType,
              'negrita' => (string)$isBold,
            ];

            if ($itemType === 'text') {
              if ($descripcion === '') {
                $flash['error'] = 'Cada item de texto requiere descripcion.';
                $openQuoteModal = true;
                break;
              }
              $itemsToInsert[] = [
                'orden' => count($itemsToInsert) + 1,
                'descripcion' => $descripcion,
                'item_type' => 'text',
                'is_bold' => $isBold,
                'cantidad' => 0,
                'precio_unitario' => 0,
                'total_linea' => 0,
              ];
              continue;
            }

            if ($descripcion === '' || $cantidad <= 0 || $precio < 0) {
              $flash['error'] = 'Cada item requiere descripcion, cantidad mayor a 0 y precio valido.';
              $openQuoteModal = true;
              break;
            }

            $totalLinea = round($cantidad * $precio, 2);
            $itemsToInsert[] = [
              'orden' => count($itemsToInsert) + 1,
              'descripcion' => $descripcion,
              'item_type' => 'normal',
              'is_bold' => $isBold,
              'cantidad' => $cantidad,
              'precio_unitario' => $precio,
              'total_linea' => $totalLinea,
            ];
            $subtotal += $totalLinea;
          }

          if (empty($quoteFormInput['items'])) {
            $quoteFormInput['items'][] = ['descripcion' => '', 'cantidad' => '1', 'precio' => '0', 'tipo' => 'normal', 'negrita' => '0'];
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
                             validez_override = :validez_override,
                             entrega_override = :entrega_override,
                             condicion_de_pago_override = :condicion_de_pago_override,
                             moneda_override = :moneda_override,
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
                        'validez_override' => $quoteFormInput['validez_override'],
                        'entrega_override' => $quoteFormInput['entrega_override'],
                        'condicion_de_pago_override' => $quoteFormInput['condicion_de_pago_override'],
                        'moneda_override' => $quoteFormInput['moneda_override'],
                        'observaciones' => $quoteFormInput['observaciones'],
                      ]);

                      $delOldItems = $pdo->prepare('DELETE FROM tenant_quote_items WHERE tenant_quote_id = :tenant_quote_id');
                      $delOldItems->execute(['tenant_quote_id' => $quoteId]);
                    } else {
                      $insQuote = $pdo->prepare(
                        'INSERT INTO tenant_quotes (
                          tenant_company_id, customer_id, numero_cotizacion,
                          fecha_emision, validez_dias, descuento_pct,
                          subtotal, total, estado, terminos_condiciones_adicionales,
                          validez_override, entrega_override, condicion_de_pago_override, moneda_override,
                          observaciones
                         ) VALUES (
                          :tenant_company_id, :customer_id, :numero_cotizacion,
                          :fecha_emision, :validez_dias, :descuento_pct,
                          :subtotal, :total, :estado, :terminos_condiciones_adicionales,
                          :validez_override, :entrega_override, :condicion_de_pago_override, :moneda_override,
                          :observaciones
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
                        'validez_override' => $quoteFormInput['validez_override'],
                        'entrega_override' => $quoteFormInput['entrega_override'],
                        'condicion_de_pago_override' => $quoteFormInput['condicion_de_pago_override'],
                        'moneda_override' => $quoteFormInput['moneda_override'],
                        'observaciones' => $quoteFormInput['observaciones'],
                      ]);
                      $quoteId = (int)$pdo->lastInsertId();
                    }

                    $insItem = $pdo->prepare(
                      'INSERT INTO tenant_quote_items (
                        tenant_quote_id, orden, descripcion, item_type, is_bold, cantidad, precio_unitario, total_linea
                       ) VALUES (
                        :tenant_quote_id, :orden, :descripcion, :item_type, :is_bold, :cantidad, :precio_unitario, :total_linea
                       )'
                    );

                    foreach ($itemsToInsert as $itemRow) {
                      $insItem->execute([
                        'tenant_quote_id' => $quoteId,
                        'orden' => $itemRow['orden'],
                        'descripcion' => $itemRow['descripcion'],
                        'item_type' => $itemRow['item_type'],
                        'is_bold' => $itemRow['is_bold'],
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
                      'validez_override' => '',
                      'entrega_override' => '',
                      'condicion_de_pago_override' => '',
                      'moneda_override' => '',
                      'terminos_condiciones_adicionales' => '',
                      'observaciones' => '',
                      'items' => [
                        ['descripcion' => '', 'cantidad' => '1', 'precio' => '0', 'tipo' => 'normal', 'negrita' => '0'],
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

        try {
          security_audit_log($pdo, [
            'tenant_company_id' => $tenantCompanyId,
            'actor_email' => $accountLoginEmail,
            'actor_role' => $role,
            'action_name' => ($action !== '' ? 'dashboard_' . $action : 'dashboard_post'),
            'entity_name' => 'dashboard_action',
            'entity_id' => ($action !== '' ? $action : null),
            'result_status' => ($flash['error'] === '' ? 'ok' : 'fail'),
            'detail' => [
              'module' => $module,
              'flash_error' => $flash['error'],
              'flash_ok' => $flash['ok'],
            ],
          ]);
        } catch (Throwable $auditError) {
        }

        if ($isAjaxPost) {
          $ajaxPayload = [
            'ok' => ($flash['error'] === ''),
            'message' => ($flash['error'] !== '' ? $flash['error'] : $flash['ok']),
            'flash' => $flash,
            'module' => $module,
          ];

          if (in_array($action, $ajaxTechnicianActions, true)) {
            $ajaxPayload['technicians'] = fetch_company_technicians($pdo, $tenantCompanyId);
            $ajaxPayload['focus_technician_id'] = (int)$ajaxTechnicianFocusId;
          }

          header('Content-Type: application/json; charset=UTF-8');
          echo json_encode($ajaxPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
          exit;
        }

        $_SESSION['hermes_company_postback'] = [
          'module' => $module,
          'flash' => $flash,
          'openCustomerModal' => $openCustomerModal,
          'openTechnicianModal' => $openTechnicianModal,
          'openTechnicianAssetModal' => $openTechnicianAssetModal,
          'openInventoryModal' => $openInventoryModal,
          'openInventoryMoveModal' => $openInventoryMoveModal,
          'openServiceReportModal' => $openServiceReportModal,
          'openQuoteModal' => $openQuoteModal,
          'openQuoteEmailModal' => $openQuoteEmailModal,
          'customerForm' => $customerForm,
          'technicianForm' => $technicianForm,
          'technicianAssetForm' => $technicianAssetForm,
          'technicianAssetRecords' => $technicianAssetRecords,
          'inventoryForm' => $inventoryForm,
          'inventoryMoveForm' => $inventoryMoveForm,
          'serviceReportForm' => $serviceReportForm,
          'quoteForm' => $quoteForm,
          'quoteEmailForm' => $quoteEmailForm,
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

    $effectivePlanCode = normalize_plan_code((string)$usage['plan_code'], 'basico');
    $seedStorageLimitMb = plan_storage_limit_mb($effectivePlanCode);

    $seedUsage = $pdo->prepare(
        'INSERT INTO tenant_plan_usage (tenant_company_id, plan_code, storage_limit_mb, storage_used_mb)
         VALUES (:tenant_company_id, :plan_code, :storage_limit_mb, :storage_used_mb)
         ON DUPLICATE KEY UPDATE tenant_company_id = tenant_company_id'
    );
    $seedUsage->execute([
        'tenant_company_id' => $tenantCompanyId,
        'plan_code' => $effectivePlanCode,
      'storage_limit_mb' => $seedStorageLimitMb,
        'storage_used_mb' => 0,
    ]);

    $stUsage = $pdo->prepare('SELECT plan_code, storage_limit_mb, storage_used_mb FROM tenant_plan_usage WHERE tenant_company_id = :tenant_company_id LIMIT 1');
    $stUsage->execute(['tenant_company_id' => $tenantCompanyId]);
    $usageRow = $stUsage->fetch();
    if ($usageRow) {
        $usagePlanCode = normalize_plan_code((string)$usageRow['plan_code'], $effectivePlanCode);
        if ($usagePlanCode !== $effectivePlanCode) {
          $usagePlanCode = $effectivePlanCode;
          $upUsagePlan = $pdo->prepare(
            'UPDATE tenant_plan_usage
             SET plan_code = :plan_code
             WHERE tenant_company_id = :tenant_company_id
             LIMIT 1'
          );
          $upUsagePlan->execute([
            'plan_code' => $usagePlanCode,
            'tenant_company_id' => $tenantCompanyId,
          ]);
        }

        $usage['plan_code'] = $usagePlanCode;
      $usage['storage_limit_mb'] = max(1, (int)$usageRow['storage_limit_mb']);
        $usage['storage_used_mb'] = max(0, (int)$usageRow['storage_used_mb']);
      $expectedLimitMb = plan_storage_limit_mb($usage['plan_code']);
      if ($usage['storage_limit_mb'] !== $expectedLimitMb) {
        $usage['storage_limit_mb'] = $expectedLimitMb;
        $upUsageLimit = $pdo->prepare('UPDATE tenant_plan_usage SET storage_limit_mb = :storage_limit_mb WHERE tenant_company_id = :tenant_company_id LIMIT 1');
        $upUsageLimit->execute([
          'storage_limit_mb' => $expectedLimitMb,
          'tenant_company_id' => $tenantCompanyId,
        ]);
      }
        if ($usage['storage_used_mb'] > $usage['storage_limit_mb']) {
            $usage['storage_used_mb'] = $usage['storage_limit_mb'];
        }

      $measuredUsageMb = tenant_storage_used_mb($tenantCompanyId);
      if ($measuredUsageMb !== $usage['storage_used_mb']) {
        $usage['storage_used_mb'] = min($usage['storage_limit_mb'], max(0, $measuredUsageMb));
        $upUsageUsed = $pdo->prepare('UPDATE tenant_plan_usage SET storage_used_mb = :storage_used_mb WHERE tenant_company_id = :tenant_company_id LIMIT 1');
        $upUsageUsed->execute([
          'storage_used_mb' => $usage['storage_used_mb'],
          'tenant_company_id' => $tenantCompanyId,
        ]);
      }

        $usage['percent'] = (int)round(($usage['storage_used_mb'] / $usage['storage_limit_mb']) * 100);
    }

    $isPaidAccount = ($planBilling['payment_status'] === 'paid') || ($planBilling['plan_status'] === 'paid');
    if ($isPaidAccount) {
      $planBilling['can_pay_renewal'] = false;
      $currentPlanName = plan_display_name($usage['plan_code']);
      if ($planBilling['days_left'] === null) {
        $planBilling['notice_tone'] = 'ok';
        $planBilling['notice_title'] = 'Plan pagado al dia';
        $planBilling['notice_text'] = 'Tu plan ' . $currentPlanName . ' ' . strtolower($planBilling['billing_cycle_name']) . ' esta pagado. Aun no se pudo calcular la fecha de vencimiento.';
      } elseif ($planBilling['days_left'] < 0) {
        $planBilling['notice_tone'] = 'danger';
        $planBilling['notice_title'] = 'Renovacion vencida';
        $planBilling['notice_text'] = 'Tu plan ' . $currentPlanName . ' ' . strtolower($planBilling['billing_cycle_name']) . ' esta vencido hace ' . abs((int)$planBilling['days_left']) . ' dias. Regulariza para evitar suspension.';
      } elseif ($planBilling['days_left'] <= 7) {
        $planBilling['notice_tone'] = 'warn';
        $planBilling['notice_title'] = 'Renovacion proxima';
        $planBilling['notice_text'] = 'Quedan ' . (int)$planBilling['days_left'] . ' dias para renovar tu plan ' . $currentPlanName . ' ' . strtolower($planBilling['billing_cycle_name']) . '.';
      } else {
        $planBilling['notice_tone'] = 'ok';
        $planBilling['notice_title'] = 'Plan pagado al dia';
        $planBilling['notice_text'] = 'Tu plan ' . $currentPlanName . ' ' . strtolower($planBilling['billing_cycle_name']) . ' esta pagado y vence en ' . (int)$planBilling['days_left'] . ' dias.';
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

    if ($signupId > 0 && table_exists($pdo, 'payment_transactions')) {
      $paymentHistoryAvailable = true;
      $stPayments = $pdo->prepare(
        'SELECT pt.provider, pt.external_reference, pt.preference_id, pt.provider_payment_id, pt.status, pt.amount, pt.currency_id, pt.created_at
           FROM payment_transactions pt
           INNER JOIN account_signups s ON s.id = pt.signup_id
          WHERE pt.signup_id = :signup_id
            AND LOWER(s.email) = LOWER(:email)
          ORDER BY pt.id DESC
          LIMIT 100'
      );
      $stPayments->execute([
        'signup_id' => $signupId,
        'email' => $accountLoginEmail,
      ]);
      $paymentHistoryRows = $stPayments->fetchAll();
    }
    if ($accountSettings['email'] === '') {
      $accountSettings['email'] = $accountLoginEmail;
    }
    if ($accountSettings['company_name'] === '') {
      $accountSettings['company_name'] = $companyName;
    }

    $stCustomers = $pdo->prepare(
      'SELECT id, rut, razon_social, nombre_fantasia, direccion, comuna, ciudad, telefono, celular, email, contacto, notas_internas, estado
         FROM tenant_customers
         WHERE tenant_company_id = :tenant_company_id
           AND deleted_at IS NULL
         ORDER BY razon_social ASC, id DESC'
    );
    $stCustomers->execute(['tenant_company_id' => $tenantCompanyId]);
    $customers = $stCustomers->fetchAll();

    $technicians = fetch_company_technicians($pdo, $tenantCompanyId);
    $inventoryItems = fetch_company_inventory_items($pdo, $tenantCompanyId);
    $inventoryMovements = fetch_company_inventory_movements($pdo, $tenantCompanyId, 250);

    $stTrashCustomers = $pdo->prepare(
      'SELECT id, rut, razon_social, nombre_fantasia, email, contacto, deleted_at, deleted_by
         FROM tenant_customers
         WHERE tenant_company_id = :tenant_company_id
           AND deleted_at IS NOT NULL
         ORDER BY deleted_at DESC, id DESC'
    );
    $stTrashCustomers->execute(['tenant_company_id' => $tenantCompanyId]);
    $trashCustomers = $stTrashCustomers->fetchAll();

    $stQuotes = $pdo->prepare(
      'SELECT q.id, q.customer_id, q.numero_cotizacion, q.fecha_emision, q.validez_dias,
          q.descuento_pct, q.subtotal, q.total, q.estado, q.terminos_condiciones_adicionales,
          q.validez_override, q.entrega_override, q.condicion_de_pago_override, q.moneda_override,
          q.observaciones,
          c.razon_social AS customer_name,
          c.email AS customer_email,
          c.contacto AS customer_contact
       FROM tenant_quotes q
       INNER JOIN tenant_customers c
         ON c.id = q.customer_id
        AND c.tenant_company_id = q.tenant_company_id
        AND c.deleted_at IS NULL
       WHERE q.tenant_company_id = :tenant_company_id
        AND q.deleted_at IS NULL
       ORDER BY q.id DESC
       LIMIT 200'
    );
    $stQuotes->execute(['tenant_company_id' => $tenantCompanyId]);
    $quotes = $stQuotes->fetchAll();

    $stTrashQuotes = $pdo->prepare(
      'SELECT q.id, q.numero_cotizacion, q.fecha_emision, q.total, q.estado, q.deleted_at, q.deleted_by,
          c.razon_social AS customer_name
       FROM tenant_quotes q
       LEFT JOIN tenant_customers c
         ON c.id = q.customer_id
        AND c.tenant_company_id = q.tenant_company_id
       WHERE q.tenant_company_id = :tenant_company_id
         AND q.deleted_at IS NOT NULL
       ORDER BY q.deleted_at DESC, q.id DESC
       LIMIT 300'
    );
    $stTrashQuotes->execute(['tenant_company_id' => $tenantCompanyId]);
    $trashQuotes = $stTrashQuotes->fetchAll();

    try {
      $stTrashInventory = $pdo->prepare(
        'SELECT id, sku, nombre, unidad, stock_actual, deleted_at, deleted_by
           FROM tenant_inventory_items
          WHERE tenant_company_id = :tenant_company_id
            AND deleted_at IS NOT NULL
          ORDER BY deleted_at DESC, id DESC
          LIMIT 300'
      );
      $stTrashInventory->execute(['tenant_company_id' => $tenantCompanyId]);
      $trashInventoryItems = $stTrashInventory->fetchAll();
    } catch (Throwable $invTrashErr) {
      $trashInventoryItems = [];
    }

    try {
      $stServiceOrders = $pdo->prepare(
        'SELECT so.id, so.customer_id, so.codigo, so.titulo, so.descripcion, so.estado, so.prioridad,
                so.fecha_creacion, so.observaciones, so.created_by, so.created_at, so.updated_at,
                c.razon_social AS customer_name, c.nombre_fantasia AS customer_fantasia
           FROM tenant_service_orders so
           LEFT JOIN tenant_customers c
             ON c.id = so.customer_id AND c.tenant_company_id = so.tenant_company_id
          WHERE so.tenant_company_id = :tc AND so.deleted_at IS NULL
          ORDER BY so.id DESC
          LIMIT 300'
      );
      $stServiceOrders->execute(['tc' => $tenantCompanyId]);
      $serviceOrders = $stServiceOrders->fetchAll();

      $stTrashSo = $pdo->prepare(
        'SELECT so.id, so.codigo, so.titulo, so.estado, so.deleted_at, so.deleted_by,
                c.razon_social AS customer_name
           FROM tenant_service_orders so
           LEFT JOIN tenant_customers c
             ON c.id = so.customer_id AND c.tenant_company_id = so.tenant_company_id
          WHERE so.tenant_company_id = :tc AND so.deleted_at IS NOT NULL
          ORDER BY so.deleted_at DESC, so.id DESC
          LIMIT 300'
      );
      $stTrashSo->execute(['tc' => $tenantCompanyId]);
      $trashServiceOrders = $stTrashSo->fetchAll();

      if (!empty($serviceOrders)) {
        $soIds = array_map(static fn($r) => (int)$r['id'], $serviceOrders);
        $phSo = implode(',', array_fill(0, count($soIds), '?'));
        $stAss = $pdo->prepare("SELECT id, service_order_id, technician_id, technician_nombre, work_date, start_time, end_time, notas FROM tenant_service_order_assignments WHERE service_order_id IN ($phSo) ORDER BY work_date ASC, id ASC");
        $stAss->execute($soIds);
        foreach ($stAss->fetchAll() as $ar) {
          $serviceOrderAssignmentsByOrder[(int)$ar['service_order_id']][] = $ar;
        }
        $stPts = $pdo->prepare("SELECT id, service_order_id, inventory_item_id, sku, nombre, unidad, cantidad, notas FROM tenant_service_order_parts WHERE service_order_id IN ($phSo) ORDER BY id ASC");
        $stPts->execute($soIds);
        foreach ($stPts->fetchAll() as $pr) {
          $serviceOrderPartsByOrder[(int)$pr['service_order_id']][] = $pr;
        }
        $stCl = $pdo->prepare("SELECT id, service_order_id, orden, descripcion, completado, completado_at, completado_by FROM tenant_service_order_checklist WHERE service_order_id IN ($phSo) ORDER BY orden ASC, id ASC");
        $stCl->execute($soIds);
        foreach ($stCl->fetchAll() as $cr) {
          $serviceOrderChecklistByOrder[(int)$cr['service_order_id']][] = $cr;
        }

        if (table_exists($pdo, 'tenant_service_order_form_templates')) {
          $stSoTpl = $pdo->prepare("SELECT service_order_id, form_template_id FROM tenant_service_order_form_templates WHERE tenant_company_id = ? AND service_order_id IN ($phSo) ORDER BY sort_order ASC, id ASC");
          $stSoTpl->execute(array_merge([$tenantCompanyId], $soIds));
          foreach ($stSoTpl->fetchAll() as $srTpl) {
            $serviceOrderFormTemplatesByOrder[(int)$srTpl['service_order_id']][] = (int)$srTpl['form_template_id'];
          }
        }
      }

      if (table_exists($pdo, 'tenant_form_templates')) {
        $stFormTemplates = $pdo->prepare(
          'SELECT id, name, description, fields_json, is_active, created_at
             FROM tenant_form_templates
            WHERE tenant_company_id = :tc
              AND is_active = 1
            ORDER BY id DESC'
        );
        $stFormTemplates->execute(['tc' => $tenantCompanyId]);
        foreach ($stFormTemplates->fetchAll() as $tplRow) {
          $tplRow['fields'] = service_form_template_fields_normalize($tplRow['fields_json'] ?? '[]');
          $formTemplates[] = $tplRow;
        }
      }
    } catch (Throwable $soFetchErr) {
      $serviceOrders = [];
      $trashServiceOrders = [];
      $serviceOrderAssignmentsByOrder = [];
      $serviceOrderPartsByOrder = [];
      $serviceOrderChecklistByOrder = [];
      $serviceOrderFormTemplatesByOrder = [];
      $formTemplates = [];
    }

    $formTemplatesById = [];
    foreach ($formTemplates as $tplRow) {
      $formTemplatesById[(int)($tplRow['id'] ?? 0)] = $tplRow;
    }
    foreach ($serviceOrderFormTemplatesByOrder as $soIdTpl => $tplIds) {
      $reportFormTemplatesCatalogByServiceOrder[$soIdTpl] = [];
      foreach ((array)$tplIds as $tplId) {
        if (!isset($formTemplatesById[(int)$tplId])) {
          continue;
        }
        $tplRow = $formTemplatesById[(int)$tplId];
        $reportFormTemplatesCatalogByServiceOrder[$soIdTpl][] = [
          'id' => (int)$tplRow['id'],
          'name' => (string)$tplRow['name'],
          'description' => (string)($tplRow['description'] ?? ''),
          'fields' => service_form_template_fields_normalize($tplRow['fields'] ?? []),
        ];
      }
    }

    try {
      $stAssignable = $pdo->prepare(
        'SELECT DISTINCT
            sa.technician_id,
            t.full_name AS technician_full_name,
            so.id AS service_order_id,
            so.codigo,
            so.titulo,
            c.razon_social AS customer_name
         FROM tenant_service_order_assignments sa
         INNER JOIN tenant_service_orders so
           ON so.id = sa.service_order_id
          AND so.tenant_company_id = sa.tenant_company_id
          AND so.deleted_at IS NULL
         LEFT JOIN tenant_customers c
           ON c.id = so.customer_id
          AND c.tenant_company_id = so.tenant_company_id
         LEFT JOIN tenant_technicians t
           ON t.id = sa.technician_id
          AND t.company_id = sa.tenant_company_id
        WHERE sa.tenant_company_id = :tc
        ORDER BY sa.technician_id ASC, so.id DESC'
      );
      $stAssignable->execute(['tc' => $tenantCompanyId]);
      foreach ($stAssignable->fetchAll() as $asRow) {
        $techId = (int)($asRow['technician_id'] ?? 0);
        $soId = (int)($asRow['service_order_id'] ?? 0);
        if ($techId <= 0 || $soId <= 0) {
          continue;
        }
        if (!isset($serviceOrderOptionsByTechnician[$techId])) {
          $serviceOrderOptionsByTechnician[$techId] = [
            'technician_id' => $techId,
            'technician_name' => trim((string)($asRow['technician_full_name'] ?? '')),
            'orders' => [],
          ];
        }
        $serviceOrderOptionsByTechnician[$techId]['orders'][] = [
          'service_order_id' => $soId,
          'codigo' => (string)($asRow['codigo'] ?? ''),
          'titulo' => (string)($asRow['titulo'] ?? ''),
          'customer_name' => (string)($asRow['customer_name'] ?? ''),
        ];
      }
    } catch (Throwable $assignableErr) {
      $serviceOrderOptionsByTechnician = [];
    }

    try {
      if (!table_exists($pdo, 'tenant_service_reports')) {
        $serviceReports = service_reports_fallback_load($tenantCompanyId);
        $soById = [];
        foreach ((array)$serviceOrders as $soRow) {
          $soById[(int)($soRow['id'] ?? 0)] = $soRow;
        }
        $techById = [];
        foreach ((array)$technicians as $tRow) {
          $tid = (int)($tRow['id'] ?? 0);
          if ($tid <= 0) {
            continue;
          }
          $techById[$tid] = trim((string)($tRow['nombre'] ?? '') . ' ' . (string)($tRow['apellido'] ?? ''));
        }

        foreach ($serviceReports as &$fbRow) {
          if (trim((string)($fbRow['deleted_at'] ?? '')) !== '') {
            continue;
          }
          $fbSoId = (int)($fbRow['service_order_id'] ?? 0);
          $fbTechId = (int)($fbRow['technician_id'] ?? 0);
          $soInfo = $soById[$fbSoId] ?? [];
          $fbRow['service_order_code'] = (string)($soInfo['codigo'] ?? ('OS #' . $fbSoId));
          $fbRow['service_order_title'] = (string)($soInfo['titulo'] ?? '');
          $fbRow['customer_name'] = (string)($soInfo['customer_name'] ?? '');
          $fbRow['technician_full_name'] = (string)($techById[$fbTechId] ?? ('Tecnico #' . $fbTechId));
          $fbRow['photo_records'] = service_report_photo_records_normalize($fbRow['photo_records'] ?? null);
          $fbRow['form_photo_records'] = service_report_photo_records_normalize($fbRow['form_photo_records'] ?? null);
          $fbRow['forms_payload'] = service_form_effective_payload_for_service_order(
            $fbRow['forms_payload'] ?? '[]',
            (int)($fbRow['service_order_id'] ?? 0),
            $reportFormTemplatesCatalogByServiceOrder
          );
        }
        $serviceReports = array_values(array_filter($serviceReports, static fn($row) => is_array($row) && trim((string)($row['deleted_at'] ?? '')) === ''));
        unset($fbRow);
      } else {
        $stReports = $pdo->prepare(
        'SELECT
            r.id, r.service_order_id, r.technician_id, r.report_date,
            r.work_done, r.external_purchases, r.observations, r.additional_details,
            r.forms_note, r.forms_payload, r.photo_records, r.form_photo_records, r.technician_signature, r.customer_signature,
            r.technician_signature_draw, r.customer_signature_draw,
            r.created_by, r.created_at,
            so.codigo AS service_order_code,
            so.titulo AS service_order_title,
            c.razon_social AS customer_name,
            t.full_name AS technician_full_name
         FROM tenant_service_reports r
         INNER JOIN tenant_service_orders so
           ON so.id = r.service_order_id
          AND so.tenant_company_id = r.tenant_company_id
         LEFT JOIN tenant_customers c
           ON c.id = so.customer_id
          AND c.tenant_company_id = so.tenant_company_id
         LEFT JOIN tenant_technicians t
           ON t.id = r.technician_id
          AND t.company_id = r.tenant_company_id
        WHERE r.tenant_company_id = :tc
          AND r.deleted_at IS NULL
        ORDER BY r.report_date DESC, r.id DESC
        LIMIT 300'
        );
        $stReports->execute(['tc' => $tenantCompanyId]);
        $serviceReports = $stReports->fetchAll();
        foreach ($serviceReports as &$srRow) {
          $srRow['photo_records'] = service_report_photo_records_normalize($srRow['photo_records'] ?? null);
          $srRow['form_photo_records'] = service_report_photo_records_normalize($srRow['form_photo_records'] ?? null);
          $srRow['forms_payload'] = service_form_effective_payload_for_service_order(
            $srRow['forms_payload'] ?? '[]',
            (int)($srRow['service_order_id'] ?? 0),
            $reportFormTemplatesCatalogByServiceOrder
          );
        }
        unset($srRow);
      }
    } catch (Throwable $reportFetchErr) {
      $serviceReports = [];
    }

    try {
      if (!table_exists($pdo, 'tenant_service_reports')) {
        $fallbackRows = service_reports_fallback_load($tenantCompanyId);
        $soById = [];
        foreach ((array)$serviceOrders as $soRow) {
          $soById[(int)($soRow['id'] ?? 0)] = $soRow;
        }
        $techById = [];
        foreach ((array)$technicians as $tRow) {
          $tid = (int)($tRow['id'] ?? 0);
          if ($tid <= 0) {
            continue;
          }
          $techById[$tid] = trim((string)($tRow['nombre'] ?? '') . ' ' . (string)($tRow['apellido'] ?? ''));
        }

        foreach ((array)$fallbackRows as $fbRow) {
          if (!is_array($fbRow) || trim((string)($fbRow['deleted_at'] ?? '')) === '') {
            continue;
          }
          $fbSoId = (int)($fbRow['service_order_id'] ?? 0);
          $fbTechId = (int)($fbRow['technician_id'] ?? 0);
          $soInfo = $soById[$fbSoId] ?? [];
          $fbRow['service_order_code'] = (string)($soInfo['codigo'] ?? ('OS #' . $fbSoId));
          $fbRow['service_order_title'] = (string)($soInfo['titulo'] ?? '');
          $fbRow['technician_full_name'] = (string)($techById[$fbTechId] ?? ('Tecnico #' . $fbTechId));
          $trashServiceReports[] = $fbRow;
        }
      } else {
        $stTrashReports = $pdo->prepare(
          'SELECT
              r.id, r.service_order_id, r.technician_id, r.report_date,
              r.work_done, r.deleted_at, r.deleted_by,
              so.codigo AS service_order_code,
              so.titulo AS service_order_title,
              t.full_name AS technician_full_name
           FROM tenant_service_reports r
           LEFT JOIN tenant_service_orders so
             ON so.id = r.service_order_id
            AND so.tenant_company_id = r.tenant_company_id
           LEFT JOIN tenant_technicians t
             ON t.id = r.technician_id
            AND t.company_id = r.tenant_company_id
          WHERE r.tenant_company_id = :tc
            AND r.deleted_at IS NOT NULL
          ORDER BY r.deleted_at DESC, r.id DESC
          LIMIT 300'
        );
        $stTrashReports->execute(['tc' => $tenantCompanyId]);
        $trashServiceReports = $stTrashReports->fetchAll();
      }
    } catch (Throwable $trashReportsErr) {
      $trashServiceReports = [];
    }

    if (!empty($quotes)) {
      $quoteIds = array_map(static fn($row) => (int)$row['id'], $quotes);
      $quoteIds = array_values(array_filter($quoteIds, static fn($id) => $id > 0));
      if (!empty($quoteIds)) {
        $placeholders = implode(',', array_fill(0, count($quoteIds), '?'));
        $stItems = $pdo->prepare(
          "SELECT tenant_quote_id, descripcion, item_type, is_bold, cantidad, precio_unitario, total_linea
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
              q.descuento_pct, q.subtotal, q.total, q.estado, q.terminos_condiciones_adicionales,
              q.validez_override, q.entrega_override, q.condicion_de_pago_override, q.moneda_override,
              q.observaciones,
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
            'SELECT descripcion, item_type, is_bold, cantidad, precio_unitario, total_linea
             FROM tenant_quote_items
             WHERE tenant_quote_id = :tenant_quote_id
             ORDER BY orden ASC, id ASC'
          );
          $stPreviewItems->execute(['tenant_quote_id' => $previewQuoteId]);
          $quotePreviewItems = $stPreviewItems->fetchAll();
        }
      }
    }

    if ($module === 'ordenes-servicio') {
      $previewServiceOrderId = (int)($_GET['view_service_order_id'] ?? 0);
      if ($previewServiceOrderId > 0) {
        $stSoPreview = $pdo->prepare(
          'SELECT so.id, so.codigo, so.titulo, so.descripcion, so.estado, so.prioridad,
                  so.fecha_creacion, so.observaciones, so.created_at,
                  c.razon_social AS customer_name, c.rut AS customer_rut,
                  c.contacto AS customer_contacto, c.email AS customer_email, c.direccion AS customer_direccion
             FROM tenant_service_orders so
             LEFT JOIN tenant_customers c
               ON c.id = so.customer_id
              AND c.tenant_company_id = so.tenant_company_id
            WHERE so.id = :id
              AND so.tenant_company_id = :tenant_company_id
              AND so.deleted_at IS NULL
            LIMIT 1'
        );
        $stSoPreview->execute([
          'id' => $previewServiceOrderId,
          'tenant_company_id' => $tenantCompanyId,
        ]);
        $serviceOrderPreview = $stSoPreview->fetch();

        if ($serviceOrderPreview) {
          $stSoAssign = $pdo->prepare(
            'SELECT technician_nombre, work_date, start_time, end_time, notas
               FROM tenant_service_order_assignments
              WHERE tenant_company_id = :tenant_company_id
                AND service_order_id = :service_order_id
              ORDER BY work_date ASC, id ASC'
          );
          $stSoAssign->execute([
            'tenant_company_id' => $tenantCompanyId,
            'service_order_id' => $previewServiceOrderId,
          ]);
          $serviceOrderPreviewAssignments = $stSoAssign->fetchAll();

          $stSoParts = $pdo->prepare(
            'SELECT sku, nombre, unidad, cantidad, notas
               FROM tenant_service_order_parts
              WHERE tenant_company_id = :tenant_company_id
                AND service_order_id = :service_order_id
              ORDER BY id ASC'
          );
          $stSoParts->execute([
            'tenant_company_id' => $tenantCompanyId,
            'service_order_id' => $previewServiceOrderId,
          ]);
          $serviceOrderPreviewParts = $stSoParts->fetchAll();

          $stSoChecklist = $pdo->prepare(
            'SELECT descripcion, completado, completado_at, completado_by
               FROM tenant_service_order_checklist
              WHERE tenant_company_id = :tenant_company_id
                AND service_order_id = :service_order_id
              ORDER BY orden ASC, id ASC'
          );
          $stSoChecklist->execute([
            'tenant_company_id' => $tenantCompanyId,
            'service_order_id' => $previewServiceOrderId,
          ]);
          $serviceOrderPreviewChecklist = $stSoChecklist->fetchAll();

          $previewReportsRows = [];
          if (table_exists($pdo, 'tenant_service_reports')) {
            $stSoReports = $pdo->prepare(
              'SELECT
                  r.technician_id, r.report_date,
                  r.work_done, r.external_purchases, r.observations, r.additional_details,
                  r.forms_note, r.forms_payload, r.photo_records, r.form_photo_records, r.technician_signature, r.customer_signature,
                  r.technician_signature_draw, r.customer_signature_draw,
                  r.created_at,
                  t.full_name AS technician_full_name
               FROM tenant_service_reports r
               LEFT JOIN tenant_technicians t
                 ON t.id = r.technician_id
                AND t.company_id = r.tenant_company_id
              WHERE r.tenant_company_id = :tenant_company_id
                AND r.service_order_id = :service_order_id
                AND r.deleted_at IS NULL
              ORDER BY r.technician_id ASC, r.report_date ASC, r.id ASC'
            );
            $stSoReports->execute([
              'tenant_company_id' => $tenantCompanyId,
              'service_order_id' => $previewServiceOrderId,
            ]);
            $previewReportsRows = $stSoReports->fetchAll();
          } else {
            $fallbackRows = service_reports_fallback_load($tenantCompanyId);
            foreach ($fallbackRows as $fbRow) {
              if ((int)($fbRow['service_order_id'] ?? 0) !== $previewServiceOrderId) {
                continue;
              }
              if (trim((string)($fbRow['deleted_at'] ?? '')) !== '') {
                continue;
              }
              $previewReportsRows[] = [
                'technician_id' => (int)($fbRow['technician_id'] ?? 0),
                'report_date' => (string)($fbRow['report_date'] ?? ''),
                'work_done' => (string)($fbRow['work_done'] ?? ''),
                'external_purchases' => (string)($fbRow['external_purchases'] ?? ''),
                'observations' => (string)($fbRow['observations'] ?? ''),
                'additional_details' => (string)($fbRow['additional_details'] ?? ''),
                'forms_note' => (string)($fbRow['forms_note'] ?? ''),
                'forms_payload' => service_form_response_payload_normalize($fbRow['forms_payload'] ?? '[]'),
                'photo_records' => $fbRow['photo_records'] ?? [],
                'form_photo_records' => $fbRow['form_photo_records'] ?? [],
                'technician_signature' => (string)($fbRow['technician_signature'] ?? ''),
                'customer_signature' => (string)($fbRow['customer_signature'] ?? ''),
                'technician_signature_draw' => (string)($fbRow['technician_signature_draw'] ?? ''),
                'customer_signature_draw' => (string)($fbRow['customer_signature_draw'] ?? ''),
                'created_at' => (string)($fbRow['created_at'] ?? ''),
                'technician_full_name' => '',
              ];
            }
          }

          if (!empty($previewReportsRows)) {
            $techNameMap = [];
            foreach ((array)$technicians as $techRow) {
              $techId = (int)($techRow['id'] ?? 0);
              if ($techId <= 0) {
                continue;
              }
              $techNameMap[$techId] = trim((string)($techRow['nombre'] ?? '') . ' ' . (string)($techRow['apellido'] ?? ''));
            }

            foreach ($previewReportsRows as $repRow) {
              $repTechId = (int)($repRow['technician_id'] ?? 0);
              $repTechName = trim((string)($repRow['technician_full_name'] ?? ''));
              if ($repTechName === '' && $repTechId > 0) {
                $repTechName = (string)($techNameMap[$repTechId] ?? '');
              }
              if ($repTechName === '') {
                $repTechName = ($repTechId > 0 ? ('Tecnico #' . $repTechId) : 'Tecnico sin identificar');
              }

              $repRow['photo_records'] = service_report_photo_records_normalize($repRow['photo_records'] ?? null);
              $repRow['form_photo_records'] = service_report_photo_records_normalize($repRow['form_photo_records'] ?? null);
              $repRow['forms_payload'] = service_form_effective_payload_for_service_order(
                $repRow['forms_payload'] ?? '[]',
                $previewServiceOrderId,
                $reportFormTemplatesCatalogByServiceOrder
              );
              if (!isset($serviceOrderPreviewReportsByTechnician[$repTechName])) {
                $serviceOrderPreviewReportsByTechnician[$repTechName] = [];
              }
              $serviceOrderPreviewReportsByTechnician[$repTechName][] = $repRow;
            }
          }
        }
      }
    }

    if ($quoteForm['numero_cotizacion'] === '') {
      $quoteForm['numero_cotizacion'] = next_quote_number($pdo, $tenantCompanyId);
    }

    $heroeOnlyModules = ['inventario', 'ordenes-servicio', 'reportes', 'formularios', 'tecnicos', 'carta-gantt'];
    $currentPlanForModules = normalize_plan_code((string)$usage['plan_code'], 'basico');
    $canAccessHeroeModules = in_array($currentPlanForModules, ['pro', 'enterprise', 'olimpico'], true);
    if (in_array($module, $heroeOnlyModules, true) && !$canAccessHeroeModules) {
      $flash['error'] = 'Tu plan actual no incluye este modulo. Actualiza a Heroe o superior para habilitarlo.';
      $module = 'plan';
    }
} catch (Throwable $e) {
    error_log('HERMES_COMPANY_DASHBOARD_ERROR: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    $flash['error'] = 'No fue posible cargar el panel de empresa por un error de base de datos.';
}

$bodyClass = 'module-' . $module;
$quoteEmbed = isset($_GET['quote_embed']) && (string)$_GET['quote_embed'] === '1';
$soEmbed = isset($_GET['so_embed']) && (string)$_GET['so_embed'] === '1';
$heroeOnlyModules = ['inventario', 'ordenes-servicio', 'reportes', 'formularios', 'tecnicos', 'carta-gantt'];
$currentPlanForModules = normalize_plan_code((string)$usage['plan_code'], 'basico');
$canAccessHeroeModules = in_array($currentPlanForModules, ['pro', 'enterprise', 'olimpico'], true);

if ($module === 'ordenes-servicio' && is_array($serviceOrderPreview) && !empty($serviceOrderPreview)) {
  ?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vista OS <?= h((string)$serviceOrderPreview['codigo']) ?></title>
  <style>
    @page { size: Letter; margin: 12mm; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Segoe UI, Arial, sans-serif;
      background: linear-gradient(180deg, #dbe7ff 0%, #e8eef9 100%);
      color: #111827;
      padding: 10px;
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
      width: min(9.6in, calc(100vw - 20px));
      min-height: 11in;
      margin: 0 auto;
      background: #fff;
      border: 1px solid #c3d4f5;
      border-radius: 10px;
      padding: 8mm 9mm;
      box-shadow: 0 10px 24px rgba(0,0,0,.12);
      display: flex;
      flex-direction: column;
    }
    .head {
      display: grid;
      grid-template-columns: 190px minmax(0, 1.55fr) minmax(180px, 1fr);
      gap: 14px;
      align-items: start;
      margin-bottom: 14px;
      border-bottom: 2px solid #123b79;
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
    .head-ot {
      text-align: right;
      display: grid;
      gap: 4px;
      align-content: start;
    }
    .doc-logo-wrap {
      max-height: 92px;
      display: flex;
      align-items: center;
    }
    .doc-logo {
      max-height: 92px;
      max-width: 280px;
      width: auto;
      height: auto;
      object-fit: contain;
      display: block;
    }
    .head h1 {
      margin: 0;
      font-size: 20px;
      letter-spacing: .03em;
      line-height: 1.2;
      color: #0f2f63;
    }
    .muted {
      color: #4b5563;
      font-size: 12px;
      line-height: 1.35;
    }
    .head-company .muted,
    .head-ot .muted { font-size: 12px; line-height: 1.25; color: #4b5563; }
    .doc-label {
      font-size: 11px;
      color: #6b7280;
      text-transform: uppercase;
      letter-spacing: .08em;
      font-weight: 700;
    }
    .doc-number {
      font-size: 18px;
      font-weight: 800;
      line-height: 1.15;
      color: #0f172a;
      word-break: break-word;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 14px;
    }
    .card {
      border: 1px solid #c5d8fb;
      border-radius: 10px;
      padding: 11px;
      background: linear-gradient(180deg, #f9fcff 0%, #f3f8ff 100%);
    }
    .card h3 {
      margin: 0 0 10px;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: #123b79;
      border-bottom: 1px solid #d7e5fb;
      padding-bottom: 6px;
    }
    .card .muted {
      margin-bottom: 4px;
    }
    .card .muted strong {
      color: #163e7a;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      font-size: 13px;
      table-layout: fixed;
    }
    th, td {
      border: 1px solid #bfdbfe;
      padding: 7px;
      vertical-align: top;
      text-align: left;
    }
    th {
      background: #d6e8ff;
      color: #133a76;
    }
    tbody tr:nth-child(even) td {
      background: #f4f9ff;
    }
    .section { margin-top: 10px; }
    .section h3 {
      margin: 0 0 8px;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: #1b3f7a;
      border-left: 4px solid #1d4ed8;
      padding-left: 8px;
      line-height: 1.2;
    }
    .obs {
      margin-top: 14px;
      border: 1px solid #d1d5db;
      border-radius: 8px;
      padding: 10px;
      white-space: pre-line;
      font-size: 13px;
      background: #fff;
    }
    .foot-note {
      margin-top: 12px;
      font-size: 12px;
      color: #6b7280;
      text-align: right;
    }
    .so-report-photo-grid {
      margin-top: 6px;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }
    .so-report-photo-card {
      border: 1px solid #bfdbfe;
      border-radius: 8px;
      background: #ffffff;
      padding: 6px;
      display: grid;
      gap: 6px;
      grid-template-rows: 200px auto;
      min-width: 0;
      overflow: hidden;
      page-break-inside: avoid;
      break-inside: avoid;
    }
    .so-report-photo-card img {
      display: block;
      width: 100%;
      max-width: 100%;
      height: 200px;
      min-height: 200px;
      max-height: 200px;
      object-fit: contain;
      object-position: center;
      border: 1px solid #bfdbfe;
      border-radius: 6px;
      box-sizing: border-box;
      background: #f8fafc;
    }
    .so-report-photo-name {
      font-size: 11px;
      color: #334155;
      line-height: 1.25;
      word-break: break-word;
    }
    .so-report-entry {
      border: 1px solid #dbeafe;
      border-radius: 9px;
      padding: 9px;
      margin-bottom: 9px;
      background: linear-gradient(180deg, #f9fcff 0%, #f4f8ff 100%);
      page-break-inside: avoid;
      break-inside: avoid;
    }
    .so-report-meta {
      margin-bottom: 7px;
      font-size: 11px;
      color: #4b5563;
      border-bottom: 1px dashed #d5e2f8;
      padding-bottom: 6px;
    }
    .so-report-field {
      margin-bottom: 6px;
    }
    .so-report-label {
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .04em;
      color: #18448a;
      margin-bottom: 2px;
    }
    .so-report-signatures {
      margin-top: 7px;
      padding-top: 7px;
      border-top: 1px dashed #d5e2f8;
      font-size: 12px;
      color: #1f2937;
    }
    .so-sign-grid {
      margin-top: 4px;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .so-sign-box {
      border: 1px solid #bfd3f8;
      border-radius: 8px;
      background: #fff;
      padding: 7px;
      min-height: 118px;
      display: grid;
      grid-template-rows: auto auto auto auto;
      gap: 4px;
    }
    .so-sign-role {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .04em;
      color: #1b3f7a;
    }
    .so-sign-meta {
      font-size: 11px;
      color: #334155;
      line-height: 1.25;
      word-break: break-word;
    }
    .so-sign-space {
      border: 1px dashed #95afd9;
      border-radius: 6px;
      min-height: 200px;
      height: 200px;
      max-height: 200px;
      background: linear-gradient(180deg, #fbfdff 0%, #f5f9ff 100%);
      position: relative;
      overflow: hidden;
    }
    .so-sign-space img {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      object-fit: contain;
      background: #fff;
    }
    .so-sign-space.is-empty::after {
      content: 'Espacio para firma';
      position: absolute;
      left: 50%;
      top: 50%;
      transform: translate(-50%, -50%);
      font-size: 10px;
      color: #90a3c3;
      text-transform: uppercase;
      letter-spacing: .04em;
      white-space: nowrap;
    }
    @media (max-width: 860px) {
      .head { grid-template-columns: 1fr; }
      .head-ot { text-align: left; }
      .head-logo { min-height: 64px; }
      .doc-logo { max-height: 64px; }
      .grid { grid-template-columns: 1fr; }
      .so-report-photo-grid { grid-template-columns: 1fr; }
      .so-sign-grid { grid-template-columns: 1fr; }
    }
    @media print {
      html, body {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      .so-report-photo-grid {
        display: grid !important;
        grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
        gap: 8px !important;
      }
      .so-report-photo-card {
        page-break-inside: avoid;
        break-inside: avoid;
      }
      body { background: #fff; padding: 0; }
      .tools { display: none; }
      .page {
        width: auto;
        min-height: calc(11in - 24mm);
        border: 0;
        box-shadow: none;
        margin: 0;
        padding: 0;
      }
    }
    <?php if ($soEmbed): ?>
    body {
      background: #0b1734;
      padding: 0;
    }
    .tools { display: none; }
    .page {
      margin: 0 auto;
      box-shadow: none;
      border: 0;
    }
    <?php endif; ?>
  </style>
</head>
<body>
  <?php if (!$soEmbed): ?>
    <div class="tools">
      <a class="btn" href="/empresa/dashboard/?module=ordenes-servicio">Volver</a>
      <button class="btn primary" type="button" onclick="window.print()">Imprimir</button>
    </div>
  <?php endif; ?>

  <article class="page">
    <header class="head">
      <div class="head-logo">
        <?php if ($logoPublicUrl !== ''): ?>
          <div class="doc-logo-wrap">
            <img class="doc-logo" src="<?= h($logoPublicUrl) ?>" alt="Logo empresa">
          </div>
        <?php endif; ?>
      </div>
      <div class="head-company">
        <h1><?= h($profile['nombre'] !== '' ? $profile['nombre'] : 'Empresa') ?></h1>
        <div class="muted">RUT: <?= h((string)$profile['rut']) ?></div>
        <div class="muted">Email: <?= h((string)$profile['email_principal']) ?></div>
        <?php if (trim((string)$profile['direccion']) !== ''): ?>
          <div class="muted">Direccion: <?= h((string)$profile['direccion']) ?></div>
        <?php endif; ?>
        <?php if (trim((string)$profile['telefono']) !== ''): ?>
          <div class="muted">Telefono: <?= h((string)$profile['telefono']) ?></div>
        <?php endif; ?>
      </div>
      <div class="head-ot">
        <div class="doc-label">Orden de servicio</div>
        <div class="doc-number"><?= h((string)$serviceOrderPreview['codigo']) ?></div>
        <div class="muted">Fecha: <?= h((string)$serviceOrderPreview['fecha_creacion']) ?></div>
        <div class="muted">Estado: <?= h((string)$serviceOrderPreview['estado']) ?></div>
        <div class="muted">Prioridad: <?= h((string)$serviceOrderPreview['prioridad']) ?></div>
      </div>
    </header>

    <section class="grid">
      <div class="card">
        <h3>Cliente</h3>
        <div><strong><?= h((string)($serviceOrderPreview['customer_name'] ?? '')) ?></strong></div>
        <div class="muted">RUT: <?= h((string)($serviceOrderPreview['customer_rut'] ?? '')) ?></div>
        <div class="muted">Contacto: <?= h((string)($serviceOrderPreview['customer_contacto'] ?? '')) ?></div>
        <div class="muted">Email: <?= h((string)($serviceOrderPreview['customer_email'] ?? '')) ?></div>
        <div class="muted">Direccion: <?= h((string)($serviceOrderPreview['customer_direccion'] ?? '')) ?></div>
      </div>
      <div class="card">
        <h3>Datos OS</h3>
        <div class="muted"><strong>Titulo:</strong> <?= h((string)$serviceOrderPreview['titulo']) ?></div>
        <div class="muted"><strong>Descripcion:</strong> <?= h((string)($serviceOrderPreview['descripcion'] ?? '')) ?></div>
        <div class="muted"><strong>Creada:</strong> <?= h((string)($serviceOrderPreview['created_at'] ?? '')) ?></div>
      </div>
    </section>

    <section class="section">
      <h3>Jornadas y tecnicos asignados</h3>
      <?php if (empty($serviceOrderPreviewAssignments)): ?>
        <div class="muted">Sin jornadas asignadas.</div>
      <?php else: ?>
        <table>
          <thead>
            <tr><th style="width:30%;">Tecnico</th><th style="width:18%;">Fecha</th><th style="width:12%;">Inicio</th><th style="width:12%;">Fin</th><th style="width:28%;">Notas</th></tr>
          </thead>
          <tbody>
            <?php foreach ($serviceOrderPreviewAssignments as $aRow): ?>
              <tr>
                <td><?= h((string)$aRow['technician_nombre']) ?></td>
                <td><?= h((string)$aRow['work_date']) ?></td>
                <td><?= h((string)($aRow['start_time'] ?? '')) ?></td>
                <td><?= h((string)($aRow['end_time'] ?? '')) ?></td>
                <td><?= h((string)($aRow['notas'] ?? '')) ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      <?php endif; ?>
    </section>

    <section class="section">
      <h3>Repuestos previstos</h3>
      <?php if (empty($serviceOrderPreviewParts)): ?>
        <div class="muted">Sin repuestos asociados.</div>
      <?php else: ?>
        <table>
          <thead>
            <tr><th style="width:20%;">SKU</th><th style="width:35%;">Nombre</th><th style="width:10%;">Unidad</th><th style="width:10%;">Cantidad</th><th style="width:25%;">Notas</th></tr>
          </thead>
          <tbody>
            <?php foreach ($serviceOrderPreviewParts as $pRow): ?>
              <tr>
                <td><?= h((string)$pRow['sku']) ?></td>
                <td><?= h((string)$pRow['nombre']) ?></td>
                <td><?= h((string)$pRow['unidad']) ?></td>
                <td><?= h((string)$pRow['cantidad']) ?></td>
                <td><?= h((string)($pRow['notas'] ?? '')) ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      <?php endif; ?>
    </section>

    <section class="section">
      <h3>Checklist operativo</h3>
      <?php if (empty($serviceOrderPreviewChecklist)): ?>
        <div class="muted">Sin checklist definido.</div>
      <?php else: ?>
        <table>
          <thead>
            <tr><th style="width:64%;">Item</th><th style="width:12%;">Estado</th><th style="width:24%;">Completado</th></tr>
          </thead>
          <tbody>
            <?php foreach ($serviceOrderPreviewChecklist as $cRow): ?>
              <?php $isDone = ((int)($cRow['completado'] ?? 0) === 1); ?>
              <tr>
                <td><?= h((string)$cRow['descripcion']) ?></td>
                <td><?= $isDone ? 'Hecho' : 'Pendiente' ?></td>
                <td><?= h((string)($cRow['completado_at'] ?? '')) ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      <?php endif; ?>
    </section>

    <section class="section">
      <h3>Reportes tecnicos asociados</h3>
      <?php if (empty($serviceOrderPreviewReportsByTechnician)): ?>
        <div class="muted">Sin reportes asociados a esta OS.</div>
      <?php else: ?>
        <?php foreach ($serviceOrderPreviewReportsByTechnician as $techName => $techReports): ?>
            <?php foreach ((array)$techReports as $reportRow): ?>
              <div class="so-report-entry">
                <div class="so-report-meta"><strong>Fecha:</strong> <?= h((string)($reportRow['report_date'] ?? '')) ?><?php if (trim((string)($reportRow['created_at'] ?? '')) !== ''): ?> | <strong>Registro:</strong> <?= h((string)$reportRow['created_at']) ?><?php endif; ?></div>

                <div class="so-report-field"><span class="so-report-label">Trabajo realizado</span><br><?= report_items_to_html((string)($reportRow['work_done'] ?? '')) ?></div>

                <?php if (trim((string)($reportRow['external_purchases'] ?? '')) !== ''): ?>
                  <div class="so-report-field"><span class="so-report-label">Compras externas</span><br><?= report_items_to_html((string)$reportRow['external_purchases']) ?></div>
                <?php endif; ?>

                <?php if (trim((string)($reportRow['observations'] ?? '')) !== ''): ?>
                  <div class="so-report-field"><span class="so-report-label">Observaciones</span><br><?= report_items_to_html((string)$reportRow['observations']) ?></div>
                <?php endif; ?>

                <?php if (trim((string)($reportRow['additional_details'] ?? '')) !== ''): ?>
                  <div class="so-report-field"><span class="so-report-label">Adicionales</span><br><?= nl2br(h((string)$reportRow['additional_details'])) ?></div>
                <?php endif; ?>

                <?php $formsPayloadRows = service_form_response_payload_normalize($reportRow['forms_payload'] ?? '[]'); ?>
                <?php if (!empty($formsPayloadRows)): ?>
                  <div class="so-report-field">
                    <?php foreach ($formsPayloadRows as $tplPayload): ?>
                      <?php
                        $tplIdPayload = (int)($tplPayload['template_id'] ?? 0);
                        $tplNamePayload = (string)($formTemplatesById[$tplIdPayload]['name'] ?? ('Plantilla #' . $tplIdPayload));
                        $answersPayload = is_array($tplPayload['answers'] ?? null) ? $tplPayload['answers'] : [];
                        $tplFieldsMap = [];
                        $tplFieldsRows = service_form_template_fields_normalize($formTemplatesById[$tplIdPayload]['fields'] ?? []);
                        foreach ($tplFieldsRows as $tplFieldRow) {
                          $tplFieldKey = trim((string)($tplFieldRow['key'] ?? ''));
                          if ($tplFieldKey === '') {
                            continue;
                          }
                          $tplFieldsMap[$tplFieldKey] = trim((string)($tplFieldRow['label'] ?? $tplFieldKey));
                        }
                      ?>
                      <div class="so-report-entry" style="margin-top:6px; margin-bottom:6px; background:#fff;">
                        <div class="so-report-meta"><strong><?= h($tplNamePayload) ?></strong></div>
                        <?php foreach ($answersPayload as $answerRow): ?>
                          <?php
                            $aKey = trim((string)($answerRow['key'] ?? ''));
                            $aLabel = trim((string)($answerRow['label'] ?? ''));
                            $aType = trim((string)($answerRow['type'] ?? 'texto_corto'));
                            $aText = trim((string)($answerRow['text'] ?? ''));
                            $aChecked = ((string)($answerRow['checked'] ?? '0') === '1');
                            $aStatus = trim((string)($answerRow['status'] ?? ''));
                            if ($aLabel === '') {
                              $aLabel = (string)($tplFieldsMap[$aKey] ?? $aKey);
                            }
                          ?>
                          <div class="so-report-field" style="margin-bottom:3px;">
                            <span class="so-report-label" style="font-size:10px;"><?= h($aLabel !== '' ? $aLabel : $aKey) ?></span><br>
                            <?php if ($aType === 'text_check'): ?>
                              <?= h($aText !== '' ? $aText : '-') ?><?= $aChecked ? ' (check: si)' : ' (check: no)' ?>
                            <?php elseif ($aType === 'semaforo'): ?>
                              Estado: <?= h($aStatus !== '' ? $aStatus : '-') ?><?php if ($aText !== ''): ?> | Nota: <?= h($aText) ?><?php endif; ?>
                            <?php else: ?>
                              <?= h($aText !== '' ? $aText : '-') ?>
                            <?php endif; ?>
                          </div>
                        <?php endforeach; ?>
                      </div>
                    <?php endforeach; ?>
                  </div>
                <?php endif; ?>

                <?php $reportPhotos = (array)($reportRow['photo_records'] ?? []); ?>
                <?php if (!empty($reportPhotos)): ?>
                  <div class="so-report-field"><span class="so-report-label">Registro fotografico</span>
                    <div class="so-report-photo-grid">
                      <?php foreach ($reportPhotos as $photoItem): ?>
                        <?php $photoName = trim((string)($photoItem['name'] ?? 'Foto')); ?>
                        <?php $photoUrl = trim((string)($photoItem['url'] ?? '')); ?>
                        <?php if ($photoUrl === '') { continue; } ?>
                        <div class="so-report-photo-card">
                          <img src="<?= h($photoUrl) ?>" alt="<?= h($photoName !== '' ? $photoName : 'Foto reporte') ?>">
                          <div class="so-report-photo-name"><?= h($photoName !== '' ? $photoName : 'Foto reporte') ?></div>
                        </div>
                      <?php endforeach; ?>
                    </div>
                  </div>
                <?php endif; ?>

                <?php $formPhotos = (array)($reportRow['form_photo_records'] ?? []); ?>
                <?php if (!empty($formPhotos)): ?>
                  <div class="so-report-field"><span class="so-report-label">Fotos de formularios</span>
                    <div class="so-report-photo-grid">
                      <?php foreach ($formPhotos as $photoItem): ?>
                        <?php $photoName = trim((string)($photoItem['name'] ?? 'Foto formulario')); ?>
                        <?php $photoUrl = trim((string)($photoItem['url'] ?? '')); ?>
                        <?php $photoKey = trim((string)($photoItem['field_key'] ?? '')); ?>
                        <?php if ($photoUrl === '') { continue; } ?>
                        <div class="so-report-photo-card">
                          <img src="<?= h($photoUrl) ?>" alt="<?= h($photoName !== '' ? $photoName : 'Foto formulario') ?>">
                          <div class="so-report-photo-name"><?= h($photoName !== '' ? $photoName : 'Foto formulario') ?><?php if ($photoKey !== ''): ?><br><small>Campo: <?= h($photoKey) ?></small><?php endif; ?></div>
                        </div>
                      <?php endforeach; ?>
                    </div>
                  </div>
                <?php endif; ?>

                <?php $pdfTechSig = service_report_signature_decode((string)($reportRow['technician_signature'] ?? '')); ?>
                <?php $pdfCustSig = service_report_signature_decode((string)($reportRow['customer_signature'] ?? '')); ?>
                <?php $pdfTechSigDrawUrl = service_report_signature_draw_public_url((string)($reportRow['technician_signature_draw'] ?? '')); ?>
                <?php $pdfCustSigDrawUrl = service_report_signature_draw_public_url((string)($reportRow['customer_signature_draw'] ?? '')); ?>
                <div class="so-report-signatures">
                  <span class="so-report-label">Firmas</span>
                  <div class="so-sign-grid">
                    <div class="so-sign-box">
                      <div class="so-sign-role">Tecnico</div>
                      <div class="so-sign-meta"><strong>Nombre:</strong> <?= h((string)($pdfTechSig['name'] ?? '')) ?></div>
                      <div class="so-sign-meta"><strong>RUT:</strong> <?= h((string)($pdfTechSig['rut'] ?? '')) ?></div>
                      <div class="so-sign-space<?= $pdfTechSigDrawUrl === '' ? ' is-empty' : '' ?>" aria-hidden="true"><?php if ($pdfTechSigDrawUrl !== ''): ?><img src="<?= h($pdfTechSigDrawUrl) ?>" alt="Firma tecnico"><?php endif; ?></div>
                    </div>
                    <div class="so-sign-box">
                      <div class="so-sign-role">Cliente que recepciona</div>
                      <div class="so-sign-meta"><strong>Nombre:</strong> <?= h((string)($pdfCustSig['name'] ?? '')) ?></div>
                      <div class="so-sign-meta"><strong>RUT:</strong> <?= h((string)($pdfCustSig['rut'] ?? '')) ?></div>
                      <div class="so-sign-space<?= $pdfCustSigDrawUrl === '' ? ' is-empty' : '' ?>" aria-hidden="true"><?php if ($pdfCustSigDrawUrl !== ''): ?><img src="<?= h($pdfCustSigDrawUrl) ?>" alt="Firma cliente"><?php endif; ?></div>
                    </div>
                  </div>
                </div>
              </div>
            <?php endforeach; ?>
        <?php endforeach; ?>
      <?php endif; ?>
    </section>

    <div class="foot-note">Documento operativo OS con detalle de reportes tecnicos asociados.</div>
  </article>
</body>
</html>
<?php
  exit;
}

if ($module === 'cotizaciones' && is_array($quotePreview) && !empty($quotePreview)) {
  $quotePreviewPages = quote_prepare_item_pages(is_array($quotePreviewItems) ? $quotePreviewItems : [], 15);
  $quotePreviewTotalPages = count($quotePreviewPages);
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
    .page + .page {
      margin-top: 14px;
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
      table-layout: fixed;
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
    .quote-items-section tbody tr {
      height: 32px;
    }
    .quote-items-section td.desc-cell {
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
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
    .quote-financials-placeholder .quote-terms-content {
      color: #6b7280;
      font-style: italic;
    }
    .quote-page-indicator {
      margin: 0;
      padding: 10px;
      font-size: 12px;
      color: #374151;
      text-align: right;
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
        min-height: calc(11in - 24mm);
        border: 0;
        box-shadow: none;
        margin: 0;
        padding: 0;
        display: flex;
        flex-direction: column;
      }
      .page + .page {
        margin-top: 0;
        page-break-before: always;
      }
      .head {
        grid-template-columns: 190px minmax(0, 1.55fr) minmax(180px, 1fr) !important;
      }
      .head-quote {
        text-align: right !important;
      }
      .quote-items-section table {
        page-break-inside: auto;
      }
      .quote-items-section thead {
        display: table-header-group;
      }
      .quote-items-section tr {
        page-break-inside: avoid;
        break-inside: avoid;
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

  <?php foreach ($quotePreviewPages as $quotePageIndex => $quotePageRows): ?>
  <?php $isLastPreviewPage = ($quotePageIndex === ($quotePreviewTotalPages - 1)); ?>
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
        <?php
          $quoteValidezShow = trim((string)($quotePreview['validez_override'] ?? ''));
          if ($quoteValidezShow === '') {
            $quoteValidezShow = trim((string)$profile['validez']);
          }
          if ($quoteValidezShow === '') {
            $quoteValidezShow = (string)$quotePreview['validez_dias'] . ' dias';
          }
          $quoteEntregaShow = trim((string)($quotePreview['entrega_override'] ?? ''));
          if ($quoteEntregaShow === '') {
            $quoteEntregaShow = trim((string)$profile['entrega']);
          }
          if ($quoteEntregaShow === '') {
            $quoteEntregaShow = 'No definida';
          }
          $quoteCondPagoShow = trim((string)($quotePreview['condicion_de_pago_override'] ?? ''));
          if ($quoteCondPagoShow === '') {
            $quoteCondPagoShow = trim((string)$profile['condicion_de_pago']);
          }
          if ($quoteCondPagoShow === '') {
            $quoteCondPagoShow = 'No definida';
          }
          $quoteMonedaShow = trim((string)($quotePreview['moneda_override'] ?? ''));
          if ($quoteMonedaShow === '') {
            $quoteMonedaShow = trim((string)$profile['moneda']);
          }
          if ($quoteMonedaShow === '') {
            $quoteMonedaShow = 'CLP';
          }
        ?>
        <div class="muted">Validez: <?= h($quoteValidezShow) ?></div>
        <div class="muted">Entrega: <?= h($quoteEntregaShow) ?></div>
        <div class="muted">Condicion de pago: <?= h($quoteCondPagoShow) ?></div>
        <div class="muted">Moneda: <?= h($quoteMonedaShow) ?></div>
      </div>
    </section>

    <section class="quote-items-section">
      <table class="items">
        <thead>
          <tr>
            <th style="width:52%;">Descripcion</th>
            <th style="width:12%;">Cantidad</th>
            <th style="width:18%;">Precio unitario</th>
            <th style="width:18%;">Total linea</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($quotePageRows as $it): ?>
            <?php
              $previewItemType = strtolower(trim((string)($it['item_type'] ?? 'normal')));
              if (!in_array($previewItemType, ['normal', 'text'], true)) {
                $previewItemType = 'normal';
              }
              $previewItemBold = ((int)($it['is_bold'] ?? 0) === 1);
              $previewIsEmpty = !empty($it['__empty']);
              $previewShowValues = isset($it['__show_values']) ? !empty($it['__show_values']) : true;
              $previewDesc = h((string)$it['descripcion']);
              if ($previewItemBold) {
                $previewDesc = '<strong>' . $previewDesc . '</strong>';
              }
            ?>
            <tr>
              <td class="desc-cell"><?= $previewDesc !== '' ? $previewDesc : '&nbsp;' ?></td>
              <td><?= ($previewIsEmpty || !$previewShowValues) ? '&nbsp;' : ($previewItemType === 'text' ? '-' : h((string)$it['cantidad'])) ?></td>
              <td><?= ($previewIsEmpty || !$previewShowValues) ? '&nbsp;' : ($previewItemType === 'text' ? '-' : ('$' . h(money_clp((float)$it['precio_unitario'])))) ?></td>
              <td><?= ($previewIsEmpty || !$previewShowValues) ? '&nbsp;' : ($previewItemType === 'text' ? '-' : ('$' . h(money_clp((float)$it['total_linea'])))) ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>

    </section>

    <?php if ($isLastPreviewPage && trim((string)$quotePreview['observaciones']) !== ''): ?>
      <section class="obs">
        <strong>Observaciones</strong>
        <div><?= h((string)$quotePreview['observaciones']) ?></div>
      </section>
    <?php endif; ?>

    <?php if ($isLastPreviewPage): ?>
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
    <?php else: ?>
    <div class="quote-financials quote-financials-placeholder">
      <div class="quote-terms-box">
        <h4 class="quote-terms-title">Terminos y condiciones adicionales</h4>
        <div class="quote-terms-content">Continua en la siguiente pagina.</div>
      </div>
      <div class="totals-box">
        <p class="quote-page-indicator">Pagina <?= (int)($quotePageIndex + 1) ?> de <?= (int)$quotePreviewTotalPages ?></p>
      </div>
    </div>
    <?php endif; ?>
  </article>
  <?php endforeach; ?>
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
      --app-header-h: 68px;
    }
    * { box-sizing: border-box; }
    html {
      scrollbar-gutter: stable;
    }
    body {
      margin: 0;
      font-family: Segoe UI, Arial, sans-serif;
      color: var(--txt);
      background:
        radial-gradient(circle at 8% 0%, rgba(255,216,77,.19), transparent 38%),
        radial-gradient(circle at 90% 0%, rgba(91,192,190,.13), transparent 44%),
        linear-gradient(180deg, var(--bg-1), var(--bg-2));
      min-height: 100dvh;
      overflow-y: auto;
      scrollbar-width: thin;
      scrollbar-color: #f4b400 rgba(11,19,43,.58);
    }
    body::-webkit-scrollbar,
    .side::-webkit-scrollbar,
    .modal-card::-webkit-scrollbar,
    .quote-preview-card::-webkit-scrollbar {
      width: 11px;
      height: 11px;
    }
    body::-webkit-scrollbar-track,
    .side::-webkit-scrollbar-track,
    .modal-card::-webkit-scrollbar-track,
    .quote-preview-card::-webkit-scrollbar-track {
      background: rgba(11,19,43,.58);
      border-radius: 999px;
    }
    body::-webkit-scrollbar-thumb,
    .side::-webkit-scrollbar-thumb,
    .modal-card::-webkit-scrollbar-thumb,
    .quote-preview-card::-webkit-scrollbar-thumb {
      background: linear-gradient(180deg, #ffe38b, #f4b400);
      border-radius: 999px;
      border: 2px solid rgba(11,19,43,.58);
    }
    body::-webkit-scrollbar-thumb:hover,
    .side::-webkit-scrollbar-thumb:hover,
    .modal-card::-webkit-scrollbar-thumb:hover,
    .quote-preview-card::-webkit-scrollbar-thumb:hover {
      background: linear-gradient(180deg, #ffefb8, #f6c744);
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
    .layout {
      display: grid;
      grid-template-columns: 280px 1fr;
      min-height: calc(100dvh - var(--app-header-h));
      transition: grid-template-columns .26s ease;
    }
    .app-header {
      position: sticky;
      top: 0;
      z-index: 52;
      width: 100%;
      border: 0;
      background: rgba(11,19,43,.82);
      backdrop-filter: saturate(140%) blur(12px);
      -webkit-backdrop-filter: saturate(140%) blur(12px);
      box-shadow: 0 10px 24px rgba(2,8,24,.3), inset 0 -1px 0 rgba(42,58,98,.78);
    }
    .side {
      border-right: 1px solid var(--line);
      background: rgba(7,17,42,.88);
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
      position: sticky;
      top: var(--app-header-h);
      height: calc(100dvh - var(--app-header-h));
      overflow-y: auto;
      z-index: 38;
      transition: padding .26s ease;
    }
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
      transition: padding .2s ease, justify-content .2s ease, gap .2s ease;
    }
    .menu a > span:first-child {
      min-width: 0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      transition: opacity .2s ease, width .2s ease, margin .2s ease;
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
    .side-toggle-wrap {
      margin-top: auto;
      display: flex;
      justify-content: flex-end;
      padding-top: .45rem;
      border-top: 1px solid rgba(42,58,98,.6);
    }
    .side-toggle {
      width: 34px;
      height: 34px;
      border-radius: 9px;
      border: 1px solid #2f4678;
      background: linear-gradient(180deg, #163166, #11264f);
      color: #dce8ff;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: transform .2s ease, border-color .2s ease, background .2s ease;
    }
    .side-toggle:hover {
      border-color: #f4b400;
      transform: translateY(-1px);
    }
    .side-toggle svg {
      width: 15px;
      height: 15px;
      stroke: currentColor;
      fill: none;
      stroke-width: 1.9;
      stroke-linecap: round;
      stroke-linejoin: round;
      transition: transform .26s ease;
    }

    body.side-collapsed .layout {
      grid-template-columns: 84px 1fr;
    }
    body.side-collapsed .side {
      padding: .72rem .48rem;
    }
    body.side-collapsed .menu a {
      justify-content: center;
      gap: 0;
      padding: .58rem .4rem;
    }
    body.side-collapsed .menu a > span:first-child {
      width: 0;
      opacity: 0;
      margin: 0;
      pointer-events: none;
    }
    body.side-collapsed .menu .nav-icon {
      margin: 0;
    }
    body.side-collapsed .side-toggle-wrap {
      justify-content: center;
    }
    body.side-collapsed .side-toggle svg {
      transform: rotate(180deg);
    }
    body.side-state-preload .layout,
    body.side-state-preload .side,
    body.side-state-preload .menu a,
    body.side-state-preload .menu a > span:first-child,
    body.side-state-preload .side-toggle,
    body.side-state-preload .side-toggle svg {
      transition: none !important;
    }
    .content { padding: 1.1rem; }
    .top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: .8rem;
      margin: 0;
      flex-wrap: wrap;
      width: 100%;
      min-height: var(--app-header-h);
      padding: .35rem 1rem;
    }
    .top-left {
      display: flex;
      align-items: center;
      gap: .6rem;
      min-width: 0;
    }
    .top-left > svg {
      height: 34px;
      width: auto;
      max-width: 100%;
      display: block;
      flex: 0 0 auto;
    }
    .top h1 { margin: 0; font-size: 1.08rem; color: #fff4b8; line-height: 1.15; }
    .actions { display: flex; gap: .4rem; }
    .btn {
      border: 1px solid #4b5e8c;
      border-radius: 10px;
      background: linear-gradient(180deg, #152546, #0c1833);
      color: #d3dcef;
      font-weight: 600;
      padding: .46rem .68rem;
      font-size: .82rem;
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
    .btn.icon {
      display: inline-flex;
      align-items: center;
      gap: .4rem;
    }
    .btn.icon-only {
      padding: .44rem;
      min-width: 34px;
      justify-content: center;
      gap: 0;
    }
    .btn.icon svg {
      width: 14px;
      height: 14px;
      stroke: currentColor;
      fill: none;
      stroke-width: 1.85;
      stroke-linecap: round;
      stroke-linejoin: round;
      flex: 0 0 auto;
    }
    .btn.trash {
      border-color: #8f3450;
      background: linear-gradient(180deg, #4a1726, #34101b);
      color: #ffdce4;
    }
    .btn.trash:hover {
      border-color: #ff8fab;
    }
    .btn.settings {
      border-color: #2e5f9a;
      background: linear-gradient(180deg, #14355d, #0d2441);
      color: #d6e8ff;
    }
    .btn.settings:hover {
      border-color: #65a6ff;
    }
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
    .toast-stack {
      position: fixed;
      right: 1rem;
      bottom: 1rem;
      z-index: 200;
      display: grid;
      gap: .55rem;
      width: min(420px, calc(100vw - 2rem));
      pointer-events: none;
    }
    .toast {
      pointer-events: auto;
      border: 1px solid #2f4678;
      border-radius: 12px;
      background: rgba(10,20,44,.94);
      color: #e5e7eb;
      box-shadow: 0 14px 36px rgba(2,8,24,.45);
      padding: .62rem .68rem;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: .55rem;
      align-items: start;
      opacity: 0;
      transform: translateY(12px);
      transition: opacity .22s ease, transform .22s ease;
    }
    .toast.is-visible {
      opacity: 1;
      transform: translateY(0);
    }
    .toast.is-closing {
      opacity: 0;
      transform: translateY(10px);
    }
    .toast--ok {
      border-color: rgba(34,197,94,.5);
      background: linear-gradient(180deg, rgba(20,83,45,.24), rgba(10,20,44,.94));
      color: #dcfce7;
    }
    .toast--err {
      border-color: rgba(239,68,68,.5);
      background: linear-gradient(180deg, rgba(127,29,29,.22), rgba(10,20,44,.94));
      color: #fecaca;
    }
    .toast-msg {
      font-size: .88rem;
      line-height: 1.34;
      padding-top: .05rem;
    }
    .toast-close {
      border: 1px solid rgba(255,255,255,.24);
      background: rgba(11,23,52,.68);
      color: #e5e7eb;
      width: 26px;
      height: 26px;
      border-radius: 8px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      cursor: pointer;
      transition: border-color .18s ease, background .18s ease;
    }
    .toast-close:hover {
      border-color: #f4b400;
      background: rgba(15,26,52,.9);
    }
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
    body.module-dashboard { height: auto; overflow: auto; }
    body.module-dashboard .content {
      height: auto;
      display: block;
      padding: .9rem 1.1rem 1rem;
      overflow: visible;
    }
    body.module-dashboard #appMain {
      min-height: auto;
      display: block;
    }
    body.module-dashboard .top { margin-bottom: 0; }
    .dashboard-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr);
      grid-template-rows: auto auto auto;
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
      min-height: auto;
      overflow: visible;
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
    .dash-pipeline,
    .dash-top-clients {
      padding: .72rem .8rem;
    }
    .dash-pipeline-list {
      list-style: none;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: .42rem;
      flex: 0 0 auto;
      min-height: auto;
      overflow: visible;
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
      flex: 0 0 auto;
      min-height: auto;
      overflow: visible;
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

    .module-empresa,
    .module-configuracion { min-height: 100vh; }
    .module-empresa .panel.compact,
    .module-configuracion .panel.compact {
      min-height: calc(100vh - 210px);
      height: auto;
      margin-bottom: 0;
      padding: .66rem .7rem;
    }
    .module-empresa .empresa-workspace,
    .module-configuracion .empresa-workspace {
      display: grid;
      grid-template-columns: minmax(280px, 33%) minmax(0, 1fr);
      gap: .62rem;
      min-height: 0;
      height: 100%;
    }
    .module-empresa .empresa-fields,
    .module-configuracion .empresa-fields {
      min-height: 0;
      display: grid;
      grid-template-rows: 1fr auto;
      gap: .45rem;
    }
    .module-empresa .grid,
    .module-configuracion .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: .4rem .52rem;
      align-content: start;
      min-height: 0;
    }
    .module-empresa .field,
    .module-configuracion .field { display: grid; gap: .2rem; }
    .module-empresa .field label,
    .module-configuracion .field label { font-size: .72rem; color: #cbd5e1; }
    .module-empresa .field input,
    .module-empresa .field select,
    .module-empresa .field textarea,
    .module-configuracion .field input,
    .module-configuracion .field select,
    .module-configuracion .field textarea {
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
    .module-empresa .field textarea.compact-line,
    .module-configuracion .field textarea.compact-line { resize: none; overflow: hidden; }
    .module-empresa .field.full,
    .module-configuracion .field.full { grid-column: span 3; }
    .module-configuracion .field input[readonly] {
      background: linear-gradient(180deg, rgba(11,23,52,.96), rgba(8,18,40,.96));
      border-color: #3b5b97;
      color: #dbe7ff;
      cursor: not-allowed;
      opacity: 1;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
    }
    .module-configuracion .field input:focus,
    .module-configuracion .field input:focus-visible,
    .module-configuracion .field select:focus,
    .module-configuracion .field textarea:focus {
      outline: none;
      border-color: #7aa2f7;
      box-shadow: 0 0 0 3px rgba(122,162,247,.16);
    }

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
    .sending-modal-card {
      width: min(420px, 100%);
      border: 1px solid #33528f;
      border-radius: 14px;
      background: linear-gradient(180deg, #0f1f41, #0a1732);
      box-shadow: 0 26px 60px rgba(2,8,23,.55);
      padding: 1rem 1.1rem;
      text-align: center;
      color: #e2e8f0;
    }
    .sending-modal-spinner {
      width: 42px;
      height: 42px;
      border-radius: 999px;
      margin: 0 auto .85rem;
      border: 3px solid rgba(244,180,0,.24);
      border-top-color: #f4b400;
      animation: sendingSpin .8s linear infinite;
    }
    .sending-modal-title {
      margin: 0;
      color: #fff4b8;
      font-size: 1rem;
      font-weight: 700;
      letter-spacing: .02em;
    }
    .sending-modal-text {
      margin: .42rem 0 0;
      color: #c8d7ef;
      font-size: .86rem;
      line-height: 1.35;
    }
    @keyframes sendingSpin {
      to { transform: rotate(360deg); }
    }
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
    .modal-close {
      border: 1px solid #33528f;
      border-radius: 8px;
      background: #0b1734;
      color: #dbe6fb;
      width: 34px;
      height: 34px;
      font-size: 1rem;
      line-height: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: border-color .15s ease, background .15s ease, color .15s ease;
    }
    .modal-close:hover {
      border-color: #f4b400;
      background: rgba(244,180,0,.14);
      color: #ffe38b;
    }

    /* Estilos modal Ordenes de servicio */
    #serviceOrderModal .modal-head h3 { color: #fff4b8; }
    #serviceOrderModal .so-section {
      border: 1px solid #2f4678;
      border-radius: 10px;
      padding: .75rem .85rem;
      background: rgba(8,18,42,.55);
    }
    #serviceOrderModal .so-section-title {
      font-weight: 600;
      color: #fff4b8;
      margin: 0 0 .35rem 0;
      font-size: .92rem;
      letter-spacing: .2px;
    }
    #serviceOrderModal .so-section-hint {
      color: #9fb0cf;
      font-size: .78rem;
      margin: 0 0 .55rem 0;
    }
    #serviceOrderModal .so-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: .6rem .7rem;
    }
    #serviceOrderModal .field { display: grid; gap: .25rem; }
    #serviceOrderModal .field.full { grid-column: 1 / -1; }
    #serviceOrderModal .field label {
      font-size: .76rem;
      color: #c8d7ef;
      letter-spacing: .2px;
    }
    #serviceOrderModal .field input:not([type="checkbox"]):not([type="radio"]),
    #serviceOrderModal .field select,
    #serviceOrderModal .field textarea {
      border: 1px solid #33528f;
      border-radius: 8px;
      background: #0b1734;
      color: #e5e7eb;
      min-height: 36px;
      padding: .42rem .55rem;
      font-size: .85rem;
      width: 100%;
      box-sizing: border-box;
      font-family: inherit;
    }
    #serviceOrderModal .field textarea {
      min-height: 64px;
      resize: vertical;
      line-height: 1.35;
    }
    #serviceOrderModal .field select {
      appearance: none;
      -webkit-appearance: none;
      -moz-appearance: none;
      padding-right: 1.8rem;
      background-image: linear-gradient(45deg, transparent 50%, #9fb0cf 50%), linear-gradient(135deg, #9fb0cf 50%, transparent 50%);
      background-position: calc(100% - 14px) calc(50% - 3px), calc(100% - 8px) calc(50% - 3px);
      background-size: 6px 6px, 6px 6px;
      background-repeat: no-repeat;
      cursor: pointer;
    }
    #serviceOrderModal .field input:focus,
    #serviceOrderModal .field select:focus,
    #serviceOrderModal .field textarea:focus {
      outline: none;
      border-color: #f4b400;
      box-shadow: 0 0 0 3px rgba(244,180,0,.18);
    }
    #serviceOrderModal .so-row {
      display: grid;
      gap: .5rem;
      align-items: end;
      padding: .55rem;
      border: 1px solid #2f4678;
      border-radius: 9px;
      background: rgba(15,30,65,.55);
      margin-bottom: .5rem;
    }
    #serviceOrderModal .so-row .field label { font-size: .7rem; }
    #serviceOrderModal .so-row-assign { grid-template-columns: 1.6fr 1fr 0.85fr 0.85fr 1.4fr auto; }
    #serviceOrderModal .so-row-part   { grid-template-columns: 2fr 1fr 1.4fr 0.75fr 0.8fr 1fr auto; }
    #serviceOrderModal .so-row-chk    { grid-template-columns: auto 1fr auto; align-items: center; }
    #serviceOrderModal .so-row-remove {
      background: transparent;
      border: 1px solid #ef4444;
      color: #fca5a5;
      border-radius: 8px;
      width: 34px;
      height: 34px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      font-weight: 700;
      transition: background .15s, color .15s;
    }
    #serviceOrderModal .so-row-remove:hover {
      background: #ef4444;
      color: #fff;
    }
    #serviceOrderModal .so-add-btn { margin-top: .3rem; }
    #serviceOrderModal .so-chk-toggle {
      display: inline-flex;
      align-items: center;
      gap: .4rem;
      color: #c8d7ef;
      font-size: .8rem;
      white-space: nowrap;
    }
    #serviceOrderModal .so-chk-toggle input[type="checkbox"] {
      width: 18px;
      height: 18px;
      accent-color: #f4b400;
      cursor: pointer;
    }
    #serviceOrderModal .so-template-picker {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
      gap: .45rem;
      border: 1px solid #2f4678;
      border-radius: 9px;
      background: rgba(15,30,65,.45);
      padding: .55rem;
    }
    #serviceOrderModal .so-template-option {
      display: inline-flex;
      align-items: center;
      gap: .45rem;
      color: #dbe8ff;
      font-size: .82rem;
      background: rgba(11,23,52,.72);
      border: 1px solid #33528f;
      border-radius: 8px;
      padding: .4rem .5rem;
      cursor: pointer;
    }
    #serviceOrderModal .so-template-option input[type="checkbox"] {
      width: 18px;
      height: 18px;
      accent-color: #f4b400;
      cursor: pointer;
    }
    #serviceOrderModal .so-template-option:hover {
      border-color: #f4b400;
      background: rgba(244,180,0,.12);
    }
    .so-template-list {
      margin: .15rem 0 0;
      padding-left: 1.1rem;
      color: #dbe8ff;
      line-height: 1.35;
    }
    .so-template-list li { margin-bottom: .2rem; }
    @media (max-width: 820px) {
      #serviceOrderModal .so-row-assign,
      #serviceOrderModal .so-row-part {
        grid-template-columns: 1fr 1fr;
      }
    }

    /* Reuso visual para modal rapido de asignaciones */
    #serviceOrderAssignModal .modal-head h3 { color: #fff4b8; }
    #serviceOrderAssignModal .so-section {
      border: 1px solid #2f4678;
      border-radius: 10px;
      padding: .75rem .85rem;
      background: rgba(8,18,42,.55);
    }
    #serviceOrderAssignModal .so-section-title {
      font-weight: 600;
      color: #fff4b8;
      margin: 0 0 .35rem 0;
      font-size: .92rem;
      letter-spacing: .2px;
    }
    #serviceOrderAssignModal .so-section-hint {
      color: #9fb0cf;
      font-size: .78rem;
      margin: 0 0 .55rem 0;
    }
    #serviceOrderAssignModal .field { display: grid; gap: .25rem; }
    #serviceOrderAssignModal .field label {
      font-size: .76rem;
      color: #c8d7ef;
      letter-spacing: .2px;
    }
    #serviceOrderAssignModal .field input:not([type="checkbox"]):not([type="radio"]),
    #serviceOrderAssignModal .field select,
    #serviceOrderAssignModal .field textarea {
      border: 1px solid #33528f;
      border-radius: 8px;
      background: #0b1734;
      color: #e5e7eb;
      min-height: 36px;
      padding: .42rem .55rem;
      font-size: .85rem;
      width: 100%;
      box-sizing: border-box;
      font-family: inherit;
    }
    #serviceOrderAssignModal .field select {
      appearance: none;
      -webkit-appearance: none;
      -moz-appearance: none;
      padding-right: 1.8rem;
      background-image: linear-gradient(45deg, transparent 50%, #9fb0cf 50%), linear-gradient(135deg, #9fb0cf 50%, transparent 50%);
      background-position: calc(100% - 14px) calc(50% - 3px), calc(100% - 8px) calc(50% - 3px);
      background-size: 6px 6px, 6px 6px;
      background-repeat: no-repeat;
      cursor: pointer;
    }
    #serviceOrderAssignModal .field input:focus,
    #serviceOrderAssignModal .field select:focus,
    #serviceOrderAssignModal .field textarea:focus {
      outline: none;
      border-color: #f4b400;
      box-shadow: 0 0 0 3px rgba(244,180,0,.18);
    }
    #serviceOrderAssignModal .so-row {
      display: grid;
      gap: .5rem;
      align-items: end;
      padding: .55rem;
      border: 1px solid #2f4678;
      border-radius: 9px;
      background: rgba(15,30,65,.55);
      margin-bottom: .5rem;
    }
    #serviceOrderAssignModal .so-row .field label { font-size: .7rem; }
    #serviceOrderAssignModal .so-row-assign { grid-template-columns: 1.6fr 1fr 0.85fr 0.85fr 1.4fr auto; }
    #serviceOrderAssignModal .so-row-remove {
      background: transparent;
      border: 1px solid #ef4444;
      color: #fca5a5;
      border-radius: 8px;
      width: 34px;
      height: 34px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      font-weight: 700;
      transition: background .15s, color .15s;
    }
    #serviceOrderAssignModal .so-row-remove:hover {
      background: #ef4444;
      color: #fff;
    }

    /* Modal Reportes */
    #serviceReportModal .modal-head h3 { color: #fff4b8; }
    #serviceReportModal .report-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: .65rem;
    }
    #serviceReportModal .field {
      display: grid;
      gap: .25rem;
    }
    #serviceReportModal .field.full {
      grid-column: 1 / -1;
    }
    #serviceReportModal .field label {
      font-size: .76rem;
      color: #c8d7ef;
      letter-spacing: .2px;
    }
    #serviceReportModal .field small {
      color: #9fb0cf;
      font-size: .75rem;
    }
    #serviceReportModal .field input:not([type="checkbox"]):not([type="radio"]),
    #serviceReportModal .field select,
    #serviceReportModal .field textarea {
      border: 1px solid #33528f;
      border-radius: 8px;
      background: #0b1734;
      color: #e5e7eb;
      min-height: 36px;
      padding: .42rem .55rem;
      font-size: .85rem;
      width: 100%;
      box-sizing: border-box;
      font-family: inherit;
    }
    #serviceReportModal .field textarea {
      min-height: 72px;
      resize: vertical;
      line-height: 1.35;
    }
    #serviceReportModal .field input[type="file"] {
      padding: .35rem;
      min-height: auto;
      background: rgba(11,23,52,.65);
    }
    #serviceReportModal .field input[readonly] {
      color: #b9c8e6;
      background: rgba(11,23,52,.68);
    }
    #serviceReportModal .field select {
      appearance: none;
      -webkit-appearance: none;
      -moz-appearance: none;
      padding-right: 1.8rem;
      background-image: linear-gradient(45deg, transparent 50%, #9fb0cf 50%), linear-gradient(135deg, #9fb0cf 50%, transparent 50%);
      background-position: calc(100% - 14px) calc(50% - 3px), calc(100% - 8px) calc(50% - 3px);
      background-size: 6px 6px, 6px 6px;
      background-repeat: no-repeat;
      cursor: pointer;
    }
    #serviceReportModal .field input:focus,
    #serviceReportModal .field select:focus,
    #serviceReportModal .field textarea:focus {
      outline: none;
      border-color: #f4b400;
      box-shadow: 0 0 0 3px rgba(244,180,0,.18);
    }
    #serviceReportModal .field select:disabled {
      opacity: .72;
      cursor: not-allowed;
    }
    #serviceReportModal .report-photo-preview {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
      gap: .5rem;
      margin-top: .45rem;
    }
    #serviceReportModal .report-photo-card {
      border: 1px solid #2f4678;
      border-radius: 9px;
      background: rgba(8,18,42,.55);
      padding: .35rem;
      display: grid;
      gap: .3rem;
    }
    #serviceReportModal .report-photo-card img {
      width: 100%;
      height: 78px;
      object-fit: cover;
      border-radius: 6px;
      border: 1px solid #334a7f;
      background: #0b1734;
    }
    #serviceReportModal .report-photo-card span {
      font-size: .71rem;
      color: #c8d7ef;
      line-height: 1.25;
      word-break: break-word;
    }
    #serviceReportModal .report-existing-wrap {
      border: 1px solid #2f4678;
      border-radius: 10px;
      background: rgba(8,18,42,.55);
      padding: .55rem;
      margin-top: .5rem;
      display: grid;
      gap: .45rem;
    }
    #serviceReportModal .report-existing-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
      gap: .6rem;
    }
    #serviceReportModal .report-existing-card {
      border: 1px solid #33528f;
      border-radius: 9px;
      background: rgba(11,23,52,.72);
      padding: .45rem;
      display: grid;
      gap: .42rem;
    }
    #serviceReportModal .report-existing-card img {
      width: 100%;
      height: 150px;
      object-fit: cover;
      border-radius: 7px;
      border: 1px solid #3a5ca2;
      background: #0b1734;
    }
    #serviceReportModal .report-existing-actions {
      display: flex;
      gap: .35rem;
    }
    #serviceReportModal .report-existing-actions button {
      flex: 1;
      min-height: 30px;
      border-radius: 7px;
      border: 1px solid #3c5ea5;
      background: #10224b;
      color: #dbe8ff;
      cursor: pointer;
      font-size: .74rem;
    }
    #serviceReportModal .report-existing-actions button.danger {
      border-color: #7f1d1d;
      background: #3f1111;
      color: #fecaca;
    }
    #serviceReportModal .report-list-builder {
      border: 1px solid #2f4678;
      border-radius: 10px;
      background: rgba(8,18,42,.45);
      padding: .55rem;
      display: grid;
      gap: .45rem;
    }
    #serviceReportModal .report-list-items {
      display: grid;
      gap: .4rem;
    }
    #serviceReportModal .report-list-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: .35rem;
      align-items: center;
    }
    #serviceReportModal .report-list-row input[type="text"] {
      min-height: 34px;
    }
    #serviceReportModal .report-list-row button {
      min-height: 34px;
      border-radius: 7px;
      border: 1px solid #3c5ea5;
      background: #10224b;
      color: #dbe8ff;
      cursor: pointer;
      font-size: .74rem;
      padding: .25rem .55rem;
    }
    #serviceReportModal .report-list-row button.danger {
      border-color: #7f1d1d;
      background: #3f1111;
      color: #fecaca;
    }
    #serviceReportModal .report-list-add-btn {
      min-height: 34px;
      border-radius: 8px;
      border: 1px dashed #3c5ea5;
      background: rgba(16,34,75,.6);
      color: #dbe8ff;
      cursor: pointer;
      font-size: .78rem;
      justify-self: start;
      padding: .3rem .65rem;
    }
    #serviceReportModal .report-dynamic-forms {
      display: grid;
      gap: .7rem;
      margin-bottom: .6rem;
    }
    #serviceReportModal .report-form-template-block {
      border: 1px solid #2f4678;
      border-radius: 10px;
      background: rgba(8,18,42,.45);
      padding: .55rem;
      display: grid;
      gap: .5rem;
    }
    #serviceReportModal .report-form-template-block h4 {
      margin: 0;
      font-size: .92rem;
      color: #dbe8ff;
    }
    #serviceReportModal .signature-block {
      border: 1px solid #2f4678;
      border-radius: 10px;
      background: rgba(8,18,42,.45);
      padding: .55rem;
      display: grid;
      gap: .5rem;
    }
    #serviceReportModal .signature-canvas {
      width: 100%;
      min-height: 148px;
      border: 1px dashed #5a74a6;
      border-radius: 8px;
      background: #ffffff;
      touch-action: none;
      cursor: crosshair;
    }
    #serviceReportModal .signature-actions {
      display: flex;
      gap: .35rem;
      justify-content: flex-end;
    }
    #serviceReportModal .signature-actions button {
      min-height: 32px;
      border-radius: 7px;
      border: 1px solid #3c5ea5;
      background: #10224b;
      color: #dbe8ff;
      cursor: pointer;
      font-size: .74rem;
      padding: .25rem .55rem;
    }
    #serviceReportModal .signature-actions button.danger {
      border-color: #7f1d1d;
      background: #3f1111;
      color: #fecaca;
    }
    #serviceReportModal .signature-hint {
      margin: 0;
      font-size: .72rem;
      color: #b8c9e8;
    }
    #formTemplateModal .modal-card {
      border: 1px solid #27457e;
      background: linear-gradient(180deg, #0d1f46 0%, #0a1738 100%);
      box-shadow: 0 18px 40px rgba(3, 10, 28, 0.45);
    }
    #formTemplateModal .modal-body {
      max-height: min(70vh, 760px);
      overflow: auto;
      padding-right: 2px;
    }
    #formTemplateModal .field {
      display: grid;
      gap: .25rem;
    }
    #formTemplateModal .field label {
      font-size: .76rem;
      color: #c8d7ef;
      letter-spacing: .2px;
    }
    #formTemplateModal .field small {
      color: #9fb0cf;
      font-size: .75rem;
    }
    #formTemplateModal .field input:not([type="checkbox"]):not([type="radio"]),
    #formTemplateModal .field select,
    #formTemplateModal .field textarea {
      border: 1px solid #33528f;
      border-radius: 8px;
      background: #0b1734;
      color: #e5e7eb;
      min-height: 36px;
      padding: .42rem .55rem;
      font-size: .85rem;
      width: 100%;
      box-sizing: border-box;
      font-family: inherit;
    }
    #formTemplateModal .field textarea {
      min-height: 72px;
      resize: vertical;
      line-height: 1.35;
    }
    #formTemplateModal .field select {
      appearance: none;
      -webkit-appearance: none;
      -moz-appearance: none;
      padding-right: 1.8rem;
      background-image: linear-gradient(45deg, transparent 50%, #9fb0cf 50%), linear-gradient(135deg, #9fb0cf 50%, transparent 50%);
      background-position: calc(100% - 14px) calc(50% - 3px), calc(100% - 8px) calc(50% - 3px);
      background-size: 6px 6px, 6px 6px;
      background-repeat: no-repeat;
      cursor: pointer;
    }
    #formTemplateModal .field input:focus,
    #formTemplateModal .field select:focus,
    #formTemplateModal .field textarea:focus {
      outline: none;
      border-color: #f4b400;
      box-shadow: 0 0 0 3px rgba(244,180,0,.18);
    }
    #formTemplateModal .form-template-row {
      display: grid;
      grid-template-columns: 2fr 1.2fr .8fr 1.2fr 1.2fr 1.2fr auto;
      gap: .4rem;
      align-items: center;
      border: 1px solid #2f4678;
      border-radius: 9px;
      padding: .45rem;
      background: rgba(8,18,42,.42);
      margin-bottom: .45rem;
    }
    #formTemplateModal .form-template-row input,
    #formTemplateModal .form-template-row select {
      min-height: 34px;
    }
    #formTemplateModal .form-template-row button.danger {
      min-height: 34px;
      border-radius: 8px;
      border: 1px solid #7f1d1d;
      background: #3f1111;
      color: #fecaca;
      cursor: pointer;
      padding: .2rem .6rem;
    }
    #formTemplateModal .form-template-row button.danger:hover {
      background: #7f1d1d;
      color: #fff;
    }
    #formTemplateModal .modal-actions .btn {
      min-height: 36px;
    }
    #formTemplateModal .modal-actions .btn.primary {
      border-color: #f4b400;
      background: linear-gradient(180deg, #f4b400 0%, #d89d00 100%);
      color: #0f172a;
      font-weight: 700;
    }
    #formTemplateModal .modal-actions .btn.primary:hover {
      filter: brightness(1.05);
    }
    @media (max-width: 980px) {
      #formTemplateModal .form-template-row {
        grid-template-columns: 1fr;
      }
    }
    .report-bulleted-list {
      margin: 0;
      padding-left: 1.1rem;
      list-style: disc;
      color: #111827;
    }
    #serviceReportModal .report-bulleted-list { color: #e5e7eb; }
    .report-bulleted-list li {
      margin: 0 0 .2rem;
      line-height: 1.35;
    }
    .report-bulleted-list li:last-child {
      margin-bottom: 0;
    }
    #serviceReportDetailModal .modal-card {
      max-width: 980px;
    }
    #serviceReportDetailModal .report-detail-grid {
      display: grid;
      gap: .7rem;
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    #serviceReportDetailModal .detail-block {
      border: 1px solid #2f4678;
      border-radius: 10px;
      background: rgba(11, 23, 52, .72);
      padding: .55rem .65rem;
      display: grid;
      gap: .35rem;
      min-height: 70px;
    }
    #serviceReportDetailModal .detail-block.full {
      grid-column: 1 / -1;
    }
    #serviceReportDetailModal .detail-label {
      margin: 0;
      font-size: .73rem;
      text-transform: uppercase;
      letter-spacing: .3px;
      color: #9fb0cf;
    }
    #serviceReportDetailModal .detail-value {
      margin: 0;
      color: #e6edf7;
      line-height: 1.4;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: .9rem;
    }
    #serviceReportDetailModal .detail-photos {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
      gap: .55rem;
    }
    #serviceReportDetailModal .detail-photo-link {
      text-decoration: none;
      border: 1px solid #324d86;
      border-radius: 10px;
      padding: .35rem;
      background: rgba(8, 18, 42, .6);
      display: grid;
      gap: .3rem;
      color: #dbe8ff;
      font-size: .75rem;
      min-width: 0;
      overflow: hidden;
      box-sizing: border-box;
    }
    #serviceReportDetailModal .detail-photo-link img {
      display: block;
      width: 100%;
      max-width: 100%;
      height: 95px;
      object-fit: cover;
      object-position: center;
      border-radius: 6px;
      border: 1px solid #34508b;
      background: #0b1734;
      box-sizing: border-box;
    }
    @media (max-width: 820px) {
      #serviceReportDetailModal .report-detail-grid {
        grid-template-columns: 1fr;
      }
    }
    @media (max-width: 820px) {
      #serviceReportModal .report-grid {
        grid-template-columns: 1fr;
      }
    }
    #serviceOrderAssignModal .so-add-btn { margin-top: .3rem; }
    @media (max-width: 820px) {
      #serviceOrderAssignModal .so-row-assign {
        grid-template-columns: 1fr 1fr;
      }
    }
    .so-detail-row td {
      background: rgba(8, 18, 42, .42);
      border-top: 0;
      padding: .7rem .6rem .85rem;
    }
    .so-detail-wrap {
      display: grid;
      grid-template-columns: repeat(3, minmax(220px, 1fr));
      gap: .7rem;
    }
    .so-detail-block {
      border: 1px solid #2f4678;
      border-radius: 10px;
      background: rgba(11, 23, 52, .75);
      padding: .55rem .6rem;
    }
    .so-detail-block h4 {
      margin: 0 0 .45rem;
      color: #fff4b8;
      font-size: .82rem;
      letter-spacing: .2px;
    }
    .so-detail-table {
      width: 100%;
      border-collapse: collapse;
      font-size: .8rem;
    }
    .so-detail-table th,
    .so-detail-table td {
      border-bottom: 1px solid rgba(159, 176, 207, .2);
      padding: .33rem .32rem;
      text-align: left;
      color: #dbe6fb;
      vertical-align: top;
    }
    .so-checklist-items {
      display: grid;
      gap: .32rem;
    }
    .so-check-item {
      display: flex;
      align-items: flex-start;
      gap: .45rem;
      border: 1px solid rgba(159,176,207,.22);
      border-radius: 8px;
      padding: .36rem .45rem;
      background: rgba(15,30,65,.5);
      color: #dbe6fb;
      font-size: .82rem;
      cursor: pointer;
    }
    .so-check-item input[type="checkbox"] {
      margin-top: .05rem;
      width: 16px;
      height: 16px;
      accent-color: #22c55e;
      cursor: pointer;
      flex: 0 0 auto;
    }
    .so-check-item.done {
      border-color: rgba(34,197,94,.4);
      background: rgba(22, 101, 52, .28);
      color: #dcfce7;
    }
    .so-check-item.done span {
      text-decoration: line-through;
      opacity: .92;
    }
    .so-main-row .icon-btn.active {
      border-color: rgba(244, 180, 0, .7);
      background: rgba(244, 180, 0, .16);
      color: #ffe38b;
    }
    @media (max-width: 980px) {
      .so-detail-wrap {
        grid-template-columns: 1fr;
      }
    }
    /* fin estilos Ordenes de servicio */
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
    .clientes-form-grid .field input:not([type="checkbox"]):not([type="radio"]),
    .clientes-form-grid .field select,
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
    .clientes-form-grid .field select {
      appearance: none;
      -webkit-appearance: none;
      -moz-appearance: none;
      padding-right: 2rem;
      background-image: linear-gradient(45deg, transparent 50%, #9fb0cf 50%), linear-gradient(135deg, #9fb0cf 50%, transparent 50%);
      background-position: calc(100% - 14px) calc(50% - 3px), calc(100% - 8px) calc(50% - 3px);
      background-size: 6px 6px, 6px 6px;
      background-repeat: no-repeat;
      cursor: pointer;
    }
    .clientes-form-grid .field input:not([type="checkbox"]):not([type="radio"]):focus,
    .clientes-form-grid .field select:focus,
    .clientes-form-grid .field textarea:focus {
      outline: none;
      border-color: #f4b400;
      box-shadow: 0 0 0 3px rgba(244,180,0,.18);
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
    .tech-skills-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: .35rem .55rem;
      max-height: 180px;
      overflow: auto;
      border: 1px solid #33528f;
      border-radius: 10px;
      padding: .5rem .55rem;
      background: #0b1734;
    }
    .tech-skill-option {
      display: flex;
      align-items: center;
      gap: .4rem;
      font-size: .88rem;
      margin: 0;
      color: #dbe6fb;
      line-height: 1.2;
      padding: .22rem .28rem;
      border-radius: 8px;
      transition: background .15s ease;
    }
    .tech-skill-option:hover {
      background: rgba(159,176,207,.12);
    }
    .tech-skill-option input[type="checkbox"] {
      width: 16px;
      height: 16px;
      min-height: 16px;
      margin: 0;
      accent-color: #f4b400;
      cursor: pointer;
      flex: 0 0 auto;
    }
    .tech-skill-option input[type="checkbox"] + span {
      color: #dbe6fb;
      transition: color .15s ease;
    }
    .tech-skill-option input[type="checkbox"]:checked + span {
      color: #ffe38b;
    }
    .tech-skills-picked {
      margin-top: .6rem;
      display: flex;
      flex-wrap: wrap;
      gap: .4rem;
      min-height: 26px;
    }
    .tech-skill-chip {
      border: 1px solid rgba(244,180,0,.5);
      border-radius: 999px;
      background: rgba(244,180,0,.15);
      color: #ffe38b;
      padding: .2rem .55rem;
      font-size: .78rem;
      line-height: 1.2;
      white-space: nowrap;
    }
    .tech-gestion-actions {
      display: inline-flex;
      align-items: center;
      gap: .38rem;
      flex-wrap: wrap;
    }
    .tech-gestion-actions .icon-btn {
      position: relative;
      border-color: #33528f;
      background: #0b1734;
    }
    .tech-gestion-actions .icon-btn:hover {
      border-color: #f4b400;
    }
    .tech-gestion-count {
      position: absolute;
      top: -6px;
      right: -6px;
      min-width: 17px;
      height: 17px;
      border-radius: 999px;
      background: #f4b400;
      color: #101d40;
      font-size: .68rem;
      line-height: 17px;
      text-align: center;
      font-weight: 700;
      border: 1px solid rgba(16,29,64,.48);
    }
    .tech-asset-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: .7rem;
      flex-wrap: wrap;
    }
    .tech-asset-tech {
      color: #d7e1f3;
      font-size: .88rem;
    }
    .tech-asset-tech strong {
      color: #ffe38b;
      font-weight: 700;
    }
    .tech-asset-switches {
      display: inline-flex;
      align-items: center;
      gap: .4rem;
      flex-wrap: wrap;
    }
    .tech-asset-switches .btn.active {
      border-color: #8b6500;
      background: linear-gradient(180deg, #ffe38b, #e3a900);
      color: #1f2937;
    }
    .tech-asset-records {
      margin-top: .8rem;
      border-top: 1px solid #2f4678;
      padding-top: .7rem;
      max-height: 180px;
      overflow: auto;
    }
    .tech-asset-table {
      width: 100%;
      border-collapse: collapse;
      font-size: .82rem;
      color: #dbe6fb;
      border: 1px solid #2f4678;
      border-radius: 10px;
      overflow: hidden;
      background: rgba(11,23,52,.75);
    }
    .tech-asset-table th,
    .tech-asset-table td {
      border: 1px solid #2f4678;
      padding: .38rem .46rem;
      text-align: left;
      vertical-align: top;
    }
    .tech-asset-table th {
      color: #ffe38b;
      font-size: .75rem;
      text-transform: uppercase;
      letter-spacing: .03em;
      background: rgba(16,33,73,.9);
      font-weight: 700;
      position: sticky;
      top: 0;
      z-index: 1;
    }
    .tech-asset-table tbody tr:nth-child(even) {
      background: rgba(21,39,83,.62);
    }
    .tech-asset-table td:first-child {
      color: #ffe38b;
      font-weight: 700;
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
    .icon-btn.email {
      background: linear-gradient(180deg, #3f356e, #2a2450);
      border-color: #5f4ea3;
      color: #ece9ff;
    }
    .icon-btn.email:hover {
      border-color: #b8a7ff;
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
    .delete-confirm-check {
      display: flex;
      align-items: flex-start;
      gap: .5rem;
      border: 1px solid #33528f;
      border-radius: 9px;
      background: #0b1734;
      padding: .55rem .62rem;
      color: #e5e7eb;
      font-size: .84rem;
      line-height: 1.3;
    }
    .delete-confirm-check input[type="checkbox"] {
      margin-top: .1rem;
      width: 16px;
      height: 16px;
      flex: 0 0 auto;
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
    .quote-email-card {
      width: min(760px, 100%);
      border: 1px solid #33528f;
      border-radius: 14px;
      background: linear-gradient(180deg, #0f1f41, #0a1732);
      box-shadow: 0 26px 60px rgba(2,8,23,.55);
      overflow: hidden;
    }
    .quote-email-form {
      display: grid;
      gap: .7rem;
    }
    .quote-email-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: .65rem;
    }
    .quote-email-grid .field {
      display: grid;
      gap: .28rem;
    }
    .quote-email-grid .field.full {
      grid-column: 1 / -1;
    }
    .quote-email-grid label {
      font-size: .8rem;
      color: #c8d7ef;
    }
    .quote-email-grid input,
    .quote-email-grid textarea {
      border: 1px solid #33528f;
      border-radius: 9px;
      background: #0b1734;
      color: #e5e7eb;
      min-height: 38px;
      padding: .45rem .52rem;
      font-size: .86rem;
      width: 100%;
    }
    .quote-email-grid textarea {
      min-height: 120px;
      resize: vertical;
    }
    .quote-email-note {
      margin: 0;
      color: #9fb4d8;
      font-size: .79rem;
      line-height: 1.35;
    }
    .quote-email-check {
      display: inline-flex;
      align-items: center;
      gap: .46rem;
      color: #dbe8ff;
      font-size: .83rem;
    }
    .quote-email-check input {
      width: 16px;
      height: 16px;
    }
    @media (max-width: 860px) {
      .quote-email-grid {
        grid-template-columns: 1fr;
      }
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
    .quote-items-wrap tr[data-item-bold="1"] input[data-item-descripcion="1"] {
      font-weight: 800;
    }
    .item-style-tools {
      display: inline-flex;
      align-items: center;
      gap: .2rem;
    }
    .btn.item-style-btn {
      min-width: 28px;
      min-height: 28px;
      padding: .2rem .36rem;
      font-size: .74rem;
      font-weight: 800;
      border-radius: 7px;
    }
    .btn.item-style-btn.active {
      border-color: #8b6500;
      background: linear-gradient(180deg, #ffe38b, #e3a900);
      color: #1f2937;
    }
    .item-dash {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 34px;
      width: 100%;
      border: 1px dashed rgba(148,163,184,.52);
      border-radius: 8px;
      background: rgba(11,23,52,.52);
      color: #cbd5e1;
      font-weight: 700;
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

    .plan-benefits-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: .9rem;
      margin-top: .95rem;
    }
    .plan-benefit-card {
      border: 1px solid #2f4e8b;
      border-radius: 12px;
      background: linear-gradient(180deg, #11224a, #0b1734);
      padding: .9rem;
    }
    .plan-benefit-card h3 {
      margin: 0 0 .35rem;
      font-size: .98rem;
      color: #f4d78f;
      letter-spacing: .02em;
    }
    .plan-benefit-card p {
      margin: 0;
      color: #d8e3f8;
      font-size: .87rem;
      line-height: 1.45;
    }
    .plan-basic-list {
      margin: .45rem 0 0;
      padding-left: 1rem;
      color: #c8d7ef;
      font-size: .88rem;
      line-height: 1.45;
    }
    .plan-upgrade-grid {
      margin-top: 1rem;
      border-top: 1px solid #28406f;
      padding-top: .9rem;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: .8rem;
    }
    .plan-upgrade-item {
      border: 1px solid #2f4e8b;
      border-radius: 12px;
      background: linear-gradient(180deg, #102046, #0b1734);
      padding: .75rem;
      display: grid;
      gap: .45rem;
      position: relative;
      overflow: hidden;
    }
    .plan-upgrade-item.current {
      border-color: rgba(244,180,0,.95);
      box-shadow:
        0 0 0 1px rgba(255,227,139,.45),
        0 12px 28px rgba(244,180,0,.18);
      background:
        linear-gradient(180deg, rgba(244,180,0,.18), rgba(244,180,0,.06)),
        linear-gradient(180deg, #102046, #0b1734);
    }
    .plan-upgrade-item.current::after {
      content: '';
      position: absolute;
      top: -28%;
      left: -42%;
      width: 180%;
      height: 58%;
      transform: rotate(-6deg);
      background: linear-gradient(120deg, rgba(255,227,139,0), rgba(255,227,139,.38), rgba(244,180,0,0));
      pointer-events: none;
    }
    .plan-current-badge {
      justify-self: start;
      display: inline-flex;
      align-items: center;
      gap: .2rem;
      margin-top: -.08rem;
      padding: .18rem .56rem;
      border-radius: 999px;
      border: 1px solid rgba(244,180,0,.92);
      background: linear-gradient(180deg, #ffe38b, #f4b400);
      color: #1f2937;
      font-size: .72rem;
      font-weight: 800;
      letter-spacing: .02em;
      text-transform: uppercase;
      position: relative;
      z-index: 1;
    }
    .plan-upgrade-item h4 {
      margin: 0;
      font-size: .94rem;
      color: #fff4b8;
    }
    .plan-upgrade-item p {
      margin: 0;
      color: #c8d7ef;
      font-size: .83rem;
      line-height: 1.4;
    }
    .plan-pay-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: fit-content;
      margin-top: .1rem;
      padding: .46rem .76rem;
      border-radius: 999px;
      border: 1px solid #8b6500;
      background: linear-gradient(180deg, #ffe38b, #f4b400);
      color: #1f2937;
      font-size: .78rem;
      font-weight: 800;
      letter-spacing: .02em;
      text-decoration: none;
      transition: transform .2s ease, filter .2s ease;
    }
    .plan-pay-link:hover { transform: translateY(-1px); filter: brightness(1.04); }
    .plan-pay-link.alt {
      border-color: rgba(244,180,0,.45);
      background: rgba(244,180,0,.12);
      color: #ffe38b;
      font-weight: 700;
    }
    .plan-pay-link.alt:hover { color: #fff4b8; }
    .plan-pay-link.disabled {
      background: rgba(148,163,184,.16);
      border-color: rgba(148,163,184,.5);
      color: #cbd5e1;
      cursor: not-allowed;
      pointer-events: none;
    }
    .plan-upgrade-note {
      margin-top: .65rem;
      color: #fcd34d;
      font-size: .79rem;
    }

    @media (max-width: 980px) {
      .module-empresa,
      .module-configuracion { height: auto; overflow: auto; }
      .module-empresa .content,
      .module-configuracion .content { height: auto; overflow: visible; padding: 1.1rem; }
      .module-empresa .panel.compact,
      .module-configuracion .panel.compact { height: auto; }
      .module-empresa .empresa-workspace,
      .module-configuracion .empresa-workspace { display: block; height: auto; }
      .module-empresa .empresa-logo-bar,
      .module-configuracion .empresa-logo-bar { margin-bottom: .68rem; }
      .module-empresa .empresa-fields,
      .module-configuracion .empresa-fields { display: block; }
      .module-empresa .grid,
      .module-configuracion .grid { grid-template-columns: 1fr; }
      .module-empresa .field.full,
      .module-configuracion .field.full { grid-column: 1 / -1; }
      .module-empresa .field textarea.compact-line,
      .module-configuracion .field textarea.compact-line { min-height: 86px; height: auto; overflow: auto; resize: vertical; }
      .module-empresa .compact-actions,
      .module-configuracion .compact-actions { border-top: 0; padding-top: .7rem; justify-content: flex-start; }

      .layout { grid-template-columns: 1fr; }
      .app-header { position: sticky; top: 0; }
      .side {
        border-right: 0;
        border-bottom: 1px solid var(--line);
        position: static;
        top: auto;
        height: auto;
        overflow: visible;
      }
      .side-toggle-wrap { display: none; }
      .layout { min-height: auto; }
      :root { --app-header-h: 60px; }
      .top { padding: .3rem .56rem; }
      .top h1 { font-size: .96rem; }
      .top-left > svg { height: 28px; }
      .cards { grid-template-columns: 1fr; }
      .clientes-form-grid { grid-template-columns: 1fr; }
      .quote-form-grid { grid-template-columns: 1fr; }
      .plan-benefits-grid { grid-template-columns: 1fr; }
      .plan-upgrade-grid { grid-template-columns: 1fr; }
      .modal-actions { justify-content: flex-start; }
      .cotizaciones-toolbar-right { width: 100%; justify-content: flex-start; }
      .cotizaciones-filters { justify-content: flex-start; }
    }
  </style>
</head>
<body class="<?= h($bodyClass) ?> side-state-preload">
  <script>
    (function () {
      try {
        if (!window.matchMedia('(max-width: 980px)').matches && localStorage.getItem('hermes_side_collapsed_v1') === '1') {
          document.body.classList.add('side-collapsed');
        }
      } catch (error) {
      }
    })();
  </script>
  <header class="app-header">
    <div class="top">
      <div class="top-left">
        <?php readfile(__DIR__ . '/assets/img/logo-hermes-page.svg'); ?>
        <h1>Panel empresa - Plan <?= h(plan_display_name($usage['plan_code'])) ?></h1>
      </div>
      <div class="actions">
        <a class="btn icon icon-only settings" href="/empresa/dashboard/?module=configuracion" title="Configuracion de usuario" aria-label="Configuracion de usuario">
          <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 6.2a3.8 3.8 0 1 1 0 7.6 3.8 3.8 0 0 1 0-7.6zm0-3.2 1 .2.5 1.8a5.9 5.9 0 0 1 1.6.9l1.7-.7.7.8-.8 1.6c.4.5.7 1.1.9 1.7l1.8.4.2 1-.2 1-1.8.5a5.9 5.9 0 0 1-.9 1.6l.8 1.7-.7.8-1.7-.8a5.9 5.9 0 0 1-1.6.9l-.5 1.8-1 .2-1-.2-.5-1.8a5.9 5.9 0 0 1-1.6-.9l-1.7.8-.8-.8.8-1.7a5.9 5.9 0 0 1-.9-1.6l-1.8-.5-.2-1 .2-1 1.8-.4c.2-.6.5-1.2.9-1.7l-.8-1.6.8-.8 1.7.7c.5-.4 1.1-.7 1.6-.9l.5-1.8z"/></svg>
        </a>
        <a class="btn icon icon-only trash" href="/empresa/dashboard/?module=papelera" title="Ir a papelera" aria-label="Ir a papelera">
          <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 5.5h12M7.2 5.5V4a1 1 0 0 1 1-1h3.6a1 1 0 0 1 1 1v1.5M6.2 5.5l.7 10.5h6.2l.7-10.5M8.7 8.2v5.2M11.3 8.2v5.2"/></svg>
        </a>
        <form method="post" style="margin:0;">
          <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
          <input type="hidden" name="logout" value="1">
          <button class="btn" type="submit">Cerrar sesion</button>
        </form>
      </div>
    </div>
  </header>
  <div class="layout">
    <aside class="side">
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
        <?php if ($canAccessHeroeModules): ?>
          <a class="<?= $module === 'inventario' ? 'active' : '' ?>" href="/empresa/dashboard/?module=inventario">
            <span>Inventario</span>
            <span class="nav-icon" aria-hidden="true">
              <svg viewBox="0 0 16 16"><path d="M2.5 4.5 8 2l5.5 2.5V12L8 14 2.5 12zM8 2v12M2.5 4.5 8 7l5.5-2.5"/></svg>
            </span>
          </a>
          <a class="<?= $module === 'ordenes-servicio' ? 'active' : '' ?>" href="/empresa/dashboard/?module=ordenes-servicio">
            <span>Ordenes de servicio</span>
            <span class="nav-icon" aria-hidden="true">
              <svg viewBox="0 0 16 16"><path d="M3 2.5h10v11H3zM5 5h6M5 7.5h6M5 10h4"/></svg>
            </span>
          </a>
          <a class="<?= $module === 'reportes' ? 'active' : '' ?>" href="/empresa/dashboard/?module=reportes">
            <span>Reportes</span>
            <span class="nav-icon" aria-hidden="true">
              <svg viewBox="0 0 16 16"><path d="M2.5 13.5h11M4 12V8.5M7 12V5.5M10 12V7M13 12V4"/></svg>
            </span>
          </a>
          <a class="<?= $module === 'formularios' ? 'active' : '' ?>" href="/empresa/dashboard/?module=formularios">
            <span>Formularios</span>
            <span class="nav-icon" aria-hidden="true">
              <svg viewBox="0 0 16 16"><path d="M3 2.5h8l2 2V13.5H3zM11 2.5V5h2M5 7h6M5 9.5h6M5 12h4"/></svg>
            </span>
          </a>
          <a class="<?= $module === 'tecnicos' ? 'active' : '' ?>" href="/empresa/dashboard/?module=tecnicos">
            <span>Tecnicos</span>
            <span class="nav-icon" aria-hidden="true">
              <svg viewBox="0 0 16 16"><path d="M8 2.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4ZM3.2 13.5v-.8c0-1.8 1.5-3.2 3.3-3.2h3c1.8 0 3.3 1.4 3.3 3.2v.8"/></svg>
            </span>
          </a>
          <a class="<?= $module === 'carta-gantt' ? 'active' : '' ?>" href="/empresa/dashboard/?module=carta-gantt">
            <span>Carta Gantt</span>
            <span class="nav-icon" aria-hidden="true">
              <svg viewBox="0 0 16 16"><path d="M2.5 3.5h11v9h-11zM4 5.5h3v2H4zM8 8.5h4v2H8zM6 11.5h5"/></svg>
            </span>
          </a>
        <?php endif; ?>
        <a class="<?= $module === 'plan' ? 'active' : '' ?>" href="/empresa/dashboard/?module=plan">
          <span>Plan</span>
          <span class="nav-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16"><path d="M2.5 3.5h11v9h-11zM5 6.2h6M5 8.5h6M5 10.8h3.6"/></svg>
          </span>
        </a>
      </nav>
      <div class="side-toggle-wrap">
        <button class="side-toggle" type="button" data-side-toggle="1" aria-label="Contraer menu" aria-expanded="true" title="Contraer menu">
          <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M12.5 4.5 7 10l5.5 5.5"/></svg>
        </button>
      </div>
    </aside>

    <main class="content">
      <div id="appMain">

      <?php if ($flash['ok'] !== '' || $flash['error'] !== ''): ?>
        <div class="toast-stack" data-toast-stack="1" aria-live="polite" aria-atomic="true">
          <?php if ($flash['ok'] !== ''): ?>
            <div class="toast toast--ok" data-toast="1" data-toast-timeout="5000">
              <div class="toast-msg"><?= h($flash['ok']) ?></div>
              <button class="toast-close" type="button" data-toast-close="1" aria-label="Cerrar notificacion">&times;</button>
            </div>
          <?php endif; ?>
          <?php if ($flash['error'] !== ''): ?>
            <div class="toast toast--err" data-toast="1" data-toast-timeout="5000">
              <div class="toast-msg"><?= h($flash['error']) ?></div>
              <button class="toast-close" type="button" data-toast-close="1" aria-label="Cerrar notificacion">&times;</button>
            </div>
          <?php endif; ?>
        </div>
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
                <span class="dash-pill-v"><?= h(plan_display_name($usage['plan_code'])) ?></span>
              </div>
              <div class="dash-pill">
                <span class="dash-pill-k">Consumo</span>
                <span class="dash-pill-v"><?= h((string)$usage['percent']) ?>%</span>
              </div>
              <div class="dash-pill">
                <span class="dash-pill-k">Disponible</span>
                <span class="dash-pill-v"><?= h((string)max(0, 100 - (int)$usage['percent'])) ?>%</span>
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
              <span>Disponible: <?= h((string)max(0, 100 - (int)$usage['percent'])) ?>%</span>
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

      <?php if ($module === 'plan'): ?>
        <section class="panel compact">
          <?php
            $currentPlanNameUi = plan_display_name($usage['plan_code']);
            $isPlanPaidUi = ($planBilling['payment_status'] === 'paid') || ($planBilling['plan_status'] === 'paid');
            $currentPlanCodeUi = strtolower(trim((string)$usage['plan_code']));
            if (in_array($currentPlanCodeUi, ['mortal', 'basic', 'basico'], true)) {
              $currentPlanCodeUi = 'basico';
            } elseif (in_array($currentPlanCodeUi, ['heroe', 'pro'], true)) {
              $currentPlanCodeUi = 'pro';
            } elseif (in_array($currentPlanCodeUi, ['semidios', 'enterprise'], true)) {
              $currentPlanCodeUi = 'enterprise';
            }
            $planRankUi = [
              'basico' => 1,
              'pro' => 2,
              'enterprise' => 3,
            ];
            $currentPlanRankUi = (int)($planRankUi[$currentPlanCodeUi] ?? 1);
            $isCurrentBasicoUi = ($currentPlanCodeUi === 'basico');
            $isCurrentProUi = ($currentPlanCodeUi === 'pro');
            $isCurrentEnterpriseUi = ($currentPlanCodeUi === 'enterprise');
            $planToneUi = $isPlanPaidUi ? 'ok' : 'warn';
            $planTitleUi = $isPlanPaidUi ? 'Plan pagado' : 'Pago pendiente';
            if ($planBilling['days_left'] === null) {
              $planDaysUi = 'No se pudo calcular la fecha de vencimiento del plan.';
            } elseif ((int)$planBilling['days_left'] < 0) {
              $planDaysUi = 'Tu plan esta vencido hace ' . abs((int)$planBilling['days_left']) . ' dias.';
            } else {
              $planDaysUi = 'Faltan ' . (int)$planBilling['days_left'] . ' dias para que venza tu plan.';
            }
            $isPlanUpToDateUi = $isPlanPaidUi && ($planBilling['days_left'] === null || (int)$planBilling['days_left'] >= 0);
          ?>
          <h2 style="margin-top:0;">Plan actual del cliente: <?= h($currentPlanNameUi) ?></h2>
          <p class="muted" style="margin-top:.25rem;">
            Este modulo resume los beneficios activos del plan <?= h($currentPlanNameUi) ?> para la cuenta empresa.
            Cuando se habiliten nuevas capacidades del plan, este apartado debe actualizarse para mantener consistencia operativa.
          </p>

          <div class="dash-plan-renew dash-plan-renew--<?= h($planToneUi) ?>" style="margin-top:.25rem;">
            <strong><?= h($planTitleUi) ?></strong>
            <span><?= h($planDaysUi) ?></span>
          </div>

          <div class="plan-benefits-grid" aria-label="Beneficios del plan actual">
            <article class="plan-benefit-card">
              <h3>Gestion base centralizada</h3>
              <p>Incluye acceso a los modulos esenciales para administrar la operacion diaria en una sola vista.</p>
              <ul class="plan-basic-list">
                <li>Dashboard ejecutivo.</li>
                <li>Empresa (perfil y datos comerciales).</li>
                <li>Clientes.</li>
                <li>Cotizaciones.</li>
                <li>Papelera y configuracion de usuario.</li>
              </ul>
            </article>

            <article class="plan-benefit-card">
              <h3>Control comercial inicial</h3>
              <p>Permite construir y hacer seguimiento del flujo comercial con trazabilidad de estados y montos.</p>
              <ul class="plan-basic-list">
                <li>Creacion de cotizaciones con items y descuentos.</li>
                <li>Estados operativos de avance.</li>
                <li>Visualizacion de totales y conversion.</li>
              </ul>
            </article>

            <article class="plan-benefit-card">
              <h3>Operacion segura</h3>
              <p>Incluye herramientas para reducir errores y respaldar acciones criticas dentro del panel.</p>
              <ul class="plan-basic-list">
                <li>Papelera con flujo de eliminacion en pasos.</li>
                <li>Mensajes de estado y validaciones de formulario.</li>
                <li>Gestion de cuenta y enlace de recuperacion de clave.</li>
              </ul>
            </article>

            <article class="plan-benefit-card">
              <h3>Estado del plan y almacenamiento</h3>
              <p>Visualiza el consumo y la renovacion para controlar capacidad disponible del servicio.</p>
              <ul class="plan-basic-list">
                <li>Consumo y disponibilidad expresados en porcentaje.</li>
                <li>Estado de pago y modalidad de facturacion.</li>
                <li>Fecha de renovacion y alertas de cuenta.</li>
              </ul>
            </article>
          </div>

          <div class="plan-upgrade-grid" aria-label="Cambiar o pagar plan">
            <article class="plan-upgrade-item<?= $isCurrentBasicoUi ? ' current' : '' ?>">
              <h4>Plan Mortal</h4>
              <?php if ($isCurrentBasicoUi): ?><span class="plan-current-badge">Plan actual</span><?php endif; ?>
              <p>Pago del plan base para mantener operacion y renovacion al dia.</p>
              <?php if ($currentPlanRankUi > 1): ?>
                <span class="plan-pay-link disabled">Plan inferior al actual</span>
              <?php elseif ($isPlanUpToDateUi && $currentPlanCodeUi === 'basico'): ?>
                <span class="plan-pay-link disabled">Cliente al dia</span>
              <?php elseif ($planUpgradeLinks['basico'] !== ''): ?>
                <a class="plan-pay-link" href="<?= h($planUpgradeLinks['basico']) ?>">Ir a pago Mortal</a>
              <?php else: ?>
                <span class="plan-pay-link disabled">Sin link de pago</span>
              <?php endif; ?>
            </article>

            <article class="plan-upgrade-item<?= $isCurrentProUi ? ' current' : '' ?>">
              <h4>Plan Heroe</h4>
              <?php if ($isCurrentProUi): ?><span class="plan-current-badge">Plan actual</span><?php endif; ?>
              <p>Escala capacidades operativas con funciones extendidas y usuarios tecnicos.</p>
              <?php if ($currentPlanRankUi > 2): ?>
                <span class="plan-pay-link disabled">Plan inferior al actual</span>
              <?php elseif ($isPlanUpToDateUi && $currentPlanCodeUi === 'pro'): ?>
                <span class="plan-pay-link disabled">Cliente al dia</span>
              <?php elseif ($planUpgradeLinks['pro'] !== ''): ?>
                <a class="plan-pay-link alt" href="<?= h($planUpgradeLinks['pro']) ?>">Subir a Heroe</a>
              <?php else: ?>
                <span class="plan-pay-link disabled">Sin link de pago</span>
              <?php endif; ?>
            </article>

            <article class="plan-upgrade-item<?= $isCurrentEnterpriseUi ? ' current' : '' ?>">
              <h4>Plan Semidios</h4>
              <?php if ($isCurrentEnterpriseUi): ?><span class="plan-current-badge">Plan actual</span><?php endif; ?>
              <p>Mayor capacidad para equipos tecnicos y reporteria avanzada interna/cliente.</p>
              <?php if ($isPlanUpToDateUi && $currentPlanCodeUi === 'enterprise'): ?>
                <span class="plan-pay-link disabled">Cliente al dia</span>
              <?php elseif ($planUpgradeLinks['enterprise'] !== ''): ?>
                <a class="plan-pay-link alt" href="<?= h($planUpgradeLinks['enterprise']) ?>">Subir a Semidios</a>
              <?php else: ?>
                <span class="plan-pay-link disabled">Sin link de pago</span>
              <?php endif; ?>
            </article>

            <article class="plan-upgrade-item">
              <h4>Plan Olimpico</h4>
              <p>Plan empresarial personalizado segun capacidad, prioridad y alcance requerido.</p>
              <a class="plan-pay-link alt" href="mailto:contacto@gesmanhermes.com?subject=Quiero%20plan%20Olimpico%20GesMan%20HERMES">Contactar para plan Olimpico</a>
            </article>
          </div>
          <p class="plan-upgrade-note">Los links de pago se generan por cuenta y tienen vigencia temporal por seguridad.</p>
        </section>
      <?php endif; ?>

      <?php if ($module === 'configuracion'): ?>
        <section class="panel compact">
          <h2 style="margin-top:0;">Configuracion de usuario</h2>
          <p class="muted" style="margin-top:.25rem;">Esta seccion corresponde a tu cuenta de acceso. Los datos de empresa se administran por separado en el modulo Empresa.</p>

          <div class="empresa-fields" style="margin-top:1rem;">
            <div class="grid">
              <div class="field">
                <label>Correo de cuenta</label>
                <input type="text" value="<?= h((string)$accountSettings['email']) ?>" readonly>
              </div>
              <div class="field">
                <label>Empresa vinculada</label>
                <input type="text" value="<?= h((string)$accountSettings['company_name']) ?>" readonly>
              </div>
              <div class="field">
                <label>Nombre de contacto</label>
                <input type="text" value="<?= h((string)$accountSettings['contact_name']) ?>" readonly>
              </div>
              <div class="field">
                <label>Telefono de cuenta</label>
                <input type="text" value="<?= h((string)$accountSettings['phone']) ?>" readonly>
              </div>
            </div>
          </div>

          <form method="post" style="margin-top:1rem; border-top:1px solid #d9e3f1; padding-top:1rem;">
            <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
            <h3 style="margin:0 0 .5rem 0;">Seguridad de cuenta</h3>
            <p class="muted" style="margin:.25rem 0 .75rem 0;">Para cambiar clave de manera segura, enviaremos un enlace de recuperacion al correo de tu cuenta. El enlace expira en 60 minutos.</p>
            <button class="btn" type="submit" name="action" value="send_password_recovery_link">Enviar enlace de recuperacion</button>
          </form>
        </section>

        <section class="panel" style="margin-top:1rem;">
          <h3 style="margin-top:0;">Historial de pagos</h3>
          <?php if (!$paymentHistoryAvailable): ?>
            <p class="muted">No hay fuente de historial de pagos disponible en este entorno.</p>
          <?php elseif (empty($paymentHistoryRows)): ?>
            <p class="muted">Aun no existen transacciones registradas para esta cuenta.</p>
          <?php else: ?>
            <div style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>Fecha</th>
                    <th>Proveedor</th>
                    <th>Estado</th>
                    <th>Monto</th>
                    <th>Moneda</th>
                    <th>Referencia</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($paymentHistoryRows as $paymentRow): ?>
                    <?php
                      $reference = (string)($paymentRow['external_reference'] ?? '');
                      if ($reference === '') {
                        $reference = (string)($paymentRow['preference_id'] ?? '');
                      }
                      if ($reference === '') {
                        $reference = (string)($paymentRow['provider_payment_id'] ?? '-');
                      }
                    ?>
                    <tr>
                      <td><?= h((string)($paymentRow['created_at'] ?? '')) ?></td>
                      <td><?= h((string)($paymentRow['provider'] ?? '-')) ?></td>
                      <td><?= h((string)($paymentRow['status'] ?? '-')) ?></td>
                      <td>$<?= h(money_clp((float)($paymentRow['amount'] ?? 0))) ?></td>
                      <td><?= h((string)($paymentRow['currency_id'] ?? 'CLP')) ?></td>
                      <td><?= h($reference) ?></td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php endif; ?>
        </section>
      <?php endif; ?>

      <?php if ($module === 'inventario'): ?>
        <?php $isInventoryEdit = (int)($inventoryForm['id'] ?? 0) > 0; ?>
        <section class="panel">
          <div class="clientes-toolbar">
            <h2 style="margin:0;">Inventario</h2>
            <div style="display:flex; gap:.5rem; align-items:center;">
              <span class="clientes-count">Total: <?= h((string)count($inventoryItems)) ?></span>
              <button class="btn" type="button" data-open-inventory-history-modal="1">Historial de movimientos</button>
              <button class="btn" type="button" data-open-inventory-move-modal="1">Entrada / salida</button>
              <button class="btn primary" type="button" data-open-inventory-modal="1">Agregar item</button>
            </div>
          </div>
          <p class="muted" style="margin:0;">Controla stock, registra entradas y salidas con motivo, y revisa el historial de movimientos.</p>
        </section>

        <section class="panel">
          <h3>Listado de items</h3>
          <?php if (empty($inventoryItems)): ?>
            <p class="muted">Aun no tienes items registrados en inventario.</p>
          <?php else: ?>
            <div class="clientes-table-wrap" style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>SKU</th>
                    <th>Item</th>
                    <th>Unidad</th>
                    <th>Stock</th>
                    <th>Minimo</th>
                    <th>Critico</th>
                    <th>Costo</th>
                    <th>Estado</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($inventoryItems as $inv): ?>
                    <?php
                      $stockActual = (float)($inv['stock_actual'] ?? 0);
                      $stockMinimo = (float)($inv['stock_minimo'] ?? 0);
                      $stockCritico = (float)($inv['stock_critico'] ?? 0);
                      $stockClass = 'ok';
                      if ($stockCritico > 0 && $stockActual <= $stockCritico) {
                        $stockClass = 'danger';
                      } elseif ($stockMinimo > 0 && $stockActual <= $stockMinimo) {
                        $stockClass = 'warn';
                      }
                    ?>
                    <tr>
                      <td><strong><?= h((string)$inv['sku']) ?></strong></td>
                      <td>
                        <?= h((string)$inv['nombre']) ?>
                        <?php if ((string)($inv['descripcion'] ?? '') !== ''): ?>
                          <div class="muted"><?= h((string)$inv['descripcion']) ?></div>
                        <?php endif; ?>
                      </td>
                      <td><?= h((string)($inv['unidad'] ?? 'unidad')) ?></td>
                      <td>
                        <span class="status <?= h($stockClass) ?>"><?= h(number_format($stockActual, 2, ',', '.')) ?></span>
                      </td>
                      <td><?= h(number_format($stockMinimo, 2, ',', '.')) ?></td>
                      <td><?= h(number_format($stockCritico, 2, ',', '.')) ?></td>
                      <td>$<?= h(money_clp((float)($inv['costo_unitario'] ?? 0))) ?></td>
                      <td>
                        <span class="status <?= ((string)($inv['estado'] ?? 'activo') === 'activo' ? 'ok' : 'warn') ?>">
                          <?= h((string)($inv['estado'] ?? 'activo')) ?>
                        </span>
                      </td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn"
                            type="button"
                            title="Registrar movimiento"
                            aria-label="Registrar movimiento"
                            data-open-inventory-move-modal="1"
                            data-move-item-id="<?= h((string)$inv['id']) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 2.5v15M2.5 10h15"/></svg>
                          </button>
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Editar item"
                            aria-label="Editar item"
                            data-edit-inventory-item="1"
                            data-inv-id="<?= h((string)$inv['id']) ?>"
                            data-inv-sku="<?= h((string)$inv['sku']) ?>"
                            data-inv-nombre="<?= h((string)$inv['nombre']) ?>"
                            data-inv-descripcion="<?= h((string)($inv['descripcion'] ?? '')) ?>"
                            data-inv-unidad="<?= h((string)($inv['unidad'] ?? 'unidad')) ?>"
                            data-inv-stock-actual="<?= h((string)$stockActual) ?>"
                            data-inv-stock-minimo="<?= h((string)$stockMinimo) ?>"
                            data-inv-stock-critico="<?= h((string)$stockCritico) ?>"
                            data-inv-costo-unitario="<?= h((string)($inv['costo_unitario'] ?? 0)) ?>"
                            data-inv-estado="<?= h((string)($inv['estado'] ?? 'activo')) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M13.5 3.5l3 3M4 16h3l9-9-3-3-9 9v3z"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Mover a papelera"
                            aria-label="Mover a papelera"
                            data-open-delete-confirm="1"
                            data-delete-action="delete_inventory_item"
                            data-delete-id-field="inventory_item_id"
                            data-delete-id-value="<?= h((string)$inv['id']) ?>"
                            data-delete-entity="item de inventario"
                            data-delete-description="<?= h((string)$inv['nombre']) ?>"
                            data-delete-mode="trash"
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

        <div class="modal-backdrop" id="inventoryHistoryModal" aria-hidden="true">
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="inventoryHistoryModalTitle" style="max-width: 1000px;">
            <div class="modal-head">
              <h3 id="inventoryHistoryModalTitle">Historial de movimientos</h3>
              <button class="btn" type="button" data-close-inventory-history-modal="1">Cerrar</button>
            </div>
            <div class="modal-body">
              <?php if (empty($inventoryMovements)): ?>
                <p class="muted">Aun no hay movimientos registrados.</p>
              <?php else: ?>
                <div class="clientes-table-wrap" style="overflow:auto; max-height: 60vh;">
                  <table>
                    <thead>
                      <tr>
                        <th>Fecha</th>
                        <th>Item</th>
                        <th>Tipo</th>
                        <th>Cantidad</th>
                        <th>Stock</th>
                        <th>Motivo</th>
                      </tr>
                    </thead>
                    <tbody>
                      <?php foreach ($inventoryMovements as $mov): ?>
                        <?php
                          $moveSku = trim((string)($mov['current_sku'] ?? ''));
                          if ($moveSku === '') {
                            $moveSku = trim((string)($mov['item_sku'] ?? ''));
                          }
                          $moveName = trim((string)($mov['current_nombre'] ?? ''));
                          if ($moveName === '') {
                            $moveName = trim((string)($mov['item_nombre'] ?? ''));
                          }
                          $moveType = inventory_type_normalize((string)($mov['tipo'] ?? 'entrada'));
                        ?>
                        <tr>
                          <td><?= h((string)($mov['created_at'] ?? '')) ?></td>
                          <td><strong><?= h($moveSku) ?></strong><div class="muted"><?= h($moveName) ?></div></td>
                          <td><span class="status <?= $moveType === 'entrada' ? 'ok' : ($moveType === 'salida' ? 'warn' : '') ?>"><?= h($moveType) ?></span></td>
                          <td><?= h(number_format((float)($mov['cantidad'] ?? 0), 2, ',', '.')) ?></td>
                          <td><?= h(number_format((float)($mov['stock_anterior'] ?? 0), 2, ',', '.')) ?> -> <?= h(number_format((float)($mov['stock_nuevo'] ?? 0), 2, ',', '.')) ?></td>
                          <td><?= h((string)($mov['motivo'] ?? '')) ?></td>
                        </tr>
                      <?php endforeach; ?>
                    </tbody>
                  </table>
                </div>
              <?php endif; ?>
            </div>
          </div>
        </div>

        <div class="modal-backdrop<?= $openInventoryModal ? ' open' : '' ?>" id="inventoryModal" aria-hidden="<?= $openInventoryModal ? 'false' : 'true' ?>">
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="inventoryModalTitle">
            <div class="modal-head">
              <h3 id="inventoryModalTitle"><?= $isInventoryEdit ? 'Editar item de inventario' : 'Agregar item de inventario' ?></h3>
              <button class="btn" type="button" data-close-inventory-modal="1">Cerrar</button>
            </div>
            <div class="modal-body">
              <form method="post" id="inventoryModalForm">
                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                <input type="hidden" name="action" value="<?= $isInventoryEdit ? 'update_inventory_item' : 'add_inventory_item' ?>" data-inventory-action="1">
                <input type="hidden" name="inventory_item_id" value="<?= h((string)($inventoryForm['id'] ?? '')) ?>" data-inventory-id="1">

                <div class="clientes-form-grid">
                  <div class="field"><label>SKU</label><input type="text" name="sku" value="<?= h((string)$inventoryForm['sku']) ?>" required></div>
                  <div class="field"><label>Nombre</label><input type="text" name="nombre" value="<?= h((string)$inventoryForm['nombre']) ?>" required></div>
                  <div class="field"><label>Unidad</label><input type="text" name="unidad" value="<?= h((string)$inventoryForm['unidad']) ?>"></div>
                  <div class="field"><label>Stock actual</label><input type="number" min="0" step="0.01" name="stock_actual" value="<?= h((string)$inventoryForm['stock_actual']) ?>" required></div>
                  <div class="field"><label>Stock minimo</label><input type="number" min="0" step="0.01" name="stock_minimo" value="<?= h((string)$inventoryForm['stock_minimo']) ?>"></div>
                  <div class="field"><label>Stock critico</label><input type="number" min="0" step="0.01" name="stock_critico" value="<?= h((string)$inventoryForm['stock_critico']) ?>"></div>
                  <div class="field"><label>Costo unitario</label><input type="number" min="0" step="0.01" name="costo_unitario" value="<?= h((string)$inventoryForm['costo_unitario']) ?>"></div>
                  <div class="field">
                    <label>Estado</label>
                    <select name="estado">
                      <option value="activo" <?= ((string)$inventoryForm['estado'] === 'activo' ? 'selected' : '') ?>>activo</option>
                      <option value="inactivo" <?= ((string)$inventoryForm['estado'] === 'inactivo' ? 'selected' : '') ?>>inactivo</option>
                    </select>
                  </div>
                  <div class="field full"><label>Descripcion</label><textarea name="descripcion" rows="3"><?= h((string)$inventoryForm['descripcion']) ?></textarea></div>
                </div>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-inventory-modal="1">Cancelar</button>
                  <button class="btn primary" type="submit" data-inventory-submit-label="1"><?= $isInventoryEdit ? 'Actualizar item' : 'Guardar item' ?></button>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div class="modal-backdrop<?= $openInventoryMoveModal ? ' open' : '' ?>" id="inventoryMoveModal" aria-hidden="<?= $openInventoryMoveModal ? 'false' : 'true' ?>">
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="inventoryMoveModalTitle">
            <div class="modal-head">
              <h3 id="inventoryMoveModalTitle">Registrar entrada / salida</h3>
              <button class="btn" type="button" data-close-inventory-move-modal="1">Cerrar</button>
            </div>
            <div class="modal-body">
              <form method="post" id="inventoryMoveModalForm">
                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                <input type="hidden" name="action" value="add_inventory_movement">
                <div class="clientes-form-grid">
                  <div class="field full">
                    <label>Item</label>
                    <select name="movement_item_id" required>
                      <option value="">Selecciona un item</option>
                      <?php foreach ($inventoryItems as $inv): ?>
                        <option value="<?= h((string)$inv['id']) ?>" <?= (string)$inventoryMoveForm['item_id'] === (string)$inv['id'] ? 'selected' : '' ?>>
                          <?= h((string)$inv['sku']) ?> - <?= h((string)$inv['nombre']) ?>
                        </option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="field">
                    <label>Tipo</label>
                    <select name="movement_tipo" required>
                      <option value="entrada" <?= ((string)$inventoryMoveForm['tipo'] === 'entrada' ? 'selected' : '') ?>>entrada</option>
                      <option value="salida" <?= ((string)$inventoryMoveForm['tipo'] === 'salida' ? 'selected' : '') ?>>salida</option>
                    </select>
                  </div>
                  <div class="field">
                    <label>Cantidad</label>
                    <input type="number" min="0.01" step="0.01" name="movement_cantidad" value="<?= h((string)$inventoryMoveForm['cantidad']) ?>" required>
                  </div>
                  <div class="field full">
                    <label>Motivo</label>
                    <textarea name="movement_motivo" rows="3" required><?= h((string)$inventoryMoveForm['motivo']) ?></textarea>
                  </div>
                </div>
                <div class="modal-actions">
                  <button class="btn" type="button" data-close-inventory-move-modal="1">Cancelar</button>
                  <button class="btn primary" type="submit">Guardar movimiento</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($module === 'ordenes-servicio'): ?>
        <?php $isSOEdit = (int)($serviceOrderForm['id'] ?? 0) > 0; ?>
        <section class="panel">
          <div class="clientes-toolbar">
            <h2 style="margin:0;">Ordenes de servicio</h2>
            <div style="display:flex; gap:.5rem; align-items:center;">
              <span class="clientes-count">Total: <?= h((string)count($serviceOrders)) ?></span>
              <button class="btn primary" type="button" data-open-service-order-modal="1">Nueva orden</button>
            </div>
          </div>
          <p class="muted" style="margin:0;">Planifica servicios, asigna tecnicos en una o varias jornadas, define repuestos desde inventario y agrega checklist.</p>
        </section>

        <section class="panel">
          <h3>Listado de ordenes</h3>
          <?php if (empty($serviceOrders)): ?>
            <p class="muted">Aun no tienes ordenes de servicio registradas.</p>
          <?php else: ?>
            <div class="clientes-table-wrap" style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>Codigo</th>
                    <th>Titulo</th>
                    <th>Cliente</th>
                    <th>Estado</th>
                    <th>Prioridad</th>
                    <th>Jornadas</th>
                    <th>Tecnicos</th>
                    <th>Repuestos</th>
                    <th>Checklist</th>
                    <th>Formularios</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                <?php foreach ($serviceOrders as $soRow):
                    $soIdR = (int)$soRow['id'];
                    $asgList = $serviceOrderAssignmentsByOrder[$soIdR] ?? [];
                    $partsList = $serviceOrderPartsByOrder[$soIdR] ?? [];
                    $chkList = $serviceOrderChecklistByOrder[$soIdR] ?? [];
                    $formTplIds = $serviceOrderFormTemplatesByOrder[$soIdR] ?? [];
                    $jornadasUniq = [];
                    $tecsUniq = [];
                    foreach ($asgList as $aRow) {
                      $jornadasUniq[(string)$aRow['work_date']] = true;
                      $tecsUniq[(string)$aRow['technician_nombre']] = true;
                    }
                    $chkTotal = count($chkList);
                    $chkDone = 0;
                    foreach ($chkList as $cRow) { if ((int)$cRow['completado'] === 1) { $chkDone++; } }
                    $formsAssignedNames = [];
                    foreach ((array)$formTplIds as $tplIdTmp) {
                      $tplInfo = $formTemplatesById[(int)$tplIdTmp] ?? null;
                      if (!is_array($tplInfo)) {
                        continue;
                      }
                      $tplNameTmp = trim((string)($tplInfo['name'] ?? ''));
                      if ($tplNameTmp !== '') {
                        $formsAssignedNames[] = $tplNameTmp;
                      }
                    }
                    $editPayload = json_encode([
                      'id' => $soIdR,
                      'customer_id' => (string)$soRow['customer_id'],
                      'codigo' => (string)$soRow['codigo'],
                      'titulo' => (string)$soRow['titulo'],
                      'descripcion' => (string)($soRow['descripcion'] ?? ''),
                      'estado' => (string)$soRow['estado'],
                      'prioridad' => (string)$soRow['prioridad'],
                      'fecha_creacion' => (string)($soRow['fecha_creacion'] ?? ''),
                      'observaciones' => (string)($soRow['observaciones'] ?? ''),
                      'assignments' => array_map(static fn($a) => [
                        'technician_id' => (string)$a['technician_id'],
                        'work_date' => (string)$a['work_date'],
                        'start_time' => (string)($a['start_time'] ?? ''),
                        'end_time' => (string)($a['end_time'] ?? ''),
                        'notas' => (string)($a['notas'] ?? ''),
                      ], $asgList),
                      'parts' => array_map(static fn($p) => [
                        'inventory_item_id' => $p['inventory_item_id'] !== null ? (string)$p['inventory_item_id'] : '',
                        'sku' => (string)$p['sku'],
                        'nombre' => (string)$p['nombre'],
                        'unidad' => (string)$p['unidad'],
                        'cantidad' => (string)$p['cantidad'],
                        'notas' => (string)($p['notas'] ?? ''),
                      ], $partsList),
                      'checklist' => array_map(static fn($c) => [
                        'id' => (int)$c['id'],
                        'descripcion' => (string)$c['descripcion'],
                        'completado' => (string)$c['completado'],
                      ], $chkList),
                      'form_template_ids' => array_values(array_map(static fn($id) => (string)$id, $formTplIds)),
                    ], JSON_UNESCAPED_UNICODE);
                    $assignPayload = json_encode([
                      'id' => $soIdR,
                      'codigo' => (string)$soRow['codigo'],
                      'titulo' => (string)$soRow['titulo'],
                      'assignments' => array_map(static fn($a) => [
                        'technician_id' => (string)$a['technician_id'],
                        'work_date' => (string)$a['work_date'],
                        'start_time' => (string)($a['start_time'] ?? ''),
                        'end_time' => (string)($a['end_time'] ?? ''),
                        'notas' => (string)($a['notas'] ?? ''),
                      ], $asgList),
                    ], JSON_UNESCAPED_UNICODE);
                ?>
                  <tr class="so-main-row">
                    <td><?= h((string)$soRow['codigo']) ?></td>
                    <td><?= h((string)$soRow['titulo']) ?></td>
                    <td><?= h((string)($soRow['customer_name'] ?? '')) ?></td>
                    <td><?= h((string)$soRow['estado']) ?></td>
                    <td><?= h((string)$soRow['prioridad']) ?></td>
                    <td><?= h((string)count($jornadasUniq)) ?></td>
                    <td><?= h((string)count($tecsUniq)) ?></td>
                    <td><?= h((string)count($partsList)) ?></td>
                    <td><?= h($chkDone . '/' . $chkTotal) ?></td>
                    <td><?= h((string)count($formTplIds)) ?></td>
                    <td class="quote-action-cell">
                      <div class="action-icons">
                        <button
                          class="icon-btn"
                          type="button"
                          title="PDF OS"
                          aria-label="PDF OS"
                          data-open-quote-preview="1"
                          data-quote-number="<?= h((string)$soRow['codigo']) ?>"
                          data-preview-url="/empresa/dashboard/?module=ordenes-servicio&amp;view_service_order_id=<?= h((string)$soIdR) ?>&amp;so_embed=1"
                          data-print-url="/empresa/dashboard/?module=ordenes-servicio&amp;view_service_order_id=<?= h((string)$soIdR) ?>"
                        >
                          <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 2.5h7l3 3V17a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-14a.5.5 0 0 1 .5-.5zM12 2.5V6h3M6.5 11h7M6.5 14h7"/></svg>
                        </button>
                        <button
                          class="icon-btn"
                          type="button"
                          title="Ver detalle"
                          aria-label="Ver detalle"
                          data-so-toggle-detail="1"
                          data-so-id="<?= h((string)$soIdR) ?>"
                        >
                          <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M2 10s3-5 8-5 8 5 8 5-3 5-8 5-8-5-8-5zm8-2.2a2.2 2.2 0 1 0 0 4.4 2.2 2.2 0 0 0 0-4.4z"/></svg>
                        </button>
                        <button
                          class="icon-btn"
                          type="button"
                          title="Asignar tecnicos"
                          aria-label="Asignar tecnicos"
                          data-open-so-assign="1"
                          data-so-assign-payload='<?= h($assignPayload) ?>'
                        >
                          <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 10a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zm-6 8a6 6 0 0 1 12 0M15.5 10.5v6M12.5 13.5h6"/></svg>
                        </button>
                        <button
                          class="icon-btn edit"
                          type="button"
                          title="Editar orden"
                          aria-label="Editar orden"
                          data-edit-service-order="1"
                          data-so-payload='<?= h($editPayload) ?>'
                        >
                          <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M13.5 3.5l3 3M4 16h3l9-9-3-3-9 9v3z"/></svg>
                        </button>
                        <button
                          class="icon-btn danger"
                          type="button"
                          title="Mover a papelera"
                          aria-label="Mover a papelera"
                          data-open-delete-confirm="1"
                          data-delete-entity="orden de servicio"
                          data-delete-description="<?= h((string)$soRow['codigo'] . ' - ' . $soRow['titulo']) ?>"
                          data-delete-action="delete_service_order"
                          data-delete-id-field="service_order_id"
                          data-delete-id-value="<?= h((string)$soIdR) ?>"
                          data-delete-mode="trash"
                        >
                          <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3.5 5.5h13M8 5.5V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M6 5.5l.7 10.5h6.6L14 5.5M8.7 8v5.5M11.3 8v5.5"/></svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                  <tr class="so-detail-row" data-so-detail-row="<?= h((string)$soIdR) ?>" hidden>
                    <td colspan="11">
                      <div class="so-detail-wrap">
                        <div class="so-detail-block">
                          <h4>Jornadas y tecnicos</h4>
                          <?php if (empty($asgList)): ?>
                            <p class="muted">Sin jornadas asignadas.</p>
                          <?php else: ?>
                            <div style="overflow:auto;">
                              <table class="so-detail-table">
                                <thead>
                                  <tr><th>Tecnico</th><th>Fecha</th><th>Inicio</th><th>Fin</th><th>Notas</th></tr>
                                </thead>
                                <tbody>
                                  <?php foreach ($asgList as $aRow): ?>
                                    <tr>
                                      <td><?= h((string)$aRow['technician_nombre']) ?></td>
                                      <td><?= h((string)$aRow['work_date']) ?></td>
                                      <td><?= h((string)($aRow['start_time'] ?? '')) ?></td>
                                      <td><?= h((string)($aRow['end_time'] ?? '')) ?></td>
                                      <td><?= h((string)($aRow['notas'] ?? '')) ?></td>
                                    </tr>
                                  <?php endforeach; ?>
                                </tbody>
                              </table>
                            </div>
                          <?php endif; ?>
                        </div>

                        <div class="so-detail-block">
                          <h4>Repuestos previstos</h4>
                          <?php if (empty($partsList)): ?>
                            <p class="muted">Sin repuestos asociados.</p>
                          <?php else: ?>
                            <div style="overflow:auto;">
                              <table class="so-detail-table">
                                <thead>
                                  <tr><th>SKU</th><th>Nombre</th><th>Unidad</th><th>Cantidad</th><th>Notas</th></tr>
                                </thead>
                                <tbody>
                                  <?php foreach ($partsList as $pRow): ?>
                                    <tr>
                                      <td><?= h((string)$pRow['sku']) ?></td>
                                      <td><?= h((string)$pRow['nombre']) ?></td>
                                      <td><?= h((string)$pRow['unidad']) ?></td>
                                      <td><?= h((string)$pRow['cantidad']) ?></td>
                                      <td><?= h((string)($pRow['notas'] ?? '')) ?></td>
                                    </tr>
                                  <?php endforeach; ?>
                                </tbody>
                              </table>
                            </div>
                          <?php endif; ?>
                        </div>

                        <div class="so-detail-block">
                          <h4>Checklist operativo</h4>
                          <?php if (empty($chkList)): ?>
                            <p class="muted">Sin checklist definido.</p>
                          <?php else: ?>
                            <div class="so-checklist-items">
                              <?php foreach ($chkList as $cRow): ?>
                                <?php $isDone = (int)$cRow['completado'] === 1; ?>
                                <label class="so-check-item <?= $isDone ? 'done' : '' ?>">
                                  <input
                                    type="checkbox"
                                    data-so-check-toggle="1"
                                    data-checklist-id="<?= h((string)$cRow['id']) ?>"
                                    data-next-state="<?= $isDone ? '0' : '1' ?>"
                                    <?= $isDone ? 'checked' : '' ?>
                                  >
                                  <span><?= h((string)$cRow['descripcion']) ?></span>
                                </label>
                              <?php endforeach; ?>
                            </div>
                          <?php endif; ?>
                        </div>

                        <div class="so-detail-block">
                          <h4>Formularios asignados</h4>
                          <?php if (empty($formsAssignedNames)): ?>
                            <p class="muted">Sin formularios asignados.</p>
                          <?php else: ?>
                            <ul class="so-template-list">
                              <?php foreach ($formsAssignedNames as $tplAssignedName): ?>
                                <li><?= h($tplAssignedName) ?></li>
                              <?php endforeach; ?>
                            </ul>
                          <?php endif; ?>
                        </div>
                      </div>
                    </td>
                  </tr>
                <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php endif; ?>
        </section>

        <div class="modal-backdrop<?= $openServiceOrderModal ? ' open' : '' ?>" id="serviceOrderModal" aria-hidden="<?= $openServiceOrderModal ? 'false' : 'true' ?>">
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="serviceOrderModalTitle" style="max-width: 1100px;">
            <div class="modal-head">
              <h3 id="serviceOrderModalTitle"><?= $isSOEdit ? 'Editar orden de servicio' : 'Nueva orden de servicio' ?></h3>
              <button class="modal-close" type="button" data-close-service-order-modal="1" aria-label="Cerrar">x</button>
            </div>
            <form method="post" id="serviceOrderModalForm" autocomplete="off">
              <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
              <input type="hidden" name="action" value="<?= $isSOEdit ? 'update_service_order' : 'add_service_order' ?>" data-so-action="1">
              <input type="hidden" name="service_order_id" value="<?= h((string)$serviceOrderForm['id']) ?>" data-so-id="1">

              <div class="modal-body" style="display:flex; flex-direction:column; gap:.85rem;">
                <div class="so-section">
                  <p class="so-section-title">Datos generales</p>
                  <div class="so-grid">
                    <div class="field">
                      <label>Cliente *</label>
                      <select name="customer_id" required>
                        <option value="">Selecciona un cliente</option>
                        <?php foreach ($customers as $cOpt): ?>
                          <option value="<?= h((string)$cOpt['id']) ?>" <?= ((string)$serviceOrderForm['customer_id'] === (string)$cOpt['id']) ? 'selected' : '' ?>><?= h((string)$cOpt['razon_social']) ?></option>
                        <?php endforeach; ?>
                      </select>
                    </div>
                    <div class="field">
                      <label>Codigo (opcional)</label>
                      <input type="text" name="codigo" value="<?= h((string)$serviceOrderForm['codigo']) ?>" placeholder="auto: OS-AAAAMM-NNN">
                    </div>
                    <div class="field full">
                      <label>Titulo *</label>
                      <input type="text" name="titulo" value="<?= h((string)$serviceOrderForm['titulo']) ?>" required maxlength="190">
                    </div>
                    <div class="field">
                      <label>Estado</label>
                      <select name="estado">
                        <?php foreach (['borrador', 'programada', 'en_curso', 'completada', 'cancelada'] as $stOpt): ?>
                          <option value="<?= h($stOpt) ?>" <?= ((string)$serviceOrderForm['estado'] === $stOpt) ? 'selected' : '' ?>><?= h($stOpt) ?></option>
                        <?php endforeach; ?>
                      </select>
                    </div>
                    <div class="field">
                      <label>Prioridad</label>
                      <select name="prioridad">
                        <?php foreach (['baja', 'normal', 'alta', 'urgente'] as $prOpt): ?>
                          <option value="<?= h($prOpt) ?>" <?= ((string)$serviceOrderForm['prioridad'] === $prOpt) ? 'selected' : '' ?>><?= h($prOpt) ?></option>
                        <?php endforeach; ?>
                      </select>
                    </div>
                    <div class="field">
                      <label>Fecha de creacion</label>
                      <input type="date" name="fecha_creacion" value="<?= h((string)$serviceOrderForm['fecha_creacion']) ?>">
                    </div>
                    <div class="field full">
                      <label>Descripcion</label>
                      <textarea name="descripcion" rows="2"><?= h((string)$serviceOrderForm['descripcion']) ?></textarea>
                    </div>
                    <div class="field full">
                      <label>Observaciones internas</label>
                      <textarea name="observaciones" rows="2"><?= h((string)$serviceOrderForm['observaciones']) ?></textarea>
                    </div>
                    <div class="field full">
                      <label>Formularios asignados a esta OS</label>
                      <?php if (empty($formTemplates)): ?>
                        <div class="muted">No hay plantillas activas. Crea primero una plantilla en el modulo Formularios.</div>
                      <?php else: ?>
                        <div class="so-template-picker" data-so-template-picker="1">
                          <?php foreach ($formTemplates as $tplOpt): ?>
                            <?php $tplOptId = (string)((int)($tplOpt['id'] ?? 0)); ?>
                            <?php $tplSelected = in_array($tplOptId, array_map('strval', (array)($serviceOrderForm['form_template_ids'] ?? [])), true); ?>
                            <label class="so-template-option">
                              <input type="checkbox" data-so-template-check="1" name="form_template_ids[]" value="<?= h($tplOptId) ?>" <?= $tplSelected ? 'checked' : '' ?>>
                              <span><?= h((string)($tplOpt['name'] ?? ('Plantilla #' . $tplOptId))) ?></span>
                            </label>
                          <?php endforeach; ?>
                        </div>
                      <?php endif; ?>
                      <small>Marca una o varias plantillas para esta OS; apareceran en el modulo Reportes para completarlas.</small>
                    </div>
                  </div>
                </div>

                <div class="so-section">
                  <p class="so-section-title">Asignaciones (jornadas y tecnicos)</p>
                  <p class="so-section-hint">Cada fila es una jornada (tecnico + dia). No se permite repetir el mismo (tecnico, dia) en la orden ni que un tecnico este asignado a otra orden en la misma fecha.</p>
                  <div data-so-assignments-container="1"></div>
                  <button class="btn so-add-btn" type="button" data-so-add-assignment="1">+ Agregar jornada</button>
                  <template data-so-tech-options="1">
                    <option value="">Selecciona tecnico</option>
                    <?php foreach ($technicians as $tOpt): ?>
                      <?php $soTechLabel = trim((string)($tOpt['nombre'] ?? '') . ' ' . (string)($tOpt['apellido'] ?? '')); ?>
                      <option value="<?= h((string)$tOpt['id']) ?>"><?= h($soTechLabel !== '' ? $soTechLabel : ('Tecnico #' . (string)$tOpt['id'])) ?></option>
                    <?php endforeach; ?>
                  </template>
                </div>

                <div class="so-section">
                  <p class="so-section-title">Repuestos previstos</p>
                  <p class="so-section-hint">Carga desde inventario o agrega items ad-hoc (sku libre).</p>
                  <div data-so-parts-container="1"></div>
                  <button class="btn so-add-btn" type="button" data-so-add-part="1">+ Agregar repuesto</button>
                  <template data-so-inv-options="1">
                    <option value="">-- Ad-hoc (sin inventario) --</option>
                    <?php foreach ($inventoryItems as $iOpt): ?>
                      <option value="<?= h((string)$iOpt['id']) ?>" data-sku="<?= h((string)$iOpt['sku']) ?>" data-nombre="<?= h((string)$iOpt['nombre']) ?>" data-unidad="<?= h((string)$iOpt['unidad']) ?>"><?= h($iOpt['sku'] . ' - ' . $iOpt['nombre']) ?></option>
                    <?php endforeach; ?>
                  </template>
                </div>

                <div class="so-section">
                  <p class="so-section-title">Checklist</p>
                  <div data-so-checklist-container="1"></div>
                  <button class="btn so-add-btn" type="button" data-so-add-checklist="1">+ Agregar item de checklist</button>
                </div>
              </div>

              <div class="modal-actions">
                <button class="btn" type="button" data-close-service-order-modal="1">Cancelar</button>
                <button class="btn primary" type="submit"><?= $isSOEdit ? 'Guardar cambios' : 'Crear orden' ?></button>
              </div>
            </form>
          </div>
        </div>

        <div class="modal-backdrop" id="serviceOrderAssignModal" aria-hidden="true">
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="serviceOrderAssignTitle" style="max-width: 980px;">
            <div class="modal-head">
              <h3 id="serviceOrderAssignTitle">Asignar tecnicos a la orden</h3>
              <button class="modal-close" type="button" data-close-so-assign-modal="1" aria-label="Cerrar">x</button>
            </div>
            <form method="post" id="serviceOrderAssignForm" autocomplete="off">
              <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
              <input type="hidden" name="action" value="save_service_order_assignments">
              <input type="hidden" name="service_order_id" value="" data-so-assign-id="1">

              <div class="modal-body" style="display:flex; flex-direction:column; gap:.85rem;">
                <div class="so-section">
                  <p class="so-section-title">Orden seleccionada</p>
                  <p class="so-section-hint" data-so-assign-meta="1">-</p>
                </div>

                <div class="so-section">
                  <p class="so-section-title">Jornadas de trabajo</p>
                  <p class="so-section-hint">Puedes definir una o varias jornadas en dias distintos para cada tecnico.</p>
                  <div data-so-assign-container="1"></div>
                  <button class="btn so-add-btn" type="button" data-so-assign-add="1">+ Agregar jornada</button>
                  <template data-so-assign-tech-options="1">
                    <option value="">Selecciona tecnico</option>
                    <?php foreach ($technicians as $tOpt): ?>
                      <?php $soQuickTechLabel = trim((string)($tOpt['nombre'] ?? '') . ' ' . (string)($tOpt['apellido'] ?? '')); ?>
                      <option value="<?= h((string)$tOpt['id']) ?>"><?= h($soQuickTechLabel !== '' ? $soQuickTechLabel : ('Tecnico #' . (string)$tOpt['id'])) ?></option>
                    <?php endforeach; ?>
                  </template>
                </div>
              </div>

              <div class="modal-actions">
                <button class="btn" type="button" data-close-so-assign-modal="1">Cancelar</button>
                <button class="btn primary" type="submit">Guardar asignaciones</button>
              </div>
            </form>
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
              <iframe class="quote-preview-frame" title="Previsualizacion de documento" data-quote-preview-frame="1" loading="lazy"></iframe>
              <p class="quote-preview-empty" data-quote-preview-empty="1" style="display:none;">No fue posible cargar la previsualizacion.</p>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($module === 'reportes'): ?>
        <section class="panel">
          <div class="clientes-toolbar">
            <h2 style="margin:0;">Reportes de trabajos tecnicos</h2>
            <div style="display:flex; align-items:center; gap:.55rem; flex-wrap:wrap;">
              <span class="clientes-count">Total: <?= h((string)count($serviceReports)) ?></span>
              <button class="btn primary" type="button" data-open-report-modal="1" <?= empty($serviceOrderOptionsByTechnician) ? 'disabled' : '' ?>>Crear reporte</button>
            </div>
          </div>
          <p class="muted" style="margin:.25rem 0 0;">Los reportes solo pueden registrarse para OS asignadas al tecnico seleccionado.</p>
          <?php if (empty($serviceOrderOptionsByTechnician)): ?>
            <p class="muted" style="margin:.35rem 0 0;">Aun no hay asignaciones tecnico/OS para generar reportes.</p>
          <?php endif; ?>
        </section>

        <?php if (!empty($serviceOrderOptionsByTechnician)): ?>
          <div class="modal-backdrop<?= $openServiceReportModal ? ' open' : '' ?>" id="serviceReportModal" aria-hidden="<?= $openServiceReportModal ? 'false' : 'true' ?>">
            <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="serviceReportModalTitle" style="max-width: 980px;">
              <div class="modal-head">
                <h3 id="serviceReportModalTitle">Nuevo reporte tecnico</h3>
                <button class="modal-close" type="button" data-close-report-modal="1" aria-label="Cerrar">x</button>
              </div>
              <div class="modal-body">
                <form method="post" enctype="multipart/form-data" id="serviceReportFormModal" style="display:grid; gap:.85rem;">
                  <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                  <input type="hidden" name="action" value="<?= h((string)((string)($serviceReportForm['report_id'] ?? '') !== '' ? 'update_service_report' : 'add_service_report')) ?>" data-report-action="1">
                  <input type="hidden" name="report_id" value="<?= h((string)($serviceReportForm['report_id'] ?? '')) ?>" data-report-id="1">
                  <input type="hidden" name="technician_signature_existing" value="<?= h((string)($serviceReportForm['technician_signature_draw'] ?? '')) ?>" data-signature-existing="technician">
                  <input type="hidden" name="customer_signature_existing" value="<?= h((string)($serviceReportForm['customer_signature_draw'] ?? '')) ?>" data-signature-existing="customer">
                  <input type="hidden" name="forms_payload_json" value="<?= h((string)($serviceReportForm['forms_payload_json'] ?? '[]')) ?>" data-report-forms-payload="1">
                  <input type="hidden" name="existing_form_photos_json" value="[]" data-report-existing-form-photos="1">

                  <div class="report-grid">
                    <div class="field">
                      <label>Tecnico asignado</label>
                      <select name="technician_id" required data-report-tech="1">
                        <option value="">Selecciona tecnico</option>
                        <?php foreach ($serviceOrderOptionsByTechnician as $tReport): ?>
                          <?php $techIdValue = (string)((int)$tReport['technician_id']); ?>
                          <?php $techLabel = trim((string)$tReport['technician_name']); ?>
                          <option value="<?= h($techIdValue) ?>" <?= ((string)$serviceReportForm['technician_id'] === $techIdValue ? 'selected' : '') ?>><?= h($techLabel !== '' ? $techLabel : ('Tecnico #' . $techIdValue)) ?></option>
                        <?php endforeach; ?>
                      </select>
                    </div>

                    <div class="field">
                      <label>OS asignada</label>
                      <select name="service_order_id" required data-report-so="1">
                        <option value="">Selecciona OS</option>
                        <?php foreach ($serviceOrderOptionsByTechnician as $tReport): ?>
                          <?php $techIdValue = (string)((int)$tReport['technician_id']); ?>
                          <?php foreach ((array)$tReport['orders'] as $soOpt): ?>
                            <?php $soIdValue = (string)((int)($soOpt['service_order_id'] ?? 0)); ?>
                            <option value="<?= h($soIdValue) ?>" data-tech-id="<?= h($techIdValue) ?>" <?= ((string)$serviceReportForm['service_order_id'] === $soIdValue ? 'selected' : '') ?>>
                              <?= h((string)($soOpt['codigo'] ?? 'OS')) ?> - <?= h((string)($soOpt['titulo'] ?? '')) ?>
                            </option>
                          <?php endforeach; ?>
                        <?php endforeach; ?>
                      </select>
                    </div>

                    <div class="field full">
                      <label>Trabajo realizado</label>
                      <input type="hidden" name="work_done" value="<?= h((string)$serviceReportForm['work_done']) ?>" data-report-hidden="work_done">
                      <div class="report-list-builder" data-report-list-builder="work_done">
                        <div class="report-list-items" data-report-list-items="work_done"></div>
                        <button class="report-list-add-btn" type="button" data-add-report-item="work_done">+ Agregar item</button>
                      </div>
                    </div>

                    <div class="field full">
                      <label>Compras externas</label>
                      <input type="hidden" name="external_purchases" value="<?= h((string)$serviceReportForm['external_purchases']) ?>" data-report-hidden="external_purchases">
                      <div class="report-list-builder" data-report-list-builder="external_purchases">
                        <div class="report-list-items" data-report-list-items="external_purchases"></div>
                        <button class="report-list-add-btn" type="button" data-add-report-item="external_purchases">+ Agregar item</button>
                      </div>
                    </div>

                    <div class="field full">
                      <label>Observaciones</label>
                      <input type="hidden" name="observations" value="<?= h((string)$serviceReportForm['observations']) ?>" data-report-hidden="observations">
                      <div class="report-list-builder" data-report-list-builder="observations">
                        <div class="report-list-items" data-report-list-items="observations"></div>
                        <button class="report-list-add-btn" type="button" data-add-report-item="observations">+ Agregar item</button>
                      </div>
                    </div>

                    <div class="field full">
                      <label>Registro fotografico</label>
                      <div class="report-existing-wrap" data-report-existing-wrap="1" style="display:none;">
                        <small>Fotos actuales del reporte (puedes cambiar nombre o eliminar).</small>
                        <div class="report-existing-grid" data-report-existing-grid="1"></div>
                      </div>
                      <input type="hidden" name="existing_photos_json" value="" data-report-existing-json="1">
                      <input type="file" name="report_photos[]" accept="image/jpeg,image/png,image/webp" multiple data-report-photo-input="1">
                      <small>Previsualizacion inmediata y optimizacion automatica antes de guardar.</small>
                      <small>Recomendado: hasta 3 fotos por envio para evitar limites del servidor.</small>
                      <div class="report-photo-preview" data-report-photo-preview="1"></div>
                    </div>

                    <div class="field full">
                      <label>Adicionales</label>
                      <textarea name="additional_details" rows="3"><?= h((string)$serviceReportForm['additional_details']) ?></textarea>
                    </div>

                    <div class="field full">
                      <label>Modulo de Formularios</label>
                      <?php if ($canAccessHeroeModules): ?>
                        <div data-report-forms-container="1" class="report-dynamic-forms"></div>
                        <textarea name="forms_note" rows="3" placeholder="Nota opcional del bloque de formularios (no crea plantillas)"><?= h((string)$serviceReportForm['forms_note']) ?></textarea>
                        <small>Primero crea la plantilla en el modulo Formularios y asignala a la OS. Aqui solo se responden plantillas ya asignadas.</small>
                      <?php else: ?>
                        <textarea name="forms_note" rows="3" readonly>Disponible solo para plan Heroe o superior.</textarea>
                        <small>Actualiza tu plan para habilitar este modulo.</small>
                      <?php endif; ?>
                    </div>

                    <div class="field">
                      <label>Nombre tecnico firmante</label>
                      <input type="text" name="technician_sign_name" value="<?= h((string)($serviceReportForm['technician_sign_name'] ?? '')) ?>" required>
                    </div>

                    <div class="field">
                      <label>RUT tecnico firmante</label>
                      <input type="text" name="technician_sign_rut" value="<?= h((string)($serviceReportForm['technician_sign_rut'] ?? '')) ?>" required>
                    </div>

                    <div class="field">
                      <label>Nombre cliente que recepciona</label>
                      <input type="text" name="customer_sign_name" value="<?= h((string)($serviceReportForm['customer_sign_name'] ?? '')) ?>" required>
                    </div>

                    <div class="field">
                      <label>RUT cliente que recepciona</label>
                      <input type="text" name="customer_sign_rut" value="<?= h((string)($serviceReportForm['customer_sign_rut'] ?? '')) ?>" required>
                    </div>

                    <div class="field full">
                      <label>Firma digital tecnico</label>
                      <input type="hidden" name="technician_signature_data" value="" data-signature-data="technician">
                      <div class="signature-block">
                        <canvas class="signature-canvas" width="700" height="180" data-signature-canvas="technician" aria-label="Firma digital tecnico"></canvas>
                        <div class="signature-actions">
                          <button type="button" class="danger" data-signature-clear="technician">Limpiar firma tecnico</button>
                        </div>
                        <p class="signature-hint">Dibuja la firma del tecnico con mouse o tactil.</p>
                      </div>
                    </div>

                    <div class="field full">
                      <label>Firma digital cliente que recepciona</label>
                      <input type="hidden" name="customer_signature_data" value="" data-signature-data="customer">
                      <div class="signature-block">
                        <canvas class="signature-canvas" width="700" height="180" data-signature-canvas="customer" aria-label="Firma digital cliente"></canvas>
                        <div class="signature-actions">
                          <button type="button" class="danger" data-signature-clear="customer">Limpiar firma cliente</button>
                        </div>
                        <p class="signature-hint">Dibuja la firma del cliente para registrar recepcion.</p>
                      </div>
                    </div>

                    <div class="field">
                      <label>Fecha del reporte</label>
                      <input type="date" name="report_date" value="<?= h((string)$serviceReportForm['report_date']) ?>" required>
                    </div>
                  </div>

                  <div class="modal-actions">
                    <button class="btn" type="button" data-close-report-modal="1">Cancelar</button>
                    <button class="btn primary" type="submit">Guardar reporte</button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        <?php endif; ?>

        <script type="application/json" id="reportFormsCatalogJson"><?= (string)json_encode($reportFormTemplatesCatalogByServiceOrder, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>

        <section class="panel">
          <h3 style="margin-top:0;">Historial de reportes</h3>
          <?php if (empty($serviceReports)): ?>
            <p class="muted">Aun no hay reportes registrados.</p>
          <?php else: ?>
            <div class="clientes-table-wrap" style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>Fecha</th>
                    <th>OS</th>
                    <th>Tecnico</th>
                    <th>Cliente</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($serviceReports as $reportRow): ?>
                    <?php $photoRows = (array)($reportRow['photo_records'] ?? []); ?>
                    <?php $formPhotoRows = (array)($reportRow['form_photo_records'] ?? []); ?>
                    <?php $techSig = service_report_signature_decode((string)($reportRow['technician_signature'] ?? '')); ?>
                    <?php $custSig = service_report_signature_decode((string)($reportRow['customer_signature'] ?? '')); ?>
                    <?php $techSigDrawUrl = service_report_signature_draw_public_url((string)($reportRow['technician_signature_draw'] ?? '')); ?>
                    <?php $custSigDrawUrl = service_report_signature_draw_public_url((string)($reportRow['customer_signature_draw'] ?? '')); ?>
                    <?php
                      $reportDetailPayload = [
                        'date' => (string)($reportRow['report_date'] ?? ''),
                        'service_order_code' => (string)($reportRow['service_order_code'] ?? ''),
                        'service_order_title' => (string)($reportRow['service_order_title'] ?? ''),
                        'technician_name' => (string)($reportRow['technician_full_name'] ?? ''),
                        'customer_name' => (string)($reportRow['customer_name'] ?? ''),
                        'work_done' => (string)($reportRow['work_done'] ?? ''),
                        'external_purchases' => (string)($reportRow['external_purchases'] ?? ''),
                        'observations' => (string)($reportRow['observations'] ?? ''),
                        'additional_details' => (string)($reportRow['additional_details'] ?? ''),
                        'forms_note' => (string)($reportRow['forms_note'] ?? ''),
                        'forms_payload' => service_form_response_payload_normalize($reportRow['forms_payload'] ?? '[]'),
                        'technician_signature' => service_report_signature_pretty((string)($reportRow['technician_signature'] ?? '')),
                        'customer_signature' => service_report_signature_pretty((string)($reportRow['customer_signature'] ?? '')),
                        'photos' => array_values(array_map(static function ($photoRow) {
                          return [
                            'url' => (string)($photoRow['url'] ?? ''),
                            'label' => (string)($photoRow['display_name'] ?? ($photoRow['name'] ?? 'Foto reporte')),
                          ];
                        }, $photoRows)),
                      ];
                    ?>
                    <tr data-report-detail="<?= h((string)json_encode($reportDetailPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">
                      <td>
                        <?= h((string)$reportRow['report_date']) ?>
                      </td>
                      <td>
                        <strong><?= h((string)($reportRow['service_order_code'] ?? '')) ?></strong><br>
                        <small class="muted"><?= h((string)($reportRow['service_order_title'] ?? '')) ?></small>
                      </td>
                      <td>
                        <?= h((string)($reportRow['technician_full_name'] ?? '')) ?>
                      </td>
                      <td>
                        <?= h((string)($reportRow['customer_name'] ?? '')) ?>
                      </td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn"
                            type="button"
                            title="Ver detalle"
                            aria-label="Ver detalle"
                            data-open-report-detail-btn="1"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 4.5c4.1 0 7.2 2.7 8.4 5.5-1.2 2.8-4.3 5.5-8.4 5.5S2.8 12.8 1.6 10C2.8 7.2 5.9 4.5 10 4.5zm0 2.2a3.3 3.3 0 1 0 0 6.6 3.3 3.3 0 0 0 0-6.6z"/></svg>
                          </button>
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Editar reporte"
                            aria-label="Editar reporte"
                            data-edit-service-report="1"
                            data-report-id="<?= h((string)($reportRow['id'] ?? '')) ?>"
                            data-report-service-order-id="<?= h((string)($reportRow['service_order_id'] ?? '')) ?>"
                            data-report-technician-id="<?= h((string)($reportRow['technician_id'] ?? '')) ?>"
                            data-report-date="<?= h((string)($reportRow['report_date'] ?? '')) ?>"
                            data-report-work-done="<?= h((string)($reportRow['work_done'] ?? '')) ?>"
                            data-report-external-purchases="<?= h((string)($reportRow['external_purchases'] ?? '')) ?>"
                            data-report-observations="<?= h((string)($reportRow['observations'] ?? '')) ?>"
                            data-report-additional-details="<?= h((string)($reportRow['additional_details'] ?? '')) ?>"
                            data-report-forms-note="<?= h((string)($reportRow['forms_note'] ?? '')) ?>"
                            data-report-forms-payload="<?= h((string)json_encode(service_form_response_payload_normalize($reportRow['forms_payload'] ?? '[]'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
                            data-report-technician-sign-name="<?= h((string)($techSig['name'] ?? '')) ?>"
                            data-report-technician-sign-rut="<?= h((string)($techSig['rut'] ?? '')) ?>"
                            data-report-customer-sign-name="<?= h((string)($custSig['name'] ?? '')) ?>"
                            data-report-customer-sign-rut="<?= h((string)($custSig['rut'] ?? '')) ?>"
                            data-report-technician-sign-draw-url="<?= h((string)$techSigDrawUrl) ?>"
                            data-report-technician-sign-draw-path="<?= h((string)($reportRow['technician_signature_draw'] ?? '')) ?>"
                            data-report-customer-sign-draw-url="<?= h((string)$custSigDrawUrl) ?>"
                            data-report-customer-sign-draw-path="<?= h((string)($reportRow['customer_signature_draw'] ?? '')) ?>"
                            data-report-photo-records="<?= h((string)json_encode($photoRows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
                            data-report-form-photo-records="<?= h((string)json_encode($formPhotoRows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M13.5 3.5l3 3M4 16h3l9-9-3-3-9 9v3z"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Mover reporte a papelera"
                            aria-label="Mover reporte a papelera"
                            data-open-delete-confirm="1"
                            data-delete-action="move_service_report_to_trash"
                            data-delete-id-field="report_id"
                            data-delete-id-value="<?= h((string)($reportRow['id'] ?? '')) ?>"
                            data-delete-entity="reporte"
                            data-delete-description="<?= h((string)($reportRow['service_order_code'] ?? '')) ?> - <?= h((string)($reportRow['report_date'] ?? '')) ?>"
                            data-delete-mode="trash"
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

            <div class="modal-backdrop" id="serviceReportDetailModal" aria-hidden="true">
              <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="serviceReportDetailTitle">
                <div class="modal-head">
                  <h3 id="serviceReportDetailTitle">Detalle de reporte</h3>
                  <button class="btn" type="button" data-close-report-detail="1">Cerrar</button>
                </div>
                <div class="modal-body">
                  <div class="report-detail-grid">
                    <div class="detail-block">
                      <p class="detail-label">Fecha</p>
                      <p class="detail-value" data-report-detail-date="1"></p>
                    </div>
                    <div class="detail-block">
                      <p class="detail-label">OS</p>
                      <p class="detail-value" data-report-detail-os="1"></p>
                    </div>
                    <div class="detail-block">
                      <p class="detail-label">Tecnico</p>
                      <p class="detail-value" data-report-detail-technician="1"></p>
                    </div>
                    <div class="detail-block">
                      <p class="detail-label">Cliente</p>
                      <p class="detail-value" data-report-detail-customer="1"></p>
                    </div>
                    <div class="detail-block full">
                      <p class="detail-label">Trabajo realizado</p>
                      <p class="detail-value" data-report-detail-work="1"></p>
                    </div>
                    <div class="detail-block full">
                      <p class="detail-label">Compras externas</p>
                      <p class="detail-value" data-report-detail-purchases="1"></p>
                    </div>
                    <div class="detail-block full">
                      <p class="detail-label">Observaciones</p>
                      <p class="detail-value" data-report-detail-observations="1"></p>
                    </div>
                    <div class="detail-block full">
                      <p class="detail-label">Adicionales y formularios</p>
                      <p class="detail-value" data-report-detail-additional="1"></p>
                    </div>
                    <div class="detail-block full">
                      <p class="detail-label">Registro fotografico</p>
                      <div class="detail-photos" data-report-detail-photos="1"></div>
                    </div>
                    <div class="detail-block">
                      <p class="detail-label">Firma tecnico</p>
                      <p class="detail-value" data-report-detail-sign-tech="1"></p>
                    </div>
                    <div class="detail-block">
                      <p class="detail-label">Firma cliente</p>
                      <p class="detail-value" data-report-detail-sign-customer="1"></p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          <?php endif; ?>
        </section>
      <?php endif; ?>

      <?php if ($module === 'formularios'): ?>
        <section class="panel">
          <div class="clientes-toolbar">
            <h2 style="margin:0;">Plantillas de formularios</h2>
            <div style="display:flex; align-items:center; gap:.55rem; flex-wrap:wrap;">
              <span class="clientes-count">Plantillas activas: <?= h((string)count($formTemplates)) ?></span>
              <button class="btn primary" type="button" data-open-form-template-builder="1">Crear formulario</button>
            </div>
          </div>
          <p class="muted" style="margin:.25rem 0 0;">Crea plantillas reutilizables y asignalas a ordenes de servicio.</p>
        </section>

        <div class="modal-backdrop" id="formTemplateModal" aria-hidden="true">
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="formTemplateModalTitle" style="max-width: 1020px;">
            <div class="modal-head">
              <h3 id="formTemplateModalTitle">Crear formulario</h3>
              <button class="modal-close" type="button" data-close-form-template-modal="1" aria-label="Cerrar">x</button>
            </div>
            <form method="post" id="formTemplateBuilderForm" style="display:grid; gap:.85rem;">
              <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
              <input type="hidden" name="action" value="save_form_template">
              <input type="hidden" name="form_template_id" value="">
              <input type="hidden" name="template_fields" value="[]" data-template-fields-json="1">
              <div class="modal-body" style="display:grid; gap:.85rem;">
                <div class="report-grid" style="grid-template-columns: repeat(2,minmax(0,1fr));">
                  <div class="field">
                    <label>Nombre de plantilla</label>
                    <input type="text" name="template_name" required maxlength="190" placeholder="Ej: Check List Mantenimiento Preventivo">
                  </div>
                  <div class="field">
                    <label>Descripcion</label>
                    <input type="text" name="template_description" maxlength="255" placeholder="Uso sugerido de la plantilla">
                  </div>
                </div>
                <div class="field full">
                  <label>Campos de la plantilla</label>
                  <div data-template-fields-container="1"></div>
                  <button class="btn so-add-btn" type="button" data-template-add-field="1">+ Agregar campo</button>
                  <small>Tipos disponibles: Texto + check, Semaforo, Texto corto, Texto largo, Imagenes.</small>
                </div>
              </div>
              <div class="modal-actions">
                <button class="btn" type="button" data-close-form-template-modal="1">Cancelar</button>
                <button class="btn primary" type="submit">Guardar plantilla</button>
              </div>
            </form>
          </div>
        </div>

        <section class="panel">
          <h3 style="margin-top:0;">Plantillas activas</h3>
          <?php if (empty($formTemplates)): ?>
            <p class="muted">No hay plantillas creadas todavia.</p>
          <?php else: ?>
            <div class="clientes-table-wrap" style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>Plantilla</th>
                    <th>Campos</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($formTemplates as $tplRow): ?>
                    <?php $tplFields = service_form_template_fields_normalize($tplRow['fields'] ?? []); ?>
                    <tr>
                      <td>
                        <strong><?= h((string)($tplRow['name'] ?? '')) ?></strong><br>
                        <small class="muted"><?= h((string)($tplRow['description'] ?? '')) ?></small>
                      </td>
                      <td>
                        <?php if (empty($tplFields)): ?>
                          <small class="muted">Sin campos.</small>
                        <?php else: ?>
                          <div style="display:flex; flex-wrap:wrap; gap:.35rem;">
                            <?php foreach ($tplFields as $fRow): ?>
                              <span class="badge"><?= h((string)($fRow['label'] ?? '')) ?> (<?= h((string)($fRow['type'] ?? 'texto_corto')) ?>)</span>
                            <?php endforeach; ?>
                          </div>
                        <?php endif; ?>
                      </td>
                      <td>
                        <form method="post" onsubmit="return confirm('Desactivar plantilla?');">
                          <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                          <input type="hidden" name="action" value="delete_form_template">
                          <input type="hidden" name="form_template_id" value="<?= h((string)($tplRow['id'] ?? '0')) ?>">
                          <button class="btn danger" type="submit">Desactivar</button>
                        </form>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php endif; ?>
        </section>

        <section class="panel">
          <h3 style="margin-top:0;">Historial de formularios en reportes</h3>
          <?php
            $reportsWithForms = [];
            foreach ((array)$serviceReports as $srTmp) {
              $hasPayload = !empty(service_form_response_payload_normalize($srTmp['forms_payload'] ?? '[]'));
              if (!$hasPayload) {
                continue;
              }
              $reportsWithForms[] = $srTmp;
            }
          ?>
          <?php if (empty($reportsWithForms)): ?>
            <p class="muted">Aun no hay formularios registrados. Puedes agregarlos desde el modulo Reportes.</p>
          <?php else: ?>
            <div class="clientes-table-wrap" style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>Fecha</th>
                    <th>OS</th>
                    <th>Tecnico</th>
                    <th>Cliente</th>
                    <th>Formulario</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($reportsWithForms as $fRow): ?>
                    <?php $payloadFormsRow = service_form_response_payload_normalize($fRow['forms_payload'] ?? '[]'); ?>
                    <tr>
                      <td><?= h((string)($fRow['report_date'] ?? '')) ?></td>
                      <td>
                        <strong><?= h((string)($fRow['service_order_code'] ?? '')) ?></strong><br>
                        <small class="muted"><?= h((string)($fRow['service_order_title'] ?? '')) ?></small>
                      </td>
                      <td><?= h((string)($fRow['technician_full_name'] ?? '')) ?></td>
                      <td><?= h((string)($fRow['customer_name'] ?? '')) ?></td>
                      <td style="white-space:pre-wrap;"><?php
                        $summaryParts = [];
                        if (!empty($payloadFormsRow)) {
                          $summaryParts[] = 'Plantillas respondidas: ' . count($payloadFormsRow);
                        }
                        echo h(implode("\n", $summaryParts));
                      ?></td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php endif; ?>
        </section>
      <?php endif; ?>

      <?php if ($module === 'tecnicos'): ?>
        <?php $isTechnicianEdit = (int)($technicianForm['id'] ?? 0) > 0; ?>
        <section class="panel">
          <div class="clientes-toolbar">
            <h2 style="margin:0;">Tecnicos</h2>
            <div style="display:flex; gap:.5rem; align-items:center;">
              <span class="clientes-count">Total: <?= h((string)count($technicians)) ?></span>
              <button class="btn primary" type="button" data-open-technician-modal="1">Agregar tecnico</button>
            </div>
          </div>
          <p class="muted" style="margin:0;">Administra tecnicos activos/inactivos para la operacion del plan Heroe.</p>
        </section>

        <section class="panel">
          <h3>Listado de tecnicos</h3>
          <?php if (empty($technicians)): ?>
            <p class="muted">Aun no tienes tecnicos registrados.</p>
          <?php else: ?>
            <div class="clientes-table-wrap" style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>Nombre</th>
                    <th>Apellido</th>
                    <th>Cargo</th>
                    <th>Cuenta</th>
                    <th>Fecha de ingreso</th>
                    <th>Estado</th>
                    <th>Acciones</th>
                    <th>Gestion</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($technicians as $tech): ?>
                    <?php $techFullName = trim((string)$tech['nombre'] . ' ' . (string)$tech['apellido']); ?>
                    <?php $techAssetCounts = technician_assets_counts((array)($tech['asset_records'] ?? [])); ?>
                    <tr>
                      <td><?= h((string)$tech['nombre']) ?></td>
                      <td><?= h((string)$tech['apellido']) ?></td>
                      <td><?= h((string)$tech['cargo']) ?></td>
                      <td><?= h((string)($tech['cuenta'] ?? '')) ?></td>
                      <td><?= h((string)($tech['fecha_ingreso'] ?? '')) ?></td>
                      <td>
                        <span class="status <?= ((string)$tech['estado'] === 'activo' ? 'ok' : 'warn') ?>">
                          <?= h((string)$tech['estado']) ?>
                        </span>
                      </td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Editar tecnico"
                            aria-label="Editar tecnico"
                            data-edit-technician="1"
                            data-tech-id="<?= h((string)$tech['id']) ?>"
                            data-tech-nombre="<?= h((string)$tech['nombre']) ?>"
                            data-tech-apellido="<?= h((string)$tech['apellido']) ?>"
                            data-tech-cargo="<?= h((string)$tech['cargo']) ?>"
                            data-tech-cuenta="<?= h((string)($tech['cuenta'] ?? '')) ?>"
                            data-tech-fecha-ingreso="<?= h((string)($tech['fecha_ingreso'] ?? '')) ?>"
                            data-tech-estado="<?= h((string)$tech['estado']) ?>"
                            data-tech-habilidades="<?= h((string)json_encode((array)($tech['habilidades'] ?? []), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M13.5 3.5l3 3M4 16h3l9-9-3-3-9 9v3z"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Eliminar tecnico"
                            aria-label="Eliminar tecnico"
                            data-open-delete-confirm="1"
                            data-delete-action="delete_technician"
                            data-delete-id-field="technician_id"
                            data-delete-id-value="<?= h((string)$tech['id']) ?>"
                            data-delete-entity="tecnico"
                            data-delete-description="<?= h($techFullName) ?>"
                            data-delete-mode="purge"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3.5 5.5h13M8 5.5V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M6 5.5l.7 10.5h6.6L14 5.5M8.7 8v5.5M11.3 8v5.5"/></svg>
                          </button>
                        </div>
                      </td>
                      <td>
                        <div class="tech-gestion-actions">
                          <button
                            class="icon-btn"
                            type="button"
                            title="Gestion EPP"
                            aria-label="Gestion EPP"
                            data-open-tech-asset="1"
                            data-asset-type="epp"
                            data-tech-id="<?= h((string)$tech['id']) ?>"
                            data-tech-name="<?= h($techFullName) ?>"
                            data-tech-assets="<?= h((string)json_encode((array)($tech['asset_records'] ?? []), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 2l6 2.4v4.5c0 4.1-2.4 6.8-6 8.9-3.6-2.1-6-4.8-6-8.9V4.4L10 2zM7.4 10.1l1.7 1.7 3.5-3.5"/></svg>
                            <span class="tech-gestion-count"><?= h((string)$techAssetCounts['epp']) ?></span>
                          </button>
                          <button
                            class="icon-btn"
                            type="button"
                            title="Gestion Cargo"
                            aria-label="Gestion Cargo"
                            data-open-tech-asset="1"
                            data-asset-type="cargo"
                            data-tech-id="<?= h((string)$tech['id']) ?>"
                            data-tech-name="<?= h($techFullName) ?>"
                            data-tech-assets="<?= h((string)json_encode((array)($tech['asset_records'] ?? []), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 4.2a2 2 0 1 0-2-2m2 2l6 4.2-2.1 2.2-2.1-1.3V17H8.2V9.3L6.1 10.6 4 8.4 10 4.2z"/></svg>
                            <span class="tech-gestion-count"><?= h((string)$techAssetCounts['cargo']) ?></span>
                          </button>
                          <button
                            class="icon-btn"
                            type="button"
                            title="Gestion Herramientas"
                            aria-label="Gestion Herramientas"
                            data-open-tech-asset="1"
                            data-asset-type="herramientas"
                            data-tech-id="<?= h((string)$tech['id']) ?>"
                            data-tech-name="<?= h($techFullName) ?>"
                            data-tech-assets="<?= h((string)json_encode((array)($tech['asset_records'] ?? []), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M12.6 3.8a3.4 3.4 0 0 0 3.6 4.8L9 15.8a1.7 1.7 0 1 1-2.4-2.4l7.2-7.2a3.4 3.4 0 0 0-1.2-2.4z"/></svg>
                            <span class="tech-gestion-count"><?= h((string)$techAssetCounts['herramientas']) ?></span>
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

        <div class="modal-backdrop<?= $openTechnicianModal ? ' open' : '' ?>" id="technicianModal" aria-hidden="<?= $openTechnicianModal ? 'false' : 'true' ?>">
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="technicianModalTitle">
            <div class="modal-head">
              <h3 id="technicianModalTitle"><?= $isTechnicianEdit ? 'Editar tecnico' : 'Agregar tecnico' ?></h3>
              <button class="btn" type="button" data-close-technician-modal="1">Cerrar</button>
            </div>
            <div class="modal-body">
              <form method="post" id="technicianModalForm">
                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                <input type="hidden" name="action" value="<?= $isTechnicianEdit ? 'update_technician' : 'add_technician' ?>" data-technician-action="1">
                <input type="hidden" name="technician_id" value="<?= h((string)($technicianForm['id'] ?? '')) ?>" data-technician-id="1">
                <div class="clientes-form-grid">
                  <div class="field"><label>Nombre</label><input type="text" name="nombre" value="<?= h((string)$technicianForm['nombre']) ?>" required></div>
                  <div class="field"><label>Apellido</label><input type="text" name="apellido" value="<?= h((string)$technicianForm['apellido']) ?>" required></div>
                  <div class="field"><label>Cargo</label><input type="text" name="cargo" value="<?= h((string)$technicianForm['cargo']) ?>" required></div>
                  <div class="field"><label>Cuenta (opcional)</label><input type="text" name="cuenta" value="<?= h((string)$technicianForm['cuenta']) ?>"></div>
                  <div class="field"><label>Fecha de ingreso</label><input type="date" name="fecha_ingreso" value="<?= h((string)$technicianForm['fecha_ingreso']) ?>" required></div>
                  <div class="field">
                    <label>Estado</label>
                    <select name="estado" required>
                      <option value="activo" <?= ((string)$technicianForm['estado'] === 'activo' ? 'selected' : '') ?>>activo</option>
                      <option value="inactivo" <?= ((string)$technicianForm['estado'] === 'inactivo' ? 'selected' : '') ?>>inactivo</option>
                    </select>
                  </div>
                  <div class="field full">
                    <label>Habilidades tecnicas</label>
                    <div class="tech-skills-grid">
                      <?php foreach ($technicianSkillCatalog as $skillLabel): ?>
                        <?php $skillChecked = in_array($skillLabel, (array)($technicianForm['habilidades'] ?? []), true); ?>
                        <label class="tech-skill-option">
                          <input type="checkbox" name="habilidades[]" value="<?= h($skillLabel) ?>" <?= $skillChecked ? 'checked' : '' ?>>
                          <span><?= h($skillLabel) ?></span>
                        </label>
                      <?php endforeach; ?>
                    </div>
                    <div class="tech-skills-picked" data-tech-skills-picked="1">
                      <?php foreach ((array)($technicianForm['habilidades'] ?? []) as $pickedSkill): ?>
                        <span class="tech-skill-chip"><?= h((string)$pickedSkill) ?></span>
                      <?php endforeach; ?>
                    </div>
                    <p class="muted" style="margin:.45rem 0 0;">Puedes seleccionar multiples habilidades por tecnico.</p>
                  </div>
                </div>
                <div class="modal-actions">
                  <button class="btn" type="button" data-close-technician-modal="1">Cancelar</button>
                  <button class="btn primary" type="submit" data-technician-submit-label="1"><?= $isTechnicianEdit ? 'Actualizar tecnico' : 'Guardar tecnico' ?></button>
                </div>
              </form>
            </div>
          </div>
        </div>

        <?php
          $assetTypeCurrent = technician_asset_type_normalize((string)($technicianAssetForm['asset_type'] ?? 'epp'));
          $assetListCurrent = (array)($technicianAssetRecords[$assetTypeCurrent] ?? []);
        ?>
        <div
          class="modal-backdrop<?= $openTechnicianAssetModal ? ' open' : '' ?>"
          id="techAssetModal"
          aria-hidden="<?= $openTechnicianAssetModal ? 'false' : 'true' ?>"
          data-tech-asset-records="<?= h((string)json_encode((array)$technicianAssetRecords, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
        >
          <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="techAssetModalTitle">
            <div class="modal-head">
              <h3 id="techAssetModalTitle">Gestion tecnico</h3>
              <button class="btn" type="button" data-close-tech-asset-modal="1">Cerrar</button>
            </div>
            <div class="modal-body">
              <form method="post" id="techAssetModalForm">
                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                <input type="hidden" name="action" value="add_technician_asset" data-tech-asset-action="1">
                <input type="hidden" name="technician_id" value="<?= h((string)($technicianAssetForm['technician_id'] ?? '')) ?>" data-tech-asset-tech-id="1">
                <input type="hidden" name="asset_type" value="<?= h($assetTypeCurrent) ?>" data-tech-asset-type="1">
                <input type="hidden" name="asset_id" value="" data-tech-asset-id="1">

                <div class="tech-asset-header">
                  <span class="tech-asset-tech">Tecnico: <strong data-tech-asset-tech-name="1"><?= h((string)($technicianAssetForm['technician_nombre'] ?? '')) ?></strong></span>
                  <div class="tech-asset-switches">
                    <button class="btn" type="button" data-tech-asset-switch="epp">EPP</button>
                    <button class="btn" type="button" data-tech-asset-switch="cargo">Cargo</button>
                    <button class="btn" type="button" data-tech-asset-switch="herramientas">Herramientas</button>
                  </div>
                </div>

                <div class="clientes-form-grid" style="margin-top:.6rem;">
                  <div class="field full">
                    <label data-tech-asset-desc-label="1">Elemento</label>
                    <input type="text" name="descripcion" value="<?= h((string)($technicianAssetForm['descripcion'] ?? '')) ?>" data-tech-asset-desc="1" required>
                  </div>
                  <div class="field">
                    <label>Fecha de entrega</label>
                    <input type="date" name="fecha_entrega" value="<?= h((string)($technicianAssetForm['fecha_entrega'] ?? date('Y-m-d'))) ?>" required>
                  </div>
                  <div class="field" data-tech-asset-vencimiento-wrap="1" style="<?= $assetTypeCurrent === 'epp' ? '' : 'display:none;' ?>">
                    <label>Fecha de vencimiento</label>
                    <input type="date" name="fecha_vencimiento" value="<?= h((string)($technicianAssetForm['fecha_vencimiento'] ?? '')) ?>" data-tech-asset-vencimiento="1">
                  </div>
                  <div class="field" data-tech-asset-estado-wrap="1" style="<?= $assetTypeCurrent === 'epp' ? 'display:none;' : '' ?>">
                    <label>Estado de entrega</label>
                    <select name="estado" data-tech-asset-estado="1">
                      <option value="nuevo" <?= ((string)($technicianAssetForm['estado'] ?? 'nuevo') === 'nuevo') ? 'selected' : '' ?>>nuevo</option>
                      <option value="usado" <?= ((string)($technicianAssetForm['estado'] ?? 'nuevo') === 'usado') ? 'selected' : '' ?>>usado</option>
                    </select>
                  </div>
                </div>

                <div class="tech-asset-records" data-tech-asset-records-list="1">
                  <?php if (empty($assetListCurrent)): ?>
                    <p class="muted">Aun no hay registros en esta categoria.</p>
                  <?php else: ?>
                    <table class="tech-asset-table">
                      <thead>
                        <tr>
                          <th>Descripcion</th>
                          <th>Entrega</th>
                          <?php if ($assetTypeCurrent === 'epp'): ?>
                            <th>Vencimiento</th>
                          <?php else: ?>
                            <th>Estado</th>
                          <?php endif; ?>
                          <th>Acciones</th>
                        </tr>
                      </thead>
                      <tbody>
                        <?php foreach ($assetListCurrent as $assetRow): ?>
                          <tr>
                            <td><?= h((string)($assetRow['descripcion'] ?? '')) ?></td>
                            <td><?= h((string)($assetRow['fecha_entrega'] ?? '')) ?></td>
                            <?php if ($assetTypeCurrent === 'epp'): ?>
                              <td><?= h((string)($assetRow['fecha_vencimiento'] ?? '')) ?></td>
                            <?php else: ?>
                              <td><?= h((string)($assetRow['estado'] ?? '')) ?></td>
                            <?php endif; ?>
                            <td>
                              <div class="action-icons">
                                <button
                                  class="icon-btn edit"
                                  type="button"
                                  title="Editar registro"
                                  aria-label="Editar registro"
                                  data-tech-asset-edit="1"
                                  data-asset-id="<?= h((string)($assetRow['id'] ?? '')) ?>"
                                  data-asset-type="<?= h($assetTypeCurrent) ?>"
                                  data-asset-descripcion="<?= h((string)($assetRow['descripcion'] ?? '')) ?>"
                                  data-asset-fecha-entrega="<?= h((string)($assetRow['fecha_entrega'] ?? '')) ?>"
                                  data-asset-fecha-vencimiento="<?= h((string)($assetRow['fecha_vencimiento'] ?? '')) ?>"
                                  data-asset-estado="<?= h((string)($assetRow['estado'] ?? 'nuevo')) ?>"
                                >
                                  <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M13.5 3.5l3 3M4 16h3l9-9-3-3-9 9v3z"/></svg>
                                </button>
                                <button
                                  class="icon-btn danger"
                                  type="button"
                                  title="Eliminar registro"
                                  aria-label="Eliminar registro"
                                  data-tech-asset-delete="1"
                                  data-asset-id="<?= h((string)($assetRow['id'] ?? '')) ?>"
                                  data-asset-type="<?= h($assetTypeCurrent) ?>"
                                >
                                  <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3.5 5.5h13M8 5.5V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M6 5.5l.7 10.5h6.6L14 5.5M8.7 8v5.5M11.3 8v5.5"/></svg>
                                </button>
                              </div>
                            </td>
                          </tr>
                        <?php endforeach; ?>
                      </tbody>
                    </table>
                  <?php endif; ?>
                </div>

                <div class="modal-actions">
                  <button class="btn" type="button" data-tech-asset-cancel-edit="1" style="display:none;">Cancelar edicion</button>
                  <button class="btn" type="button" data-close-tech-asset-modal="1">Cancelar</button>
                  <button class="btn primary" type="submit" data-tech-asset-submit-label="1">Guardar registro</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($module === 'carta-gantt'): ?>
        <?php
          $ganttTechnicians = [];
          foreach ((array)$technicians as $gtRow) {
            $gtId = (int)($gtRow['id'] ?? 0);
            if ($gtId <= 0) {
              continue;
            }
            $ganttTechnicians[] = [
              'id' => $gtId,
              'name' => trim((string)($gtRow['nombre'] ?? '') . ' ' . (string)($gtRow['apellido'] ?? '')),
            ];
          }

          $ganttOrders = [];
          foreach ((array)$serviceOrders as $soRow) {
            $soId = (int)($soRow['id'] ?? 0);
            if ($soId <= 0) {
              continue;
            }
            $soAssignments = [];
            foreach ((array)($serviceOrderAssignmentsByOrder[$soId] ?? []) as $asgRow) {
              $asgTechId = (int)($asgRow['technician_id'] ?? 0);
              $asgDate = trim((string)($asgRow['work_date'] ?? ''));
              if ($asgTechId <= 0 || $asgDate === '') {
                continue;
              }
              $soAssignments[] = [
                'technician_id' => $asgTechId,
                'work_date' => $asgDate,
              ];
            }

            $ganttOrders[] = [
              'id' => $soId,
              'codigo' => (string)($soRow['codigo'] ?? ''),
              'titulo' => (string)($soRow['titulo'] ?? ''),
              'estado' => (string)($soRow['estado'] ?? ''),
              'prioridad' => (string)($soRow['prioridad'] ?? 'normal'),
              'customer_name' => (string)($soRow['customer_name'] ?? ''),
              'observaciones' => (string)($soRow['observaciones'] ?? ''),
              'assignments' => $soAssignments,
              'view_url' => '/empresa/dashboard/?module=ordenes-servicio&view_service_order_id=' . $soId,
              'module_url' => '/empresa/dashboard/?module=ordenes-servicio',
            ];
          }
        ?>
        <style>
          .gantt-shell { display:flex; flex-direction:column; gap:.8rem; }
          .gantt-top-row { display:flex; flex-wrap:wrap; gap:.65rem; align-items:center; justify-content:space-between; }
          .gantt-view-switch, .gantt-nav, .gantt-quick { display:flex; gap:.4rem; flex-wrap:wrap; }
          .gantt-chip { border:1px solid #d7deee; border-radius:999px; background:#fff; color:#1a2647; padding:.35rem .68rem; font-size:.78rem; cursor:pointer; }
          .gantt-chip.active { background:#0f172a; border-color:#0f172a; color:#fff; }
          .gantt-focus-label { font-weight:700; color:#20315a; }
          .gantt-kpis { display:grid; grid-template-columns:repeat(5, minmax(110px, 1fr)); gap:.55rem; }
          .gantt-kpis article { border:1px solid #e3e8f6; border-radius:10px; background:#f8faff; padding:.5rem .55rem; }
          .gantt-kpis strong { display:block; font-size:1.02rem; color:#111e43; }
          .gantt-kpis span { color:#546587; font-size:.76rem; }
          .gantt-filters { display:grid; grid-template-columns:2fr 1fr 1fr; gap:.55rem; }
          .gantt-filters input, .gantt-filters select { width:100%; }
          .gantt-board { overflow:auto; border:1px solid #dfe5f3; border-radius:12px; }
          .gantt-head, .gantt-row { display:grid; grid-template-columns:220px 1fr; min-width:980px; }
          .gantt-head-tech { padding:.5rem .65rem; border-right:1px solid #dfe5f3; background:#eef3ff; font-weight:700; color:#243764; }
          .gantt-head-days { display:grid; background:#f5f8ff; border-bottom:1px solid #dfe5f3; }
          .gantt-day-head { text-align:center; padding:.42rem .2rem; border-right:1px solid #e5eaf8; }
          .gantt-day-head strong { display:block; font-size:.75rem; color:#273a66; }
          .gantt-day-head span { font-size:.68rem; color:#6b7c9f; }
          .gantt-tech { border-right:1px solid #e2e8f7; border-top:1px solid #edf1fa; padding:.54rem .62rem; background:#f9fbff; }
          .gantt-tech strong { display:block; color:#1d315b; font-size:.82rem; }
          .gantt-tech span { color:#5e7196; font-size:.72rem; }
          .gantt-track { position:relative; display:grid; border-top:1px solid #edf1fa; min-height:38px; }
          .gantt-cell { border-right:1px solid #edf2fb; }
          .gantt-bar { border:0; border-radius:8px; margin:4px 3px; cursor:pointer; color:#fff; text-align:left; font-size:.72rem; padding:.24rem .45rem; overflow:hidden; white-space:nowrap; text-overflow:ellipsis; }
          .gantt-bar.borrador { background:#475569; }
          .gantt-bar.planificada { background:#2563eb; }
          .gantt-bar.en-proceso { background:#f97316; }
          .gantt-bar.completada, .gantt-bar.cerrada { background:#16a34a; }
          .gantt-bar.default { background:#334155; }
          .gantt-detail { border:1px solid #dfe6f5; border-radius:11px; background:#f8fbff; padding:.7rem .8rem; }
          .gantt-detail h4 { margin:.1rem 0 .3rem; color:#13244a; }
          .gantt-detail .muted { margin:.2rem 0; }
          .gantt-detail-actions { display:flex; flex-wrap:wrap; gap:.45rem; margin-top:.5rem; }
          .gantt-empty { border:1px dashed #cfd8ea; border-radius:10px; padding:.8rem; color:#56688e; background:#fbfcff; }
          @media (max-width: 980px) {
            .gantt-kpis { grid-template-columns:repeat(2, minmax(130px, 1fr)); }
            .gantt-filters { grid-template-columns:1fr; }
          }
        </style>
        <section class="panel compact">
          <div class="gantt-shell" data-gantt-root="1">
            <h2 style="margin-top:0;">Carta Gantt</h2>
            <p class="muted" style="margin-top:.1rem;">Vista de planificacion por tecnico con navegacion temporal, filtros y acceso directo a cada OS.</p>

            <div class="gantt-top-row">
              <div class="gantt-view-switch" data-gantt-view-switch="1">
                <button class="gantt-chip" type="button" data-gantt-view="day">Diaria</button>
                <button class="gantt-chip active" type="button" data-gantt-view="week">Semanal</button>
                <button class="gantt-chip" type="button" data-gantt-view="month">Mensual</button>
              </div>
              <div class="gantt-nav">
                <button class="gantt-chip" type="button" data-gantt-nav="prev">Anterior</button>
                <button class="gantt-chip" type="button" data-gantt-nav="today">Hoy</button>
                <button class="gantt-chip" type="button" data-gantt-nav="next">Siguiente</button>
              </div>
            </div>

            <div class="gantt-focus-label" data-gantt-focus-label="1"></div>

            <div class="gantt-kpis" data-gantt-kpis="1"></div>

            <div class="gantt-quick" data-gantt-quick="1">
              <button class="gantt-chip active" type="button" data-gantt-quick-preset="all">Todo</button>
              <button class="gantt-chip" type="button" data-gantt-quick-preset="today">Hoy</button>
              <button class="gantt-chip" type="button" data-gantt-quick-preset="overdue">Atrasadas</button>
              <button class="gantt-chip" type="button" data-gantt-quick-preset="unassigned">Sin tecnico</button>
              <button class="gantt-chip" type="button" data-gantt-quick-preset="nodate">Sin fecha</button>
            </div>

            <div class="gantt-filters">
              <input type="search" placeholder="Buscar OS, cliente o titulo" data-gantt-filter="search">
              <select data-gantt-filter="state">
                <option value="todos">Todos los estados</option>
                <option value="borrador">Borrador</option>
                <option value="planificada">Planificada</option>
                <option value="en-proceso">En proceso</option>
                <option value="completada">Completada</option>
                <option value="cerrada">Cerrada</option>
              </select>
              <select data-gantt-filter="technician">
                <option value="todos">Todos los tecnicos</option>
                <option value="sin-asignar">Sin asignar</option>
              </select>
            </div>

            <div class="gantt-board" data-gantt-board="1"></div>

            <div class="gantt-detail" data-gantt-detail="1" hidden>
              <h4 data-gantt-detail-title="1"></h4>
              <p class="muted" data-gantt-detail-meta="1"></p>
              <p class="muted" data-gantt-detail-note="1"></p>
              <div class="gantt-detail-actions">
                <button class="btn" type="button" data-gantt-detail-view="1">Ver OS en panel</button>
                <button class="btn" type="button" data-gantt-detail-assign="1">Asignar tecnico (rapido)</button>
                <a class="btn" href="#" target="_blank" rel="noopener" data-gantt-detail-view-new="1">Ver OS (nueva pestaña)</a>
                <a class="btn" href="/empresa/dashboard/?module=ordenes-servicio">Abrir modulo OS</a>
              </div>
            </div>
          </div>
        </section>
        <script type="application/json" id="ganttOrdersJson"><?= json_encode($ganttOrders, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
        <script type="application/json" id="ganttTechniciansJson"><?= json_encode($ganttTechnicians, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
      <?php endif; ?>

      <?php if ($module === 'empresa'): ?>
        <section class="panel compact">
          <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
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
                            title="Mover cliente a papelera"
                            aria-label="Mover cliente a papelera"
                            data-open-delete-confirm="1"
                            data-delete-action="move_customer_to_trash"
                            data-delete-id-field="customer_id"
                            data-delete-id-value="<?= h((string)$customer['id']) ?>"
                            data-delete-entity="cliente"
                            data-delete-description="<?= h((string)$customer['razon_social']) ?>"
                            data-delete-mode="trash"
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
                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
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
                        'validez_override' => (string)($quote['validez_override'] ?? ''),
                        'entrega_override' => (string)($quote['entrega_override'] ?? ''),
                        'condicion_de_pago_override' => (string)($quote['condicion_de_pago_override'] ?? ''),
                        'moneda_override' => (string)($quote['moneda_override'] ?? ''),
                        'terminos_condiciones_adicionales' => (string)$quote['terminos_condiciones_adicionales'],
                        'observaciones' => (string)$quote['observaciones'],
                        'items' => array_map(static function ($item) {
                          return [
                            'descripcion' => (string)$item['descripcion'],
                            'cantidad' => (string)$item['cantidad'],
                            'precio' => (string)$item['precio_unitario'],
                            'tipo' => (string)($item['item_type'] ?? 'normal'),
                            'negrita' => ((int)($item['is_bold'] ?? 0) === 1) ? '1' : '0',
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
                          <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
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
                            class="icon-btn email"
                            type="button"
                            title="Enviar por correo"
                            aria-label="Enviar por correo"
                            data-open-quote-email="1"
                            data-quote-id="<?= h((string)$quote['id']) ?>"
                            data-quote-number="<?= h((string)$quote['numero_cotizacion']) ?>"
                            data-customer-name="<?= h((string)$quote['customer_name']) ?>"
                            data-customer-contact="<?= h((string)($quote['customer_contact'] ?? '')) ?>"
                            data-customer-email="<?= h((string)($quote['customer_email'] ?? '')) ?>"
                            data-print-url="/empresa/dashboard/?module=cotizaciones&amp;view_quote_id=<?= h((string)$quote['id']) ?>"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5.5h14v9H3zM3 6l7 5 7-5"/></svg>
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
                            title="Mover cotizacion a papelera"
                            aria-label="Mover cotizacion a papelera"
                            data-open-delete-confirm="1"
                            data-delete-action="move_quote_to_trash"
                            data-delete-id-field="quote_id"
                            data-delete-id-value="<?= h((string)$quote['id']) ?>"
                            data-delete-entity="cotizacion"
                            data-delete-description="<?= h((string)$quote['numero_cotizacion']) ?>"
                            data-delete-mode="trash"
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
                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
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
                        <th style="width:44%;">Descripcion</th>
                        <th style="width:12%;">Cantidad</th>
                        <th style="width:15%;">Precio unitario</th>
                        <th style="width:13%;">Total linea</th>
                        <th style="width:10%;">Formato</th>
                        <th style="width:6%;">Accion</th>
                      </tr>
                    </thead>
                    <tbody data-quote-items-body="1">
                      <?php foreach ($quoteForm['items'] as $item): ?>
                        <?php
                          $itemType = strtolower(trim((string)($item['tipo'] ?? 'normal')));
                          if (!in_array($itemType, ['normal', 'text'], true)) {
                            $itemType = 'normal';
                          }
                          $itemIsBold = ((string)($item['negrita'] ?? '0') === '1');
                          $itemQty = (float)str_replace(',', '.', (string)($item['cantidad'] ?? 0));
                          $itemPrice = (float)str_replace(',', '.', (string)($item['precio'] ?? 0));
                          $itemTotal = ($itemType === 'text') ? 0 : (($itemQty > 0 ? ($itemQty * $itemPrice) : 0));
                        ?>
                        <tr data-item-row="1" data-item-type="<?= h($itemType) ?>" data-item-bold="<?= $itemIsBold ? '1' : '0' ?>">
                          <td>
                            <input type="text" name="item_descripcion[]" value="<?= h($item['descripcion']) ?>" data-item-descripcion="1" required>
                            <input type="hidden" name="item_tipo[]" value="<?= h($itemType) ?>" data-item-type-input="1">
                            <input type="hidden" name="item_negrita[]" value="<?= $itemIsBold ? '1' : '0' ?>" data-item-bold-input="1">
                          </td>
                          <td>
                            <input type="number" name="item_cantidad[]" value="<?= h((string)$item['cantidad']) ?>" min="0.01" step="0.01" data-item-cantidad="1" <?= $itemType === 'text' ? 'readonly' : '' ?> required>
                            <span class="item-dash" data-item-dash="qty" <?= $itemType === 'text' ? '' : 'style="display:none;"' ?>>-</span>
                          </td>
                          <td>
                            <input type="number" name="item_precio[]" value="<?= h((string)$item['precio']) ?>" min="0" step="0.01" data-item-precio="1" <?= $itemType === 'text' ? 'readonly' : '' ?> required>
                            <span class="item-dash" data-item-dash="price" <?= $itemType === 'text' ? '' : 'style="display:none;"' ?>>-</span>
                          </td>
                          <td>
                            <span class="line-total" data-line-total="1"><?= $itemType === 'text' ? '-' : ('$' . h(money_clp($itemTotal))) ?></span>
                          </td>
                          <td>
                            <div class="item-style-tools">
                              <button class="btn item-style-btn<?= $itemIsBold ? ' active' : '' ?>" type="button" data-item-bold-toggle="1" title="Negrita">N</button>
                              <button class="btn item-style-btn<?= $itemType === 'text' ? ' active' : '' ?>" type="button" data-item-type-toggle="1" title="Texto sin precio">T</button>
                            </div>
                          </td>
                          <td><button class="btn danger" type="button" data-quote-remove-item="1">X</button></td>
                        </tr>
                      <?php endforeach; ?>
                    </tbody>
                  </table>
                </div>

                <div style="margin-top:.65rem; display:flex; justify-content:flex-start;">
                  <button class="btn" type="button" data-quote-add-item="1">Agregar item</button>
                </div>
                <p class="muted" style="margin:.4rem 0 0;">La tabla de salida usa 15 filas por pagina. Si hay mas items, se crean paginas adicionales automaticamente.</p>

                <div class="quote-form-grid" style="margin-top:.72rem;">
                  <div class="field full">
                    <label>Validez especial de esta cotizacion (opcional)</label>
                    <textarea name="validez_override" placeholder="Si queda en blanco, se usa la validez definida en Empresa."><?= h((string)($quoteForm['validez_override'] ?? '')) ?></textarea>
                  </div>
                  <div class="field full">
                    <label>Entrega especial de esta cotizacion (opcional)</label>
                    <textarea name="entrega_override" placeholder="Si queda en blanco, se usa la entrega definida en Empresa."><?= h((string)($quoteForm['entrega_override'] ?? '')) ?></textarea>
                  </div>
                  <div class="field full">
                    <label>Condicion de pago especial (opcional)</label>
                    <textarea name="condicion_de_pago_override" placeholder="Si queda en blanco, se usa la condicion de pago definida en Empresa."><?= h((string)($quoteForm['condicion_de_pago_override'] ?? '')) ?></textarea>
                  </div>
                  <div class="field">
                    <label>Moneda especial (opcional)</label>
                    <input type="text" name="moneda_override" maxlength="10" value="<?= h((string)($quoteForm['moneda_override'] ?? '')) ?>" placeholder="Ej: CLP, USD, EUR">
                  </div>
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

        <div class="modal-backdrop<?= $openQuoteEmailModal ? ' open' : '' ?>" id="quoteEmailModal" aria-hidden="<?= $openQuoteEmailModal ? 'false' : 'true' ?>">
          <div class="quote-email-card" role="dialog" aria-modal="true" aria-labelledby="quoteEmailModalTitle">
            <div class="modal-head">
              <h3 id="quoteEmailModalTitle">Enviar cotizacion por correo</h3>
              <button class="btn" type="button" data-close-quote-email="1">Cerrar</button>
            </div>
            <div class="modal-body">
              <form method="post" enctype="multipart/form-data" class="quote-email-form" id="quoteEmailForm">
                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                <input type="hidden" name="action" value="send_quote_email">
                <input type="hidden" name="quote_id" value="<?= h((string)($quoteEmailForm['quote_id'] ?? '')) ?>" data-quote-email-id="1">

                <div class="quote-email-grid">
                  <div class="field full">
                    <label>Para (separar varios con coma)</label>
                    <input type="text" name="quote_email_to" value="<?= h((string)($quoteEmailForm['to'] ?? '')) ?>" placeholder="cliente@empresa.com" required data-quote-email-to="1">
                  </div>
                  <div class="field full">
                    <label>CC (opcional)</label>
                    <input type="text" name="quote_email_cc" value="<?= h((string)($quoteEmailForm['cc'] ?? '')) ?>" placeholder="supervisor@empresa.com, compras@empresa.com" data-quote-email-cc="1">
                  </div>
                  <div class="field full">
                    <label>Asunto</label>
                    <input type="text" name="quote_email_subject" value="<?= h((string)($quoteEmailForm['subject'] ?? '')) ?>" required data-quote-email-subject="1">
                  </div>
                  <div class="field full">
                    <label>Mensaje</label>
                    <textarea name="quote_email_message" required data-quote-email-message="1"><?= h((string)($quoteEmailForm['message'] ?? '')) ?></textarea>
                  </div>
                  <div class="field full">
                    <label>Adjuntos opcionales (max 5 archivos, 8 MB c/u)</label>
                    <input type="file" name="quote_email_files[]" multiple>
                  </div>
                </div>

                <label class="quote-email-check">
                  <input type="checkbox" name="include_quote_attachment" value="1" <?= ((string)($quoteEmailForm['include_quote_attachment'] ?? '1') === '1') ? 'checked' : '' ?> data-quote-email-include="1">
                  Adjuntar cotizacion en PDF
                </label>
                <p class="quote-email-note" data-quote-email-meta="1">Se incluira tambien el enlace a la vista imprimible de la cotizacion.</p>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-quote-email="1">Cancelar</button>
                  <button class="btn primary" type="submit" data-quote-email-submit-label="1">Enviar correo</button>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div class="modal-backdrop" id="quoteEmailSendingModal" aria-hidden="true">
          <div class="sending-modal-card" role="status" aria-live="polite" aria-label="Enviando correo de cotizacion">
            <div class="sending-modal-spinner" aria-hidden="true"></div>
            <p class="sending-modal-title">Enviando correo...</p>
            <p class="sending-modal-text">Por favor espera. Estamos generando el PDF y enviando la cotizacion.</p>
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

      <?php if ($module === 'papelera'): ?>
        <section class="panel">
          <h2>Papelera de reciclaje</h2>
          <p class="muted">Los registros aqui pueden eliminarse de forma definitiva. Esta accion no se puede deshacer.</p>

          <h3 style="margin-top:1rem;">Clientes en papelera</h3>
          <?php if (empty($trashCustomers)): ?>
            <p class="muted">No hay clientes en papelera.</p>
          <?php else: ?>
            <div style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>RUT</th><th>Razon social</th><th>Contacto</th><th>Eliminado por</th><th>Fecha</th><th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($trashCustomers as $trashCustomer): ?>
                    <tr>
                      <td><?= h((string)$trashCustomer['rut']) ?></td>
                      <td><?= h((string)$trashCustomer['razon_social']) ?></td>
                      <td><?= h((string)$trashCustomer['contacto']) ?></td>
                      <td><?= h((string)($trashCustomer['deleted_by'] ?? 'N/D')) ?></td>
                      <td><?= h((string)($trashCustomer['deleted_at'] ?? '')) ?></td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Restaurar cliente"
                            aria-label="Restaurar cliente"
                            data-open-delete-confirm="1"
                            data-delete-action="restore_customer"
                            data-delete-id-field="customer_id"
                            data-delete-id-value="<?= h((string)$trashCustomer['id']) ?>"
                            data-delete-entity="cliente"
                            data-delete-description="<?= h((string)$trashCustomer['razon_social']) ?>"
                            data-delete-mode="restore"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 10a6 6 0 1 0 2-4.5M4 5v4h4"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Eliminar cliente de forma definitiva"
                            aria-label="Eliminar cliente de forma definitiva"
                            data-open-delete-confirm="1"
                            data-delete-action="purge_customer"
                            data-delete-id-field="customer_id"
                            data-delete-id-value="<?= h((string)$trashCustomer['id']) ?>"
                            data-delete-entity="cliente"
                            data-delete-description="<?= h((string)$trashCustomer['razon_social']) ?>"
                            data-delete-mode="purge"
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

          <h3 style="margin-top:1rem;">Cotizaciones en papelera</h3>
          <?php if (empty($trashQuotes)): ?>
            <p class="muted">No hay cotizaciones en papelera.</p>
          <?php else: ?>
            <div style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>#</th><th>Cliente</th><th>Total</th><th>Estado</th><th>Eliminado por</th><th>Fecha</th><th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($trashQuotes as $trashQuote): ?>
                    <tr>
                      <td><?= h((string)$trashQuote['numero_cotizacion']) ?></td>
                      <td><?= h((string)($trashQuote['customer_name'] ?: 'Cliente eliminado')) ?></td>
                      <td>$<?= h(money_clp((float)$trashQuote['total'])) ?></td>
                      <td><?= h((string)$trashQuote['estado']) ?></td>
                      <td><?= h((string)($trashQuote['deleted_by'] ?? 'N/D')) ?></td>
                      <td><?= h((string)($trashQuote['deleted_at'] ?? '')) ?></td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Restaurar cotizacion"
                            aria-label="Restaurar cotizacion"
                            data-open-delete-confirm="1"
                            data-delete-action="restore_quote"
                            data-delete-id-field="quote_id"
                            data-delete-id-value="<?= h((string)$trashQuote['id']) ?>"
                            data-delete-entity="cotizacion"
                            data-delete-description="<?= h((string)$trashQuote['numero_cotizacion']) ?>"
                            data-delete-mode="restore"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 10a6 6 0 1 0 2-4.5M4 5v4h4"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Eliminar cotizacion de forma definitiva"
                            aria-label="Eliminar cotizacion de forma definitiva"
                            data-open-delete-confirm="1"
                            data-delete-action="purge_quote"
                            data-delete-id-field="quote_id"
                            data-delete-id-value="<?= h((string)$trashQuote['id']) ?>"
                            data-delete-entity="cotizacion"
                            data-delete-description="<?= h((string)$trashQuote['numero_cotizacion']) ?>"
                            data-delete-mode="purge"
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

          <h3 style="margin-top:1rem;">Items de inventario en papelera</h3>
          <?php if (empty($trashInventoryItems)): ?>
            <p class="muted">No hay items de inventario en papelera.</p>
          <?php else: ?>
            <div style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>SKU</th><th>Nombre</th><th>Unidad</th><th>Stock</th><th>Eliminado por</th><th>Fecha</th><th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($trashInventoryItems as $trashInv): ?>
                    <tr>
                      <td><?= h((string)$trashInv['sku']) ?></td>
                      <td><?= h((string)$trashInv['nombre']) ?></td>
                      <td><?= h((string)$trashInv['unidad']) ?></td>
                      <td><?= h(number_format((float)$trashInv['stock_actual'], 2, ',', '.')) ?></td>
                      <td><?= h((string)($trashInv['deleted_by'] ?? 'N/D')) ?></td>
                      <td><?= h((string)($trashInv['deleted_at'] ?? '')) ?></td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Restaurar item"
                            aria-label="Restaurar item"
                            data-open-delete-confirm="1"
                            data-delete-action="restore_inventory_item"
                            data-delete-id-field="inventory_item_id"
                            data-delete-id-value="<?= h((string)$trashInv['id']) ?>"
                            data-delete-entity="item de inventario"
                            data-delete-description="<?= h((string)$trashInv['nombre']) ?>"
                            data-delete-mode="restore"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 10a6 6 0 1 0 2-4.5M4 5v4h4"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Eliminar item de forma definitiva"
                            aria-label="Eliminar item de forma definitiva"
                            data-open-delete-confirm="1"
                            data-delete-action="purge_inventory_item"
                            data-delete-id-field="inventory_item_id"
                            data-delete-id-value="<?= h((string)$trashInv['id']) ?>"
                            data-delete-entity="item de inventario"
                            data-delete-description="<?= h((string)$trashInv['nombre']) ?>"
                            data-delete-mode="purge"
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

          <h3 style="margin-top:1rem;">Ordenes de servicio en papelera</h3>
          <?php if (empty($trashServiceOrders)): ?>
            <p class="muted">No hay ordenes de servicio en papelera.</p>
          <?php else: ?>
            <div style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>Codigo</th><th>Titulo</th><th>Cliente</th><th>Estado</th><th>Eliminado por</th><th>Fecha</th><th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($trashServiceOrders as $trashSo): ?>
                    <tr>
                      <td><?= h((string)$trashSo['codigo']) ?></td>
                      <td><?= h((string)$trashSo['titulo']) ?></td>
                      <td><?= h((string)($trashSo['customer_name'] ?? '')) ?></td>
                      <td><?= h((string)$trashSo['estado']) ?></td>
                      <td><?= h((string)($trashSo['deleted_by'] ?? 'N/D')) ?></td>
                      <td><?= h((string)($trashSo['deleted_at'] ?? '')) ?></td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Restaurar orden"
                            data-open-delete-confirm="1"
                            data-delete-action="restore_service_order"
                            data-delete-id-field="service_order_id"
                            data-delete-id-value="<?= h((string)$trashSo['id']) ?>"
                            data-delete-entity="orden de servicio"
                            data-delete-description="<?= h((string)$trashSo['codigo'] . ' - ' . $trashSo['titulo']) ?>"
                            data-delete-mode="restore"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 10a6 6 0 1 0 2-4.5M4 5v4h4"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Eliminar orden de forma definitiva"
                            data-open-delete-confirm="1"
                            data-delete-action="purge_service_order"
                            data-delete-id-field="service_order_id"
                            data-delete-id-value="<?= h((string)$trashSo['id']) ?>"
                            data-delete-entity="orden de servicio"
                            data-delete-description="<?= h((string)$trashSo['codigo'] . ' - ' . $trashSo['titulo']) ?>"
                            data-delete-mode="purge"
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

          <h3 style="margin-top:1rem;">Reportes en papelera</h3>
          <?php if (empty($trashServiceReports)): ?>
            <p class="muted">No hay reportes en papelera.</p>
          <?php else: ?>
            <div style="overflow:auto;">
              <table>
                <thead>
                  <tr>
                    <th>Fecha reporte</th><th>OS</th><th>Tecnico</th><th>Trabajo</th><th>Eliminado por</th><th>Fecha papelera</th><th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($trashServiceReports as $trashReport): ?>
                    <tr>
                      <td><?= h((string)($trashReport['report_date'] ?? '')) ?></td>
                      <td><strong><?= h((string)($trashReport['service_order_code'] ?? '')) ?></strong><br><small class="muted"><?= h((string)($trashReport['service_order_title'] ?? '')) ?></small></td>
                      <td><?= h((string)($trashReport['technician_full_name'] ?? '')) ?></td>
                      <td><?= nl2br(h((string)($trashReport['work_done'] ?? ''))) ?></td>
                      <td><?= h((string)($trashReport['deleted_by'] ?? 'N/D')) ?></td>
                      <td><?= h((string)($trashReport['deleted_at'] ?? '')) ?></td>
                      <td class="quote-action-cell">
                        <div class="action-icons">
                          <button
                            class="icon-btn edit"
                            type="button"
                            title="Restaurar reporte"
                            aria-label="Restaurar reporte"
                            data-open-delete-confirm="1"
                            data-delete-action="restore_service_report"
                            data-delete-id-field="report_id"
                            data-delete-id-value="<?= h((string)($trashReport['id'] ?? '')) ?>"
                            data-delete-entity="reporte"
                            data-delete-description="<?= h((string)($trashReport['service_order_code'] ?? '')) ?> - <?= h((string)($trashReport['report_date'] ?? '')) ?>"
                            data-delete-mode="restore"
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 10a6 6 0 1 0 2-4.5M4 5v4h4"/></svg>
                          </button>
                          <button
                            class="icon-btn danger"
                            type="button"
                            title="Eliminar reporte de forma definitiva"
                            aria-label="Eliminar reporte de forma definitiva"
                            data-open-delete-confirm="1"
                            data-delete-action="purge_service_report"
                            data-delete-id-field="report_id"
                            data-delete-id-value="<?= h((string)($trashReport['id'] ?? '')) ?>"
                            data-delete-entity="reporte"
                            data-delete-description="<?= h((string)($trashReport['service_order_code'] ?? '')) ?> - <?= h((string)($trashReport['report_date'] ?? '')) ?>"
                            data-delete-mode="purge"
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
      <?php endif; ?>

      <?php if ($module === 'clientes' || $module === 'tecnicos' || $module === 'inventario' || $module === 'cotizaciones' || $module === 'papelera' || $module === 'ordenes-servicio' || $module === 'reportes'): ?>
        <div class="modal-backdrop" id="deleteConfirmModal" aria-hidden="true" data-delete-csrf-token="<?= h($csrfToken) ?>">
          <div class="delete-confirm-card" role="dialog" aria-modal="true" aria-labelledby="deleteConfirmTitle">
            <div class="modal-head">
              <h3 id="deleteConfirmTitle" data-delete-confirm-title="1">Confirmar accion</h3>
              <button class="btn" type="button" data-close-delete-confirm="1">Cerrar</button>
            </div>
            <div class="delete-confirm-body">
              <p class="delete-confirm-text" data-delete-confirm-description="1"></p>
              <div data-delete-step-one="1">
                <p class="delete-confirm-text" data-delete-step-one-text="1">Primer paso: confirma que quieres continuar.</p>
                <div class="modal-actions" style="margin-top:.5rem;">
                  <button class="btn" type="button" data-close-delete-confirm="1">Cancelar</button>
                  <button class="btn danger" type="button" data-delete-go-step-two="1">Continuar</button>
                </div>
              </div>
              <div data-delete-step-two="1" style="display:none;">
                <p class="delete-confirm-text" data-delete-step-two-text="1">Segundo paso: confirma la accion para habilitar el boton final.</p>
                <label class="delete-confirm-check" data-delete-check-wrap="1">
                  <input type="checkbox" data-delete-confirm-checkbox="1">
                  <span data-delete-check-text="1">Confirmo que entiendo esta accion.</span>
                </label>
                <div class="modal-actions" style="margin-top:.5rem;">
                  <button class="btn" type="button" data-delete-back-step-one="1">Volver</button>
                  <button class="btn danger" type="button" data-delete-submit="1" disabled data-delete-submit-label="1">Eliminar definitivamente</button>
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
      var technicianModalCleanup = null;
      var technicianAssetModalCleanup = null;
      var inventoryModalCleanup = null;
      var inventoryMoveModalCleanup = null;
      var inventoryHistoryModalCleanup = null;
      var serviceOrderModalCleanup = null;
      var serviceOrderAssignModalCleanup = null;
      var serviceOrderListCleanup = null;
      var quoteModalCleanup = null;
      var reportFormCleanup = null;
      var reportHistoryCleanup = null;
      var formTemplateBuilderCleanup = null;
      var cartaGanttCleanup = null;

      function isTechniciansModuleActive() {
        return !!document.getElementById('technicianModal') || !!document.getElementById('techAssetModal');
      }

      function showTechError(message) {
        var text = String(message || 'No se pudo completar la accion.');
        window.alert(text);
      }

      async function postTechnicianAjax(formData) {
        formData.append('ajax', '1');
        var response = await fetch(window.location.href, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: formData,
        });

        var payload = null;
        try {
          payload = await response.json();
        } catch (e) {
          payload = null;
        }

        if (!response.ok || !payload || payload.ok !== true) {
          var serverMessage = payload && payload.message ? payload.message : 'No se pudo completar la accion.';
          throw new Error(serverMessage);
        }

        var targetUrl = new URL(window.location.href);
        if (shouldHandleAsSpa(targetUrl)) {
          await navigateSpa(targetUrl, false);
        }
      }

            function bindTechnicianModal() {
              if (typeof technicianModalCleanup === 'function') {
                technicianModalCleanup();
                technicianModalCleanup = null;
              }

              var technicianModal = document.getElementById('technicianModal');
              if (!technicianModal) {
                return;
              }

              var openButtons = document.querySelectorAll('[data-open-technician-modal="1"]');
              var editButtons = document.querySelectorAll('[data-edit-technician="1"]');
              var closeButtons = technicianModal.querySelectorAll('[data-close-technician-modal="1"]');
              var form = technicianModal.querySelector('#technicianModalForm');
              var title = technicianModal.querySelector('#technicianModalTitle');
              var actionInput = technicianModal.querySelector('[data-technician-action="1"]');
              var idInput = technicianModal.querySelector('[data-technician-id="1"]');
              var submitLabel = technicianModal.querySelector('[data-technician-submit-label="1"]');
              var skillsPreview = technicianModal.querySelector('[data-tech-skills-picked="1"]');
              var initialValues = {};
              var initialSkills = [];
              var skillInputs = form ? Array.prototype.slice.call(form.querySelectorAll('input[name="habilidades[]"]')) : [];

              function renderSkillChips(skills) {
                if (!skillsPreview) {
                  return;
                }
                skillsPreview.innerHTML = '';
                if (!Array.isArray(skills) || skills.length === 0) {
                  var empty = document.createElement('span');
                  empty.className = 'muted';
                  empty.textContent = 'Sin habilidades seleccionadas.';
                  skillsPreview.appendChild(empty);
                  return;
                }

                skills.forEach(function (skill) {
                  var chip = document.createElement('span');
                  chip.className = 'tech-skill-chip';
                  chip.textContent = String(skill || '');
                  skillsPreview.appendChild(chip);
                });
              }

              function getSelectedSkills() {
                var picked = [];
                skillInputs.forEach(function (input) {
                  if (input.checked) {
                    picked.push(input.value);
                  }
                });
                return picked;
              }

              function onSkillsChange() {
                renderSkillChips(getSelectedSkills());
              }

              function setSkills(skills) {
                if (!form) {
                  return;
                }
                var selected = {};
                (Array.isArray(skills) ? skills : []).forEach(function (skill) {
                  selected[String(skill || '')] = true;
                });

                skillInputs.forEach(function (input) {
                  input.checked = !!selected[input.value];
                });
                renderSkillChips(getSelectedSkills());
              }

              if (form) {
                ['nombre', 'apellido', 'cargo', 'cuenta', 'fecha_ingreso', 'estado'].forEach(function (fieldName) {
                  var field = form.querySelector('[name="' + fieldName + '"]');
                  initialValues[fieldName] = field ? field.value : '';
                });
                form.querySelectorAll('input[name="habilidades[]"]:checked').forEach(function (input) {
                  initialSkills.push(input.value);
                });
                renderSkillChips(initialSkills);
              }

              function setTechnicianMode(isEdit) {
                if (actionInput) {
                  actionInput.value = isEdit ? 'update_technician' : 'add_technician';
                }
                if (title) {
                  title.textContent = isEdit ? 'Editar tecnico' : 'Agregar tecnico';
                }
                if (submitLabel) {
                  submitLabel.textContent = isEdit ? 'Actualizar tecnico' : 'Guardar tecnico';
                }
                if (!isEdit && idInput) {
                  idInput.value = '';
                }
              }

              function fillFormFromButton(button) {
                if (!form) {
                  return;
                }
                var map = [
                  ['tech-nombre', 'nombre'],
                  ['tech-apellido', 'apellido'],
                  ['tech-cargo', 'cargo'],
                  ['tech-cuenta', 'cuenta'],
                  ['tech-fecha-ingreso', 'fecha_ingreso'],
                  ['tech-estado', 'estado']
                ];
                map.forEach(function (pair) {
                  var dataName = pair[0];
                  var fieldName = pair[1];
                  var field = form.querySelector('[name="' + fieldName + '"]');
                  if (field) {
                    field.value = button.getAttribute('data-' + dataName) || '';
                  }
                });

                var rawSkills = button.getAttribute('data-tech-habilidades') || '[]';
                var parsedSkills = [];
                try {
                  var data = JSON.parse(rawSkills);
                  if (Array.isArray(data)) {
                    parsedSkills = data;
                  }
                } catch (e) {
                  parsedSkills = [];
                }
                setSkills(parsedSkills);
              }

              function openModal() {
                if (form) {
                  Object.keys(initialValues).forEach(function (fieldName) {
                    var field = form.querySelector('[name="' + fieldName + '"]');
                    if (field) {
                      field.value = initialValues[fieldName] || '';
                    }
                  });
                  setSkills(initialSkills);
                }
                setTechnicianMode(false);
                technicianModal.classList.add('open');
                technicianModal.setAttribute('aria-hidden', 'false');
                var firstInput = technicianModal.querySelector('input[name="nombre"]');
                if (firstInput) {
                  firstInput.focus();
                }
              }

              function closeModal() {
                technicianModal.classList.remove('open');
                technicianModal.setAttribute('aria-hidden', 'true');
              }

              function onBackdropClick(event) {
                if (event.target === technicianModal) {
                  closeModal();
                }
              }

              function onEsc(event) {
                if (event.key === 'Escape' && technicianModal.classList.contains('open')) {
                  closeModal();
                }
              }

              function onEditClick(event) {
                var button = event.currentTarget;
                setTechnicianMode(true);
                if (idInput) {
                  idInput.value = button.getAttribute('data-tech-id') || '';
                }
                fillFormFromButton(button);
                technicianModal.classList.add('open');
                technicianModal.setAttribute('aria-hidden', 'false');
              }

              async function onSubmit(event) {
                if (!isTechniciansModuleActive()) {
                  return;
                }
                event.preventDefault();
                if (!form) {
                  return;
                }

                var submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn) {
                  submitBtn.disabled = true;
                }

                try {
                  await postTechnicianAjax(new FormData(form));
                } catch (error) {
                  showTechError(error && error.message ? error.message : 'No se pudo guardar el tecnico.');
                } finally {
                  if (submitBtn) {
                    submitBtn.disabled = false;
                  }
                }
              }

              openButtons.forEach(function (button) {
                button.addEventListener('click', openModal);
              });
              editButtons.forEach(function (button) {
                button.addEventListener('click', onEditClick);
              });
              if (form) {
                form.addEventListener('submit', onSubmit);
              }
              skillInputs.forEach(function (input) {
                input.addEventListener('change', onSkillsChange);
              });
              closeButtons.forEach(function (button) {
                button.addEventListener('click', closeModal);
              });
              technicianModal.addEventListener('click', onBackdropClick);
              document.addEventListener('keydown', onEsc);

              technicianModalCleanup = function () {
                openButtons.forEach(function (button) {
                  button.removeEventListener('click', openModal);
                });
                editButtons.forEach(function (button) {
                  button.removeEventListener('click', onEditClick);
                });
                if (form) {
                  form.removeEventListener('submit', onSubmit);
                }
                skillInputs.forEach(function (input) {
                  input.removeEventListener('change', onSkillsChange);
                });
                closeButtons.forEach(function (button) {
                  button.removeEventListener('click', closeModal);
                });
                technicianModal.removeEventListener('click', onBackdropClick);
                document.removeEventListener('keydown', onEsc);
              };
            }

            function bindTechnicianAssetModal() {
              if (typeof technicianAssetModalCleanup === 'function') {
                technicianAssetModalCleanup();
                technicianAssetModalCleanup = null;
              }

              var modal = document.getElementById('techAssetModal');
              if (!modal) {
                return;
              }

              var openButtons = document.querySelectorAll('[data-open-tech-asset="1"]');
              var closeButtons = modal.querySelectorAll('[data-close-tech-asset-modal="1"]');
              var form = modal.querySelector('#techAssetModalForm');
              var title = modal.querySelector('#techAssetModalTitle');
              var actionInput = modal.querySelector('[data-tech-asset-action="1"]');
              var typeInput = modal.querySelector('[data-tech-asset-type="1"]');
              var assetIdInput = modal.querySelector('[data-tech-asset-id="1"]');
              var techIdInput = modal.querySelector('[data-tech-asset-tech-id="1"]');
              var techName = modal.querySelector('[data-tech-asset-tech-name="1"]');
              var descLabel = modal.querySelector('[data-tech-asset-desc-label="1"]');
              var descInput = modal.querySelector('[data-tech-asset-desc="1"]');
              var deliveryInput = modal.querySelector('input[name="fecha_entrega"]');
              var vencWrap = modal.querySelector('[data-tech-asset-vencimiento-wrap="1"]');
              var vencInput = modal.querySelector('[data-tech-asset-vencimiento="1"]');
              var estadoWrap = modal.querySelector('[data-tech-asset-estado-wrap="1"]');
              var estadoSelect = modal.querySelector('[data-tech-asset-estado="1"]');
              var submitLabel = modal.querySelector('[data-tech-asset-submit-label="1"]');
              var cancelEditButton = modal.querySelector('[data-tech-asset-cancel-edit="1"]');
              var recordsBox = modal.querySelector('[data-tech-asset-records-list="1"]');
              var switchButtons = modal.querySelectorAll('[data-tech-asset-switch]');

              var currentRecords = { epp: [], cargo: [], herramientas: [] };

              function normalizeType(type) {
                var value = String(type || '').toLowerCase();
                return (value === 'cargo' || value === 'herramientas' || value === 'epp') ? value : 'epp';
              }

              function safeParseRecords(raw) {
                var parsed;
                try {
                  parsed = JSON.parse(raw || '{}');
                } catch (e) {
                  parsed = {};
                }
                var normalized = { epp: [], cargo: [], herramientas: [] };
                ['epp', 'cargo', 'herramientas'].forEach(function (type) {
                  if (Array.isArray(parsed[type])) {
                    normalized[type] = parsed[type];
                  }
                });
                return normalized;
              }

              function escapeHtml(value) {
                return String(value || '')
                  .replace(/&/g, '&amp;')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;')
                  .replace(/'/g, '&#039;');
              }

              function renderRecords(type) {
                if (!recordsBox) {
                  return;
                }
                var list = currentRecords[type] || [];
                if (!Array.isArray(list) || list.length === 0) {
                  recordsBox.innerHTML = '<p class="muted">Aun no hay registros en esta categoria.</p>';
                  return;
                }

                var rows = list.map(function (row) {
                  var detail = type === 'epp'
                    ? escapeHtml(row.fecha_vencimiento || '')
                    : escapeHtml(row.estado || '');
                  return '<tr>'
                    + '<td>' + escapeHtml(row.descripcion || '') + '</td>'
                    + '<td>' + escapeHtml(row.fecha_entrega || '') + '</td>'
                    + '<td>' + detail + '</td>'
                    + '<td><div class="action-icons">'
                    + '<button class="icon-btn edit" type="button" title="Editar registro" aria-label="Editar registro"'
                    + ' data-tech-asset-edit="1"'
                    + ' data-asset-id="' + escapeHtml(row.id || '') + '"'
                    + ' data-asset-type="' + escapeHtml(type) + '"'
                    + ' data-asset-descripcion="' + escapeHtml(row.descripcion || '') + '"'
                    + ' data-asset-fecha-entrega="' + escapeHtml(row.fecha_entrega || '') + '"'
                    + ' data-asset-fecha-vencimiento="' + escapeHtml(row.fecha_vencimiento || '') + '"'
                    + ' data-asset-estado="' + escapeHtml(row.estado || 'nuevo') + '">'
                    + '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M13.5 3.5l3 3M4 16h3l9-9-3-3-9 9v3z"></path></svg>'
                    + '</button>'
                    + '<button class="icon-btn danger" type="button" title="Eliminar registro" aria-label="Eliminar registro"'
                    + ' data-tech-asset-delete="1"'
                    + ' data-asset-id="' + escapeHtml(row.id || '') + '"'
                    + ' data-asset-type="' + escapeHtml(type) + '">'
                    + '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3.5 5.5h13M8 5.5V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M6 5.5l.7 10.5h6.6L14 5.5M8.7 8v5.5M11.3 8v5.5"></path></svg>'
                    + '</button>'
                    + '</div></td>'
                    + '</tr>';
                });
                var detailLabel = type === 'epp' ? 'Vencimiento' : 'Estado';
                recordsBox.innerHTML = '<table class="tech-asset-table">'
                  + '<thead><tr><th>Descripcion</th><th>Entrega</th><th>' + detailLabel + '</th><th>Acciones</th></tr></thead>'
                  + '<tbody>' + rows.join('') + '</tbody>'
                  + '</table>';
              }

              function resetAssetFormMode() {
                if (actionInput) {
                  actionInput.value = 'add_technician_asset';
                }
                if (assetIdInput) {
                  assetIdInput.value = '';
                }
                if (submitLabel) {
                  submitLabel.textContent = 'Guardar registro';
                }
                if (cancelEditButton) {
                  cancelEditButton.style.display = 'none';
                }
              }

              function fillAssetFormFromButton(button) {
                if (typeInput) {
                  typeInput.value = normalizeType(button.getAttribute('data-asset-type') || (typeInput.value || 'epp'));
                }
                if (assetIdInput) {
                  assetIdInput.value = button.getAttribute('data-asset-id') || '';
                }
                if (descInput) {
                  descInput.value = button.getAttribute('data-asset-descripcion') || '';
                }
                if (deliveryInput) {
                  deliveryInput.value = button.getAttribute('data-asset-fecha-entrega') || '';
                }
                if (vencInput) {
                  vencInput.value = button.getAttribute('data-asset-fecha-vencimiento') || '';
                }
                if (estadoSelect) {
                  estadoSelect.value = button.getAttribute('data-asset-estado') || 'nuevo';
                }
              }

              async function onFormSubmit(event) {
                if (!isTechniciansModuleActive()) {
                  return;
                }
                event.preventDefault();
                if (!form) {
                  return;
                }

                var submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn) {
                  submitBtn.disabled = true;
                }

                try {
                  await postTechnicianAjax(new FormData(form));
                } catch (error) {
                  showTechError(error && error.message ? error.message : 'No se pudo guardar la gestion del tecnico.');
                } finally {
                  if (submitBtn) {
                    submitBtn.disabled = false;
                  }
                }
              }

              function onCancelEditClick() {
                resetAssetFormMode();
                if (descInput) {
                  descInput.value = '';
                }
                if (deliveryInput) {
                  deliveryInput.value = new Date().toISOString().slice(0, 10);
                }
                if (vencInput) {
                  vencInput.value = '';
                }
                if (estadoSelect) {
                  estadoSelect.value = 'nuevo';
                }
              }

              async function deleteAsset(button) {
                if (!window.confirm('¿Eliminar este registro de gestion?')) {
                  return;
                }
                var fd = new FormData();
                var csrfInput = form ? form.querySelector('input[name="csrf_token"]') : null;
                if (csrfInput && csrfInput.value) {
                  fd.append('csrf_token', csrfInput.value);
                }
                fd.append('action', 'delete_technician_asset');
                fd.append('technician_id', techIdInput ? (techIdInput.value || '') : '');
                fd.append('asset_type', button.getAttribute('data-asset-type') || (typeInput ? typeInput.value : 'epp'));
                fd.append('asset_id', button.getAttribute('data-asset-id') || '');

                try {
                  await postTechnicianAjax(fd);
                } catch (error) {
                  showTechError(error && error.message ? error.message : 'No se pudo eliminar el registro.');
                }
              }

              function onRecordsClick(event) {
                var editBtn = event.target.closest('[data-tech-asset-edit="1"]');
                if (editBtn) {
                  applyType(editBtn.getAttribute('data-asset-type') || (typeInput ? typeInput.value : 'epp'));
                  fillAssetFormFromButton(editBtn);
                  if (actionInput) {
                    actionInput.value = 'update_technician_asset';
                  }
                  if (submitLabel) {
                    submitLabel.textContent = 'Guardar cambios';
                  }
                  if (cancelEditButton) {
                    cancelEditButton.style.display = '';
                  }
                  if (descInput) {
                    descInput.focus();
                  }
                  return;
                }

                var deleteBtn = event.target.closest('[data-tech-asset-delete="1"]');
                if (deleteBtn) {
                  deleteAsset(deleteBtn);
                }
              }

              function applyType(type) {
                var normalizedType = normalizeType(type);
                if (typeInput) {
                  typeInput.value = normalizedType;
                }
                if (title) {
                  if (normalizedType === 'epp') {
                    title.textContent = 'Gestion EPP';
                  } else if (normalizedType === 'cargo') {
                    title.textContent = 'Gestion Cargo';
                  } else {
                    title.textContent = 'Gestion Herramientas';
                  }
                }
                if (descLabel) {
                  descLabel.textContent = normalizedType === 'epp' ? 'Elemento EPP' : (normalizedType === 'cargo' ? 'Prenda de trabajo' : 'Herramienta');
                }
                if (vencWrap) {
                  vencWrap.style.display = normalizedType === 'epp' ? '' : 'none';
                }
                if (estadoWrap) {
                  estadoWrap.style.display = normalizedType === 'epp' ? 'none' : '';
                }
                if (normalizedType === 'epp' && estadoSelect) {
                  estadoSelect.value = 'nuevo';
                }
                if (normalizedType !== 'epp' && vencInput) {
                  vencInput.value = '';
                }
                resetAssetFormMode();
                switchButtons.forEach(function (btn) {
                  if ((btn.getAttribute('data-tech-asset-switch') || '') === normalizedType) {
                    btn.classList.add('active');
                  } else {
                    btn.classList.remove('active');
                  }
                });
                renderRecords(normalizedType);
              }

              function openModal(config) {
                currentRecords = safeParseRecords(config.recordsRaw || '{}');
                if (techIdInput) {
                  techIdInput.value = String(config.techId || '');
                }
                if (techName) {
                  techName.textContent = String(config.techName || '');
                }
                applyType(config.type || 'epp');
                resetAssetFormMode();
                modal.classList.add('open');
                modal.setAttribute('aria-hidden', 'false');
              }

              function closeModal() {
                modal.classList.remove('open');
                modal.setAttribute('aria-hidden', 'true');
                resetAssetFormMode();
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

              function onOpenClick(event) {
                var button = event.currentTarget;
                openModal({
                  techId: button.getAttribute('data-tech-id') || '',
                  techName: button.getAttribute('data-tech-name') || '',
                  type: button.getAttribute('data-asset-type') || 'epp',
                  recordsRaw: button.getAttribute('data-tech-assets') || '{}',
                });
              }

              function onSwitchClick(event) {
                var targetType = event.currentTarget.getAttribute('data-tech-asset-switch') || 'epp';
                applyType(targetType);
              }

              openButtons.forEach(function (button) {
                button.addEventListener('click', onOpenClick);
              });
              closeButtons.forEach(function (button) {
                button.addEventListener('click', closeModal);
              });
              switchButtons.forEach(function (button) {
                button.addEventListener('click', onSwitchClick);
              });
              if (form) {
                form.addEventListener('submit', onFormSubmit);
              }
              if (cancelEditButton) {
                cancelEditButton.addEventListener('click', onCancelEditClick);
              }
              if (recordsBox) {
                recordsBox.addEventListener('click', onRecordsClick);
              }
              modal.addEventListener('click', onBackdropClick);
              document.addEventListener('keydown', onEsc);

              if (modal.classList.contains('open')) {
                openModal({
                  techId: techIdInput ? techIdInput.value : '',
                  techName: techName ? techName.textContent : '',
                  type: typeInput ? typeInput.value : 'epp',
                  recordsRaw: modal.getAttribute('data-tech-asset-records') || '{}',
                });
              }

              technicianAssetModalCleanup = function () {
                openButtons.forEach(function (button) {
                  button.removeEventListener('click', onOpenClick);
                });
                closeButtons.forEach(function (button) {
                  button.removeEventListener('click', closeModal);
                });
                switchButtons.forEach(function (button) {
                  button.removeEventListener('click', onSwitchClick);
                });
                if (form) {
                  form.removeEventListener('submit', onFormSubmit);
                }
                if (cancelEditButton) {
                  cancelEditButton.removeEventListener('click', onCancelEditClick);
                }
                if (recordsBox) {
                  recordsBox.removeEventListener('click', onRecordsClick);
                }
                modal.removeEventListener('click', onBackdropClick);
                document.removeEventListener('keydown', onEsc);
              };
            }

      function bindInventoryModal() {
        if (typeof inventoryModalCleanup === 'function') {
          inventoryModalCleanup();
          inventoryModalCleanup = null;
        }

        var modal = document.getElementById('inventoryModal');
        if (!modal) {
          return;
        }

        var openButtons = document.querySelectorAll('[data-open-inventory-modal="1"]');
        var editButtons = document.querySelectorAll('[data-edit-inventory-item="1"]');
        var closeButtons = modal.querySelectorAll('[data-close-inventory-modal="1"]');
        var form = modal.querySelector('#inventoryModalForm');
        var title = modal.querySelector('#inventoryModalTitle');
        var actionInput = modal.querySelector('[data-inventory-action="1"]');
        var idInput = modal.querySelector('[data-inventory-id="1"]');
        var submitLabel = modal.querySelector('[data-inventory-submit-label="1"]');
        var initialValues = {};

        if (form) {
          ['sku', 'nombre', 'descripcion', 'unidad', 'stock_actual', 'stock_minimo', 'stock_critico', 'costo_unitario', 'estado'].forEach(function (fieldName) {
            var field = form.querySelector('[name="' + fieldName + '"]');
            initialValues[fieldName] = field ? field.value : '';
          });
        }

        function setMode(isEdit) {
          if (actionInput) {
            actionInput.value = isEdit ? 'update_inventory_item' : 'add_inventory_item';
          }
          if (title) {
            title.textContent = isEdit ? 'Editar item de inventario' : 'Agregar item de inventario';
          }
          if (submitLabel) {
            submitLabel.textContent = isEdit ? 'Actualizar item' : 'Guardar item';
          }
          if (!isEdit && idInput) {
            idInput.value = '';
          }
        }

        function openCreate() {
          if (form) {
            Object.keys(initialValues).forEach(function (fieldName) {
              var field = form.querySelector('[name="' + fieldName + '"]');
              if (field) {
                field.value = initialValues[fieldName] || '';
              }
            });
          }
          setMode(false);
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }

        function openEdit(button) {
          if (!form) {
            return;
          }

          setMode(true);
          if (idInput) {
            idInput.value = button.getAttribute('data-inv-id') || '';
          }

          var fieldMap = [
            ['data-inv-sku', 'sku'],
            ['data-inv-nombre', 'nombre'],
            ['data-inv-descripcion', 'descripcion'],
            ['data-inv-unidad', 'unidad'],
            ['data-inv-stock-actual', 'stock_actual'],
            ['data-inv-stock-minimo', 'stock_minimo'],
            ['data-inv-stock-critico', 'stock_critico'],
            ['data-inv-costo-unitario', 'costo_unitario'],
            ['data-inv-estado', 'estado']
          ];
          fieldMap.forEach(function (pair) {
            var attr = pair[0];
            var fieldName = pair[1];
            var field = form.querySelector('[name="' + fieldName + '"]');
            if (field) {
              field.value = button.getAttribute(attr) || '';
            }
          });

          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }

        function closeModal() {
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
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

        function onSoChange() {
          renderDynamicForms();
        }

        function onCreateClick() {
          openCreate();
        }

        function onEditClick(event) {
          openEdit(event.currentTarget);
        }

        async function onSubmit(event) {
          if (!form) {
            return;
          }
          event.preventDefault();
          var submitBtn = form.querySelector('button[type="submit"]');
          if (submitBtn) {
            submitBtn.disabled = true;
          }
          try {
            await postTechnicianAjax(new FormData(form));
            closeModal();
          } catch (error) {
            window.alert(error && error.message ? error.message : 'No se pudo guardar el item de inventario.');
          } finally {
            if (submitBtn) {
              submitBtn.disabled = false;
            }
          }
        }

        openButtons.forEach(function (button) {
          button.addEventListener('click', onCreateClick);
        });
        editButtons.forEach(function (button) {
          button.addEventListener('click', onEditClick);
        });
        closeButtons.forEach(function (button) {
          button.addEventListener('click', closeModal);
        });
        if (form) {
          form.addEventListener('submit', onSubmit);
        }
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);

        inventoryModalCleanup = function () {
          openButtons.forEach(function (button) {
            button.removeEventListener('click', onCreateClick);
          });
          editButtons.forEach(function (button) {
            button.removeEventListener('click', onEditClick);
          });
          closeButtons.forEach(function (button) {
            button.removeEventListener('click', closeModal);
          });
          if (form) {
            form.removeEventListener('submit', onSubmit);
          }
          modal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
        };
      }

      function bindInventoryMovementModal() {
        if (typeof inventoryMoveModalCleanup === 'function') {
          inventoryMoveModalCleanup();
          inventoryMoveModalCleanup = null;
        }

        var modal = document.getElementById('inventoryMoveModal');
        if (!modal) {
          return;
        }

        var openButtons = document.querySelectorAll('[data-open-inventory-move-modal="1"]');
        var closeButtons = modal.querySelectorAll('[data-close-inventory-move-modal="1"]');
        var form = modal.querySelector('#inventoryMoveModalForm');
        var itemSelect = form ? form.querySelector('[name="movement_item_id"]') : null;

        function openModal(itemId) {
          if (itemSelect && itemId) {
            itemSelect.value = String(itemId);
          }
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }

        function closeModal() {
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
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

        function onOpenClick(event) {
          var button = event.currentTarget;
          var itemId = button.getAttribute('data-move-item-id') || '';
          openModal(itemId);
        }

        async function onSubmit(event) {
          if (!form) {
            return;
          }
          event.preventDefault();
          var submitBtn = form.querySelector('button[type="submit"]');
          if (submitBtn) {
            submitBtn.disabled = true;
          }
          try {
            await postTechnicianAjax(new FormData(form));
            closeModal();
          } catch (error) {
            window.alert(error && error.message ? error.message : 'No se pudo registrar el movimiento.');
          } finally {
            if (submitBtn) {
              submitBtn.disabled = false;
            }
          }
        }

        openButtons.forEach(function (button) {
          button.addEventListener('click', onOpenClick);
        });
        closeButtons.forEach(function (button) {
          button.addEventListener('click', closeModal);
        });
        if (form) {
          form.addEventListener('submit', onSubmit);
        }
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);

        inventoryMoveModalCleanup = function () {
          openButtons.forEach(function (button) {
            button.removeEventListener('click', onOpenClick);
          });
          closeButtons.forEach(function (button) {
            button.removeEventListener('click', closeModal);
          });
          if (form) {
            form.removeEventListener('submit', onSubmit);
          }
          modal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
        };
      }

      var quoteEmailCleanup = null;
      var quotePreviewCleanup = null;
      var deleteConfirmCleanup = null;
      var quoteFiltersCleanup = null;
      var quoteQuickStateCleanup = null;
      var sideToggleCleanup = null;

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

      function bindToasts() {
        var toasts = document.querySelectorAll('[data-toast="1"]');
        if (!toasts.length) {
          return;
        }

        toasts.forEach(function (toast) {
          var timeoutMs = Number(toast.getAttribute('data-toast-timeout') || '5000');
          if (!isFinite(timeoutMs) || timeoutMs < 0) {
            timeoutMs = 5000;
          }

          var closeBtn = toast.querySelector('[data-toast-close="1"]');
          var closed = false;
          var closeTimerId = null;

          function removeToast() {
            var parent = toast.parentElement;
            toast.remove();
            if (parent && parent.matches('[data-toast-stack="1"]') && parent.children.length === 0) {
              parent.remove();
            }
          }

          function closeToast() {
            if (closed) {
              return;
            }
            closed = true;
            if (closeTimerId !== null) {
              clearTimeout(closeTimerId);
              closeTimerId = null;
            }
            toast.classList.remove('is-visible');
            toast.classList.add('is-closing');
            window.setTimeout(removeToast, 230);
          }

          window.requestAnimationFrame(function () {
            toast.classList.add('is-visible');
          });

          closeTimerId = window.setTimeout(closeToast, timeoutMs);
          if (closeBtn) {
            closeBtn.addEventListener('click', closeToast);
          }
        });
      }

      function bindSideMenuToggle() {
        if (typeof sideToggleCleanup === 'function') {
          sideToggleCleanup();
          sideToggleCleanup = null;
        }

        var toggleBtn = document.querySelector('[data-side-toggle="1"]');
        if (!toggleBtn) {
          document.body.classList.remove('side-state-preload');
          return;
        }

        var storageKey = 'hermes_side_collapsed_v1';

        function applyCollapsed(collapsed) {
          if (window.matchMedia('(max-width: 980px)').matches) {
            document.body.classList.remove('side-collapsed');
            toggleBtn.setAttribute('aria-expanded', 'true');
            toggleBtn.setAttribute('aria-label', 'Contraer menu');
            toggleBtn.setAttribute('title', 'Contraer menu');
            return;
          }

          if (collapsed) {
            document.body.classList.add('side-collapsed');
            toggleBtn.setAttribute('aria-expanded', 'false');
            toggleBtn.setAttribute('aria-label', 'Expandir menu');
            toggleBtn.setAttribute('title', 'Expandir menu');
          } else {
            document.body.classList.remove('side-collapsed');
            toggleBtn.setAttribute('aria-expanded', 'true');
            toggleBtn.setAttribute('aria-label', 'Contraer menu');
            toggleBtn.setAttribute('title', 'Contraer menu');
          }
        }

        function onToggleClick() {
          var collapsed = !document.body.classList.contains('side-collapsed');
          applyCollapsed(collapsed);
          try {
            localStorage.setItem(storageKey, collapsed ? '1' : '0');
          } catch (error) {
          }
        }

        function onResize() {
          var preferredCollapsed = false;
          try {
            preferredCollapsed = localStorage.getItem(storageKey) === '1';
          } catch (error) {
            preferredCollapsed = false;
          }
          applyCollapsed(preferredCollapsed);
        }

        var startCollapsed = false;
        try {
          startCollapsed = localStorage.getItem(storageKey) === '1';
        } catch (error) {
          startCollapsed = false;
        }
        applyCollapsed(startCollapsed);
        window.requestAnimationFrame(function () {
          document.body.classList.remove('side-state-preload');
        });

        toggleBtn.addEventListener('click', onToggleClick);
        window.addEventListener('resize', onResize);

        sideToggleCleanup = function () {
          toggleBtn.removeEventListener('click', onToggleClick);
          window.removeEventListener('resize', onResize);
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

      function bindCartaGanttModule() {
        if (typeof cartaGanttCleanup === 'function') {
          cartaGanttCleanup();
          cartaGanttCleanup = null;
        }

        var root = document.querySelector('[data-gantt-root="1"]');
        if (!root) {
          return;
        }

        function readJsonFromScript(id, fallback) {
          var node = document.getElementById(id);
          if (!node) {
            return fallback;
          }
          try {
            var parsed = JSON.parse(node.textContent || '[]');
            return parsed;
          } catch (error) {
            return fallback;
          }
        }

        var orders = readJsonFromScript('ganttOrdersJson', []);
        var technicians = readJsonFromScript('ganttTechniciansJson', []);
        var board = root.querySelector('[data-gantt-board="1"]');
        var kpisWrap = root.querySelector('[data-gantt-kpis="1"]');
        var focusLabel = root.querySelector('[data-gantt-focus-label="1"]');
        var searchInput = root.querySelector('[data-gantt-filter="search"]');
        var stateSelect = root.querySelector('[data-gantt-filter="state"]');
        var techSelect = root.querySelector('[data-gantt-filter="technician"]');
        var detailWrap = root.querySelector('[data-gantt-detail="1"]');
        var detailTitle = root.querySelector('[data-gantt-detail-title="1"]');
        var detailMeta = root.querySelector('[data-gantt-detail-meta="1"]');
        var detailNote = root.querySelector('[data-gantt-detail-note="1"]');
        var detailView = root.querySelector('[data-gantt-detail-view="1"]');
        var detailAssign = root.querySelector('[data-gantt-detail-assign="1"]');
        var detailViewNew = root.querySelector('[data-gantt-detail-view-new="1"]');
        if (!board || !kpisWrap || !focusLabel || !searchInput || !stateSelect || !techSelect) {
          return;
        }

        while (techSelect.options.length > 2) {
          techSelect.remove(techSelect.options.length - 1);
        }
        technicians.forEach(function (tech) {
          var opt = document.createElement('option');
          opt.value = String(tech.id || '');
          opt.textContent = String(tech.name || ('Tecnico #' + String(tech.id || '')));
          techSelect.appendChild(opt);
        });

        var viewMode = 'week';
        var quickPreset = 'all';
        var focusDate = new Date();
        var selectedDetail = null;

        function parseDate(value) {
          var text = String(value || '').trim();
          if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) {
            return null;
          }
          var parts = text.split('-');
          return new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]));
        }

        function toIsoDate(date) {
          if (!(date instanceof Date) || isNaN(date.getTime())) {
            return '';
          }
          var y = date.getFullYear();
          var m = String(date.getMonth() + 1).padStart(2, '0');
          var d = String(date.getDate()).padStart(2, '0');
          return y + '-' + m + '-' + d;
        }

        function startOfWeek(date) {
          var d = new Date(date.getFullYear(), date.getMonth(), date.getDate());
          var day = d.getDay();
          var diff = day === 0 ? -6 : 1 - day;
          d.setDate(d.getDate() + diff);
          return d;
        }

        function addDays(date, days) {
          var d = new Date(date.getFullYear(), date.getMonth(), date.getDate());
          d.setDate(d.getDate() + Number(days || 0));
          return d;
        }

        function dayDiff(a, b) {
          var ms = b.getTime() - a.getTime();
          return Math.round(ms / 86400000);
        }

        function sameDay(a, b) {
          return toIsoDate(a) === toIsoDate(b);
        }

        function normalizeState(value) {
          return String(value || '').toLowerCase().trim();
        }

        function priorityScore(value) {
          var p = String(value || '').toLowerCase();
          if (p === 'critica' || p === 'crítica') return 1;
          if (p === 'alta') return 2;
          if (p === 'normal') return 3;
          if (p === 'baja') return 4;
          return 5;
        }

        function getRange() {
          if (viewMode === 'day') {
            var sDay = new Date(focusDate.getFullYear(), focusDate.getMonth(), focusDate.getDate());
            return { start: sDay, end: sDay, days: [sDay] };
          }
          if (viewMode === 'week') {
            var sWeek = startOfWeek(focusDate);
            var weekDays = [];
            for (var wi = 0; wi < 7; wi += 1) {
              weekDays.push(addDays(sWeek, wi));
            }
            return { start: weekDays[0], end: weekDays[6], days: weekDays };
          }
          var sMonth = new Date(focusDate.getFullYear(), focusDate.getMonth(), 1);
          var eMonth = new Date(focusDate.getFullYear(), focusDate.getMonth() + 1, 0);
          var monthDays = [];
          var cursor = new Date(sMonth.getFullYear(), sMonth.getMonth(), sMonth.getDate());
          while (cursor <= eMonth) {
            monthDays.push(new Date(cursor.getFullYear(), cursor.getMonth(), cursor.getDate()));
            cursor = addDays(cursor, 1);
          }
          return { start: sMonth, end: eMonth, days: monthDays };
        }

        function groupOrders() {
          return orders.map(function (order) {
            var byTech = {};
            var noTechDates = [];
            var asg = Array.isArray(order.assignments) ? order.assignments : [];
            asg.forEach(function (row) {
              var rowDate = parseDate(row.work_date);
              if (!rowDate) {
                return;
              }
              var techId = Number(row.technician_id || 0);
              if (techId <= 0) {
                noTechDates.push(rowDate);
                return;
              }
              if (!byTech[techId]) {
                byTech[techId] = [];
              }
              byTech[techId].push(rowDate);
            });

            var lanes = [];
            Object.keys(byTech).forEach(function (techKey) {
              var dates = byTech[techKey].slice().sort(function (a, b) {
                return a.getTime() - b.getTime();
              });
              if (!dates.length) {
                return;
              }
              lanes.push({
                technician_id: Number(techKey),
                start: dates[0],
                end: dates[dates.length - 1],
                hasDate: true,
              });
            });

            if (lanes.length === 0) {
              if (noTechDates.length) {
                noTechDates.sort(function (a, b) { return a.getTime() - b.getTime(); });
                lanes.push({
                  technician_id: 0,
                  start: noTechDates[0],
                  end: noTechDates[noTechDates.length - 1],
                  hasDate: true,
                });
              } else {
                lanes.push({
                  technician_id: 0,
                  start: null,
                  end: null,
                  hasDate: false,
                });
              }
            }

            return {
              order: order,
              lanes: lanes,
            };
          });
        }

        function intersects(range, lane) {
          if (!lane.hasDate || !lane.start || !lane.end) {
            return false;
          }
          return !(lane.end < range.start || lane.start > range.end);
        }

        function formatFocus(range) {
          var opts = { day: '2-digit', month: 'short', year: 'numeric' };
          if (viewMode === 'day') {
            return 'Vista diaria: ' + range.start.toLocaleDateString('es-CL', opts);
          }
          return 'Rango: ' + range.start.toLocaleDateString('es-CL', opts) + ' - ' + range.end.toLocaleDateString('es-CL', opts);
        }

        function calcKpis(rows, filteredRows) {
          var total = rows.length;
          var visible = filteredRows.length;
          var completed = rows.filter(function (r) {
            var st = normalizeState(r.order.estado);
            return st === 'completada' || st === 'cerrada';
          }).length;
          var active = rows.filter(function (r) {
            var st = normalizeState(r.order.estado);
            return st === 'planificada' || st === 'en-proceso';
          }).length;
          var unassigned = rows.filter(function (r) {
            return r.lanes.some(function (l) { return Number(l.technician_id || 0) === 0; });
          }).length;
          return {
            total: total,
            visible: visible,
            completed: completed,
            active: active,
            unassigned: unassigned,
          };
        }

        function renderKpis(kpis) {
          kpisWrap.innerHTML = '';
          [
            { label: 'OS totales', value: kpis.total },
            { label: 'OS visibles', value: kpis.visible },
            { label: 'Activas', value: kpis.active },
            { label: 'Cerradas/OK', value: kpis.completed },
            { label: 'Sin tecnico', value: kpis.unassigned },
          ].forEach(function (item) {
            var card = document.createElement('article');
            var strong = document.createElement('strong');
            strong.textContent = String(item.value || 0);
            var span = document.createElement('span');
            span.textContent = item.label;
            card.appendChild(strong);
            card.appendChild(span);
            kpisWrap.appendChild(card);
          });
        }

        function applyQuickPreset(rows, range) {
          var todayIso = toIsoDate(new Date());
          if (quickPreset === 'all') {
            return rows;
          }
          if (quickPreset === 'today') {
            return rows.filter(function (row) {
              return row.lanes.some(function (lane) {
                return lane.hasDate && lane.start && lane.end && toIsoDate(lane.start) <= todayIso && toIsoDate(lane.end) >= todayIso;
              });
            });
          }
          if (quickPreset === 'overdue') {
            return rows.filter(function (row) {
              return row.lanes.some(function (lane) {
                if (!lane.hasDate || !lane.end) {
                  return false;
                }
                var done = normalizeState(row.order.estado) === 'completada' || normalizeState(row.order.estado) === 'cerrada';
                return toIsoDate(lane.end) < todayIso && !done;
              });
            });
          }
          if (quickPreset === 'unassigned') {
            return rows.filter(function (row) {
              return row.lanes.some(function (lane) { return Number(lane.technician_id || 0) === 0; });
            });
          }
          if (quickPreset === 'nodate') {
            return rows.filter(function (row) {
              return row.lanes.some(function (lane) { return !lane.hasDate; });
            });
          }
          return rows;
        }

        function filterRows(rows, range) {
          var search = String(searchInput.value || '').toLowerCase().trim();
          var stateFilter = String(stateSelect.value || 'todos').toLowerCase();
          var techFilter = String(techSelect.value || 'todos').toLowerCase();

          var subset = rows.filter(function (row) {
            var order = row.order || {};
            if (stateFilter !== 'todos' && normalizeState(order.estado) !== stateFilter) {
              return false;
            }
            if (search !== '') {
              var hay = [order.codigo, order.titulo, order.customer_name, order.observaciones]
                .join(' ')
                .toLowerCase();
              if (hay.indexOf(search) === -1) {
                return false;
              }
            }

            var matchingLane = row.lanes.filter(function (lane) {
              if (techFilter === 'todos') {
                return true;
              }
              if (techFilter === 'sin-asignar') {
                return Number(lane.technician_id || 0) === 0;
              }
              return String(lane.technician_id || '') === techFilter;
            });
            if (!matchingLane.length) {
              return false;
            }

            var hasVisibleLane = matchingLane.some(function (lane) {
              if (!lane.hasDate) {
                return true;
              }
              return intersects(range, lane);
            });

            return hasVisibleLane;
          });

          return applyQuickPreset(subset, range);
        }

        function techNameById(id) {
          var n = Number(id || 0);
          if (n <= 0) {
            return 'Sin asignar';
          }
          for (var i = 0; i < technicians.length; i += 1) {
            if (Number(technicians[i].id || 0) === n) {
              return String(technicians[i].name || ('Tecnico #' + String(n)));
            }
          }
          return 'Tecnico #' + String(n);
        }

        function buildRowsByTechnician(filteredRows, range) {
          var map = {};
          filteredRows.forEach(function (row) {
            row.lanes.forEach(function (lane) {
              var key = String(lane.technician_id || 0);
              var laneStart = lane.start;
              var laneEnd = lane.end;
              var visibleStart = laneStart;
              var visibleEnd = laneEnd;
              if (lane.hasDate && laneStart && laneEnd) {
                if (!intersects(range, lane)) {
                  return;
                }
                visibleStart = laneStart < range.start ? range.start : laneStart;
                visibleEnd = laneEnd > range.end ? range.end : laneEnd;
              }
              if (!map[key]) {
                map[key] = [];
              }
              map[key].push({
                order: row.order,
                lane: lane,
                visibleStart: visibleStart,
                visibleEnd: visibleEnd,
              });
            });
          });

          var techIds = Object.keys(map).sort(function (a, b) {
            if (a === '0') return 1;
            if (b === '0') return -1;
            return techNameById(a).localeCompare(techNameById(b), 'es');
          });

          return techIds.map(function (techId) {
            var items = map[techId].sort(function (x, y) {
              var sx = x.visibleStart ? x.visibleStart.getTime() : Number.MAX_SAFE_INTEGER;
              var sy = y.visibleStart ? y.visibleStart.getTime() : Number.MAX_SAFE_INTEGER;
              if (sx !== sy) {
                return sx - sy;
              }
              return priorityScore(x.order.prioridad) - priorityScore(y.order.prioridad);
            });

            var lanesEnd = [];
            items.forEach(function (item) {
              var placed = false;
              for (var i = 0; i < lanesEnd.length; i += 1) {
                var laneEnd = lanesEnd[i];
                var itemStartMs = item.visibleStart ? item.visibleStart.getTime() : Number.MAX_SAFE_INTEGER;
                if (itemStartMs > laneEnd) {
                  item.row = i;
                  lanesEnd[i] = item.visibleEnd ? item.visibleEnd.getTime() : Number.MAX_SAFE_INTEGER;
                  placed = true;
                  break;
                }
              }
              if (!placed) {
                item.row = lanesEnd.length;
                lanesEnd.push(item.visibleEnd ? item.visibleEnd.getTime() : Number.MAX_SAFE_INTEGER);
              }
            });

            return {
              technicianId: Number(techId || 0),
              technicianName: techNameById(techId),
              items: items,
              lanes: Math.max(1, lanesEnd.length),
            };
          });
        }

        async function openOrderInSpa(order, openAssignQuick) {
          if (!order || !order.id) {
            return;
          }
          var targetUrl = new URL('/empresa/dashboard/?module=ordenes-servicio', window.location.origin);
          await navigateSpa(targetUrl, true);

          var soId = String(order.id || '');
          var detailBtn = document.querySelector('[data-so-toggle-detail="1"][data-so-id="' + soId + '"]');
          if (detailBtn && !detailBtn.classList.contains('active')) {
            detailBtn.click();
          }

          if (openAssignQuick) {
            var assignBtn = document.querySelector('[data-open-so-assign="1"][data-so-id="' + soId + '"]');
            if (assignBtn) {
              assignBtn.click();
            }
          }

          if (!detailBtn) {
            var fallbackUrl = new URL('/empresa/dashboard/?module=ordenes-servicio&view_service_order_id=' + encodeURIComponent(soId), window.location.origin);
            await navigateSpa(fallbackUrl, true);
          }
        }

        function showDetail(item) {
          selectedDetail = item;
          if (!detailWrap || !detailTitle || !detailMeta || !detailNote || !detailView || !detailViewNew || !detailAssign) {
            return;
          }
          var order = item.order || {};
          var title = (order.codigo ? String(order.codigo) + ' - ' : '') + String(order.titulo || 'Orden de servicio');
          detailTitle.textContent = title;
          detailMeta.textContent = [
            'Estado: ' + String(order.estado || 'Sin estado'),
            'Prioridad: ' + String(order.prioridad || 'normal'),
            'Tecnico: ' + techNameById(item.lane.technician_id),
            'Cliente: ' + String(order.customer_name || 'Sin cliente')
          ].join(' | ');
          detailNote.textContent = String(order.observaciones || 'Sin observaciones adicionales.');
          detailView.setAttribute('data-view-url', String(order.view_url || '#'));
          detailView.setAttribute('data-order-id', String(order.id || ''));
          detailAssign.setAttribute('data-order-id', String(order.id || ''));
          detailViewNew.href = String(order.view_url || '#');
          detailWrap.hidden = false;
        }

        function renderBoard(rowsByTech, range) {
          board.innerHTML = '';
          var dayCount = range.days.length;

          if (!rowsByTech.length) {
            var empty = document.createElement('div');
            empty.className = 'gantt-empty';
            empty.textContent = 'No hay OS que coincidan con los filtros actuales.';
            board.appendChild(empty);
            return;
          }

          var head = document.createElement('div');
          head.className = 'gantt-head';
          var headTech = document.createElement('div');
          headTech.className = 'gantt-head-tech';
          headTech.textContent = 'Tecnico';
          var headDays = document.createElement('div');
          headDays.className = 'gantt-head-days';
          headDays.style.gridTemplateColumns = 'repeat(' + String(dayCount) + ', minmax(34px,1fr))';
          range.days.forEach(function (day) {
            var c = document.createElement('div');
            c.className = 'gantt-day-head';
            c.innerHTML = '<strong>' + day.toLocaleDateString('es-CL', { weekday: 'short' }) + '</strong><span>' + day.toLocaleDateString('es-CL', { day: '2-digit', month: '2-digit' }) + '</span>';
            headDays.appendChild(c);
          });
          head.appendChild(headTech);
          head.appendChild(headDays);
          board.appendChild(head);

          rowsByTech.forEach(function (techRow) {
            var row = document.createElement('div');
            row.className = 'gantt-row';

            var techCell = document.createElement('div');
            techCell.className = 'gantt-tech';
            techCell.style.minHeight = String(techRow.lanes * 36) + 'px';
            techCell.innerHTML = '<strong>' + techRow.technicianName + '</strong><span>' + String(techRow.items.length) + ' OS</span>';

            var track = document.createElement('div');
            track.className = 'gantt-track';
            track.style.gridTemplateColumns = 'repeat(' + String(dayCount) + ', minmax(34px,1fr))';
            track.style.gridTemplateRows = 'repeat(' + String(techRow.lanes) + ', 36px)';

            for (var di = 0; di < dayCount * techRow.lanes; di += 1) {
              var cell = document.createElement('div');
              cell.className = 'gantt-cell';
              track.appendChild(cell);
            }

            techRow.items.forEach(function (item) {
              if (!item.visibleStart || !item.visibleEnd) {
                return;
              }
              var sOffset = Math.max(0, dayDiff(range.start, item.visibleStart));
              var eOffset = Math.max(sOffset, dayDiff(range.start, item.visibleEnd));
              var bar = document.createElement('button');
              var state = normalizeState(item.order.estado).replace(/[^a-z0-9]+/g, '-');
              bar.className = 'gantt-bar ' + (state || 'default');
              bar.type = 'button';
              bar.textContent = String(item.order.codigo || ('OS #' + String(item.order.id || '')));
              bar.style.gridColumn = String(sOffset + 1) + ' / ' + String(eOffset + 2);
              bar.style.gridRow = String((item.row || 0) + 1);
              bar.title = String(item.order.titulo || 'Orden de servicio');
              bar.addEventListener('click', function () {
                void openOrderInSpa(item.order, false);
              });
              track.appendChild(bar);
            });

            row.appendChild(techCell);
            row.appendChild(track);
            board.appendChild(row);
          });
        }

        function paintActiveChips() {
          var viewButtons = root.querySelectorAll('[data-gantt-view]');
          viewButtons.forEach(function (btn) {
            btn.classList.toggle('active', String(btn.getAttribute('data-gantt-view') || '') === viewMode);
          });
          var quickButtons = root.querySelectorAll('[data-gantt-quick-preset]');
          quickButtons.forEach(function (btn) {
            btn.classList.toggle('active', String(btn.getAttribute('data-gantt-quick-preset') || '') === quickPreset);
          });
        }

        function render() {
          paintActiveChips();
          var range = getRange();
          focusLabel.textContent = formatFocus(range);
          var grouped = groupOrders();
          var filtered = filterRows(grouped, range);
          renderKpis(calcKpis(grouped, filtered));
          var rowsByTech = buildRowsByTechnician(filtered, range);
          renderBoard(rowsByTech, range);

          if (selectedDetail) {
            var stillExists = filtered.some(function (row) {
              return Number(row.order.id || 0) === Number(selectedDetail.order.id || 0);
            });
            if (!stillExists && detailWrap) {
              detailWrap.hidden = true;
            }
          }
        }

        function onViewClick(event) {
          var button = event.currentTarget;
          viewMode = String(button.getAttribute('data-gantt-view') || 'week');
          render();
        }

        function onNavClick(event) {
          var action = String(event.currentTarget.getAttribute('data-gantt-nav') || 'today');
          if (action === 'today') {
            focusDate = new Date();
            render();
            return;
          }
          if (viewMode === 'day') {
            focusDate = addDays(focusDate, action === 'next' ? 1 : -1);
          } else if (viewMode === 'week') {
            focusDate = addDays(focusDate, action === 'next' ? 7 : -7);
          } else {
            focusDate = new Date(focusDate.getFullYear(), focusDate.getMonth() + (action === 'next' ? 1 : -1), 1);
          }
          render();
        }

        function onQuickClick(event) {
          quickPreset = String(event.currentTarget.getAttribute('data-gantt-quick-preset') || 'all');
          render();
        }

        function onDetailViewClick(event) {
          event.preventDefault();
          if (!selectedDetail || !selectedDetail.order) {
            return;
          }
          void openOrderInSpa(selectedDetail.order, false);
        }

        function onDetailAssignClick(event) {
          event.preventDefault();
          if (!selectedDetail || !selectedDetail.order) {
            return;
          }
          void openOrderInSpa(selectedDetail.order, true);
        }

        var viewButtons = Array.prototype.slice.call(root.querySelectorAll('[data-gantt-view]'));
        var navButtons = Array.prototype.slice.call(root.querySelectorAll('[data-gantt-nav]'));
        var quickButtons = Array.prototype.slice.call(root.querySelectorAll('[data-gantt-quick-preset]'));

        viewButtons.forEach(function (btn) {
          btn.addEventListener('click', onViewClick);
        });
        navButtons.forEach(function (btn) {
          btn.addEventListener('click', onNavClick);
        });
        quickButtons.forEach(function (btn) {
          btn.addEventListener('click', onQuickClick);
        });
        searchInput.addEventListener('input', render);
        stateSelect.addEventListener('change', render);
        techSelect.addEventListener('change', render);
        if (detailView) {
          detailView.addEventListener('click', onDetailViewClick);
        }
        if (detailAssign) {
          detailAssign.addEventListener('click', onDetailAssignClick);
        }

        render();

        cartaGanttCleanup = function () {
          viewButtons.forEach(function (btn) {
            btn.removeEventListener('click', onViewClick);
          });
          navButtons.forEach(function (btn) {
            btn.removeEventListener('click', onNavClick);
          });
          quickButtons.forEach(function (btn) {
            btn.removeEventListener('click', onQuickClick);
          });
          searchInput.removeEventListener('input', render);
          stateSelect.removeEventListener('change', render);
          techSelect.removeEventListener('change', render);
          if (detailView) {
            detailView.removeEventListener('click', onDetailViewClick);
          }
          if (detailAssign) {
            detailAssign.removeEventListener('click', onDetailAssignClick);
          }
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

      function bindInventoryHistoryModal() {
        if (typeof inventoryHistoryModalCleanup === 'function') {
          inventoryHistoryModalCleanup();
          inventoryHistoryModalCleanup = null;
        }

        var modal = document.getElementById('inventoryHistoryModal');
        if (!modal) {
          return;
        }

        var openButtons = document.querySelectorAll('[data-open-inventory-history-modal="1"]');
        var closeButtons = modal.querySelectorAll('[data-close-inventory-history-modal="1"]');

        function openModal() {
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }

        function closeModal() {
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
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

        openButtons.forEach(function (button) {
          button.addEventListener('click', openModal);
        });
        closeButtons.forEach(function (button) {
          button.addEventListener('click', closeModal);
        });
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);

        inventoryHistoryModalCleanup = function () {
          openButtons.forEach(function (button) {
            button.removeEventListener('click', openModal);
          });
          closeButtons.forEach(function (button) {
            button.removeEventListener('click', closeModal);
          });
          modal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
        };
      }

      function bindServiceOrderModal() {
        if (typeof serviceOrderModalCleanup === 'function') {
          serviceOrderModalCleanup();
          serviceOrderModalCleanup = null;
        }
        var modal = document.getElementById('serviceOrderModal');
        if (!modal) { return; }

        var openButtons = document.querySelectorAll('[data-open-service-order-modal="1"]');
        var editButtons = document.querySelectorAll('[data-edit-service-order="1"]');
        var closeButtons = modal.querySelectorAll('[data-close-service-order-modal="1"]');
        var form = modal.querySelector('#serviceOrderModalForm');
        var titleEl = modal.querySelector('#serviceOrderModalTitle');
        var actionInput = modal.querySelector('[data-so-action="1"]');
        var idInput = modal.querySelector('[data-so-id="1"]');
        var asgContainer = modal.querySelector('[data-so-assignments-container="1"]');
        var partsContainer = modal.querySelector('[data-so-parts-container="1"]');
        var checklistContainer = modal.querySelector('[data-so-checklist-container="1"]');
        var addAsgBtn = modal.querySelector('[data-so-add-assignment="1"]');
        var addPartBtn = modal.querySelector('[data-so-add-part="1"]');
        var addChkBtn = modal.querySelector('[data-so-add-checklist="1"]');
        var techOptsTpl = modal.querySelector('[data-so-tech-options="1"]');
        var invOptsTpl = modal.querySelector('[data-so-inv-options="1"]');
        var formTemplateChecks = modal.querySelectorAll('[data-so-template-check="1"]');

        function techOptionsHTML() { return techOptsTpl ? techOptsTpl.innerHTML : '<option value="">--</option>'; }
        function invOptionsHTML() { return invOptsTpl ? invOptsTpl.innerHTML : '<option value="">--</option>'; }

        function addAssignmentRow(data) {
          data = data || {};
          var row = document.createElement('div');
          row.className = 'so-row so-row-assign';
          row.innerHTML = ''
            + '<div class="field"><label>Tecnico</label><select name="assignments[][technician_id]" data-so-asg-tech="1" required>' + techOptionsHTML() + '</select></div>'
            + '<div class="field"><label>Fecha</label><input type="date" name="assignments[][work_date]" data-so-asg-date="1" required></div>'
            + '<div class="field"><label>Inicio</label><input type="time" name="assignments[][start_time]" data-so-asg-start="1"></div>'
            + '<div class="field"><label>Fin</label><input type="time" name="assignments[][end_time]" data-so-asg-end="1"></div>'
            + '<div class="field"><label>Notas</label><input type="text" name="assignments[][notas]" data-so-asg-notas="1" maxlength="255"></div>'
            + '<button type="button" class="so-row-remove" data-so-row-remove="1" title="Quitar" aria-label="Quitar">x</button>';
          asgContainer.appendChild(row);
          if (data.technician_id) { row.querySelector('[data-so-asg-tech="1"]').value = String(data.technician_id); }
          if (data.work_date) { row.querySelector('[data-so-asg-date="1"]').value = String(data.work_date); }
          if (data.start_time) { row.querySelector('[data-so-asg-start="1"]').value = String(data.start_time); }
          if (data.end_time) { row.querySelector('[data-so-asg-end="1"]').value = String(data.end_time); }
          if (data.notas) { row.querySelector('[data-so-asg-notas="1"]').value = String(data.notas); }
        }
        function addPartRow(data) {
          data = data || {};
          var row = document.createElement('div');
          row.className = 'so-row so-row-part';
          row.innerHTML = ''
            + '<div class="field"><label>Item inventario</label><select name="parts[][inventory_item_id]" data-so-part-inv="1">' + invOptionsHTML() + '</select></div>'
            + '<div class="field"><label>SKU</label><input type="text" name="parts[][sku]" data-so-part-sku="1" maxlength="90"></div>'
            + '<div class="field"><label>Nombre</label><input type="text" name="parts[][nombre]" data-so-part-nombre="1" maxlength="190"></div>'
            + '<div class="field"><label>Unidad</label><input type="text" name="parts[][unidad]" data-so-part-unidad="1" maxlength="40" value="unidad"></div>'
            + '<div class="field"><label>Cantidad</label><input type="number" min="0" step="0.01" name="parts[][cantidad]" data-so-part-cant="1" value="1"></div>'
            + '<div class="field"><label>Notas</label><input type="text" name="parts[][notas]" data-so-part-notas="1" maxlength="255"></div>'
            + '<button type="button" class="so-row-remove" data-so-row-remove="1" title="Quitar" aria-label="Quitar">x</button>';
          partsContainer.appendChild(row);
          var invSel = row.querySelector('[data-so-part-inv="1"]');
          var skuI = row.querySelector('[data-so-part-sku="1"]');
          var nomI = row.querySelector('[data-so-part-nombre="1"]');
          var uniI = row.querySelector('[data-so-part-unidad="1"]');
          invSel.addEventListener('change', function () {
            var opt = invSel.options[invSel.selectedIndex];
            if (opt && opt.value) {
              skuI.value = opt.getAttribute('data-sku') || '';
              nomI.value = opt.getAttribute('data-nombre') || '';
              uniI.value = opt.getAttribute('data-unidad') || 'unidad';
            }
          });
          if (data.inventory_item_id) { invSel.value = String(data.inventory_item_id); }
          if (data.sku) { skuI.value = String(data.sku); }
          if (data.nombre) { nomI.value = String(data.nombre); }
          if (data.unidad) { uniI.value = String(data.unidad); }
          if (data.cantidad !== undefined && data.cantidad !== '') { row.querySelector('[data-so-part-cant="1"]').value = String(data.cantidad); }
          if (data.notas) { row.querySelector('[data-so-part-notas="1"]').value = String(data.notas); }
        }
        function addChecklistRow(data) {
          data = data || {};
          var row = document.createElement('div');
          row.className = 'so-row so-row-chk';
          row.innerHTML = ''
            + '<label class="so-chk-toggle"><input type="checkbox" name="checklist[][completado]" value="1" data-so-chk-done="1"> Hecho</label>'
            + '<div class="field"><input type="text" name="checklist[][descripcion]" data-so-chk-desc="1" placeholder="Descripcion del item de checklist" maxlength="255" required></div>'
            + '<button type="button" class="so-row-remove" data-so-row-remove="1" title="Quitar" aria-label="Quitar">x</button>';
          checklistContainer.appendChild(row);
          if (data.descripcion) { row.querySelector('[data-so-chk-desc="1"]').value = String(data.descripcion); }
          if (String(data.completado || '0') === '1') { row.querySelector('[data-so-chk-done="1"]').checked = true; }
        }

        function clearRows() {
          asgContainer.innerHTML = '';
          partsContainer.innerHTML = '';
          checklistContainer.innerHTML = '';
        }
        function setMode(isEdit) {
          if (actionInput) { actionInput.value = isEdit ? 'update_service_order' : 'add_service_order'; }
          if (titleEl) { titleEl.textContent = isEdit ? 'Editar orden de servicio' : 'Nueva orden de servicio'; }
        }
        function fillForm(data) {
          data = data || {};
          if (idInput) { idInput.value = data.id ? String(data.id) : ''; }
          var f = function (name) { return form.querySelector('[name="' + name + '"]'); };
          if (f('customer_id')) { f('customer_id').value = data.customer_id ? String(data.customer_id) : ''; }
          if (f('codigo')) { f('codigo').value = data.codigo || ''; }
          if (f('titulo')) { f('titulo').value = data.titulo || ''; }
          if (f('descripcion')) { f('descripcion').value = data.descripcion || ''; }
          if (f('estado')) { f('estado').value = data.estado || 'borrador'; }
          if (f('prioridad')) { f('prioridad').value = data.prioridad || 'normal'; }
          if (f('fecha_creacion')) { f('fecha_creacion').value = data.fecha_creacion || ''; }
          if (f('observaciones')) { f('observaciones').value = data.observaciones || ''; }
          var selectedTpl = Array.isArray(data.form_template_ids) ? data.form_template_ids.map(function (id) { return String(id); }) : [];
          Array.prototype.slice.call(formTemplateChecks || []).forEach(function (chk) {
            chk.checked = selectedTpl.indexOf(String(chk.value || '')) >= 0;
          });
          clearRows();
          var asg = Array.isArray(data.assignments) ? data.assignments : [];
          if (asg.length === 0) { addAssignmentRow({}); } else { asg.forEach(addAssignmentRow); }
          var pts = Array.isArray(data.parts) ? data.parts : [];
          if (pts.length === 0) { addPartRow({}); } else { pts.forEach(addPartRow); }
          var chk = Array.isArray(data.checklist) ? data.checklist : [];
          if (chk.length === 0) { addChecklistRow({}); } else { chk.forEach(addChecklistRow); }
        }
        function openModalNew() {
          setMode(false);
          fillForm({});
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }
        function openModalEdit(button) {
          var payload = button.getAttribute('data-so-payload') || '{}';
          var data = {};
          try { data = JSON.parse(payload); } catch (e) { data = {}; }
          setMode(true);
          fillForm(data);
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }
        function closeModal() {
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
        }
        function onContainerClick(event) {
          var rm = event.target.closest('[data-so-row-remove="1"]');
          if (rm) {
            var row = rm.closest('.so-row');
            if (row) { row.parentNode.removeChild(row); }
          }
        }
        async function onFormSubmit(event) {
          event.preventDefault();
          // ajustar names: convertir parts[][field] a parts[idx][field]
          var fd = new FormData();
          var csrf = form.querySelector('[name="csrf_token"]');
          if (csrf) { fd.append('csrf_token', csrf.value); }
          fd.append('action', actionInput.value);
          fd.append('service_order_id', idInput.value || '');
          ['customer_id','codigo','titulo','descripcion','estado','prioridad','fecha_creacion','observaciones'].forEach(function (n) {
            var el = form.querySelector('[name="' + n + '"]');
            if (el) { fd.append(n, el.value); }
          });
          Array.prototype.slice.call(formTemplateChecks || []).forEach(function (chk) {
            if (chk.checked) {
              fd.append('form_template_ids[]', chk.value || '');
            }
          });
          var asgRows = asgContainer.querySelectorAll('.so-row');
          asgRows.forEach(function (row, idx) {
            fd.append('assignments[' + idx + '][technician_id]', row.querySelector('[data-so-asg-tech="1"]').value || '');
            fd.append('assignments[' + idx + '][work_date]', row.querySelector('[data-so-asg-date="1"]').value || '');
            fd.append('assignments[' + idx + '][start_time]', row.querySelector('[data-so-asg-start="1"]').value || '');
            fd.append('assignments[' + idx + '][end_time]', row.querySelector('[data-so-asg-end="1"]').value || '');
            fd.append('assignments[' + idx + '][notas]', row.querySelector('[data-so-asg-notas="1"]').value || '');
          });
          var partRows = partsContainer.querySelectorAll('.so-row');
          partRows.forEach(function (row, idx) {
            fd.append('parts[' + idx + '][inventory_item_id]', row.querySelector('[data-so-part-inv="1"]').value || '');
            fd.append('parts[' + idx + '][sku]', row.querySelector('[data-so-part-sku="1"]').value || '');
            fd.append('parts[' + idx + '][nombre]', row.querySelector('[data-so-part-nombre="1"]').value || '');
            fd.append('parts[' + idx + '][unidad]', row.querySelector('[data-so-part-unidad="1"]').value || 'unidad');
            fd.append('parts[' + idx + '][cantidad]', row.querySelector('[data-so-part-cant="1"]').value || '1');
            fd.append('parts[' + idx + '][notas]', row.querySelector('[data-so-part-notas="1"]').value || '');
          });
          var chkRows = checklistContainer.querySelectorAll('.so-row');
          chkRows.forEach(function (row, idx) {
            fd.append('checklist[' + idx + '][descripcion]', row.querySelector('[data-so-chk-desc="1"]').value || '');
            fd.append('checklist[' + idx + '][completado]', row.querySelector('[data-so-chk-done="1"]').checked ? '1' : '0');
          });
          try {
            await postTechnicianAjax(fd);
            closeModal();
          } catch (error) {
            window.alert(error && error.message ? error.message : 'No se pudo guardar la orden de servicio.');
          }
        }
        function onBackdropClick(event) { if (event.target === modal) { closeModal(); } }
        function onEsc(event) { if (event.key === 'Escape' && modal.classList.contains('open')) { closeModal(); } }
        function onNewClick() { openModalNew(); }
        function onEditClick(event) { openModalEdit(event.currentTarget); }

        openButtons.forEach(function (b) { b.addEventListener('click', onNewClick); });
        editButtons.forEach(function (b) { b.addEventListener('click', onEditClick); });
        closeButtons.forEach(function (b) { b.addEventListener('click', closeModal); });
        if (addAsgBtn) { addAsgBtn.addEventListener('click', function () { addAssignmentRow({}); }); }
        if (addPartBtn) { addPartBtn.addEventListener('click', function () { addPartRow({}); }); }
        if (addChkBtn) { addChkBtn.addEventListener('click', function () { addChecklistRow({}); }); }
        if (asgContainer) { asgContainer.addEventListener('click', onContainerClick); }
        if (partsContainer) { partsContainer.addEventListener('click', onContainerClick); }
        if (checklistContainer) { checklistContainer.addEventListener('click', onContainerClick); }
        if (form) { form.addEventListener('submit', onFormSubmit); }
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);

        // si el modal viene abierto por postback (error de validacion), poblar con valores actuales:
        if (modal.classList.contains('open')) {
          // los <input>/<select>/textarea ya tienen valores via PHP. solo necesitamos al menos una fila si esta vacio.
          if (asgContainer.children.length === 0) { addAssignmentRow({}); }
          if (partsContainer.children.length === 0) { addPartRow({}); }
          if (checklistContainer.children.length === 0) { addChecklistRow({}); }
        }

        serviceOrderModalCleanup = function () {
          openButtons.forEach(function (b) { b.removeEventListener('click', onNewClick); });
          editButtons.forEach(function (b) { b.removeEventListener('click', onEditClick); });
          closeButtons.forEach(function (b) { b.removeEventListener('click', closeModal); });
          if (form) { form.removeEventListener('submit', onFormSubmit); }
          modal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
        };
      }

      function bindServiceOrderListInteractions() {
        if (typeof serviceOrderListCleanup === 'function') {
          serviceOrderListCleanup();
          serviceOrderListCleanup = null;
        }

        var detailButtons = document.querySelectorAll('[data-so-toggle-detail="1"]');
        var checklistToggles = document.querySelectorAll('[data-so-check-toggle="1"]');
        if (!detailButtons.length && !checklistToggles.length) {
          return;
        }

        function toggleDetail(event) {
          var button = event.currentTarget;
          var soId = button.getAttribute('data-so-id') || '';
          if (!soId) {
            return;
          }
          var row = document.querySelector('[data-so-detail-row="' + soId + '"]');
          if (!row) {
            return;
          }
          var isHidden = row.hasAttribute('hidden');
          if (isHidden) {
            row.removeAttribute('hidden');
            button.classList.add('active');
            button.setAttribute('title', 'Ocultar detalle');
            button.setAttribute('aria-label', 'Ocultar detalle');
          } else {
            row.setAttribute('hidden', 'hidden');
            button.classList.remove('active');
            button.setAttribute('title', 'Ver detalle');
            button.setAttribute('aria-label', 'Ver detalle');
          }
        }

        async function onChecklistToggle(event) {
          var checkbox = event.currentTarget;
          var checklistId = checkbox.getAttribute('data-checklist-id') || '';
          if (!checklistId) {
            return;
          }
          var previous = !checkbox.checked;
          checkbox.disabled = true;
          var formData = new FormData();
          var csrfToken = '';
          var deleteModal = document.getElementById('deleteConfirmModal');
          if (deleteModal) {
            csrfToken = deleteModal.getAttribute('data-delete-csrf-token') || '';
          }
          if (csrfToken === '') {
            var csrfInput = document.querySelector('#serviceOrderModalForm input[name="csrf_token"]');
            if (csrfInput) {
              csrfToken = csrfInput.value || '';
            }
          }
          if (csrfToken !== '') {
            formData.append('csrf_token', csrfToken);
          }
          formData.append('action', 'toggle_service_order_checklist');
          formData.append('checklist_item_id', checklistId);
          formData.append('completado', checkbox.checked ? '1' : '0');
          try {
            await postTechnicianAjax(formData);
          } catch (error) {
            checkbox.checked = previous;
            checkbox.disabled = false;
            window.alert(error && error.message ? error.message : 'No se pudo actualizar el checklist.');
          }
        }

        detailButtons.forEach(function (button) {
          button.addEventListener('click', toggleDetail);
        });
        checklistToggles.forEach(function (input) {
          input.addEventListener('change', onChecklistToggle);
        });

        serviceOrderListCleanup = function () {
          detailButtons.forEach(function (button) {
            button.removeEventListener('click', toggleDetail);
          });
          checklistToggles.forEach(function (input) {
            input.removeEventListener('change', onChecklistToggle);
          });
        };
      }

      function bindServiceOrderAssignQuickModal() {
        if (typeof serviceOrderAssignModalCleanup === 'function') {
          serviceOrderAssignModalCleanup();
          serviceOrderAssignModalCleanup = null;
        }

        var modal = document.getElementById('serviceOrderAssignModal');
        if (!modal) {
          return;
        }

        var openButtons = document.querySelectorAll('[data-open-so-assign="1"]');
        var closeButtons = modal.querySelectorAll('[data-close-so-assign-modal="1"]');
        var form = modal.querySelector('#serviceOrderAssignForm');
        var idInput = modal.querySelector('[data-so-assign-id="1"]');
        var meta = modal.querySelector('[data-so-assign-meta="1"]');
        var container = modal.querySelector('[data-so-assign-container="1"]');
        var addButton = modal.querySelector('[data-so-assign-add="1"]');
        var techOptionsTpl = modal.querySelector('[data-so-assign-tech-options="1"]');

        if (!form || !idInput || !container || !addButton) {
          return;
        }

        function techOptionsHTML() {
          return techOptionsTpl ? techOptionsTpl.innerHTML : '<option value="">Selecciona tecnico</option>';
        }

        function addRow(data) {
          data = data || {};
          var row = document.createElement('div');
          row.className = 'so-row so-row-assign';
          row.innerHTML = ''
            + '<div class="field"><label>Tecnico</label><select data-so-qa-tech="1" required>' + techOptionsHTML() + '</select></div>'
            + '<div class="field"><label>Fecha</label><input type="date" data-so-qa-date="1" required></div>'
            + '<div class="field"><label>Inicio</label><input type="time" data-so-qa-start="1"></div>'
            + '<div class="field"><label>Fin</label><input type="time" data-so-qa-end="1"></div>'
            + '<div class="field"><label>Notas</label><input type="text" data-so-qa-notas="1" maxlength="255"></div>'
            + '<button type="button" class="so-row-remove" data-so-qa-remove="1" title="Quitar" aria-label="Quitar">x</button>';
          container.appendChild(row);

          if (data.technician_id) row.querySelector('[data-so-qa-tech="1"]').value = String(data.technician_id);
          if (data.work_date) row.querySelector('[data-so-qa-date="1"]').value = String(data.work_date);
          if (data.start_time) row.querySelector('[data-so-qa-start="1"]').value = String(data.start_time);
          if (data.end_time) row.querySelector('[data-so-qa-end="1"]').value = String(data.end_time);
          if (data.notas) row.querySelector('[data-so-qa-notas="1"]').value = String(data.notas);
        }

        function clearRows() {
          container.innerHTML = '';
        }

        function openModal(payload) {
          payload = payload || {};
          idInput.value = payload.id ? String(payload.id) : '';
          if (meta) {
            var code = payload.codigo || '';
            var title = payload.titulo || '';
            meta.textContent = code !== '' ? (code + ' - ' + title) : title;
          }
          clearRows();
          var assignments = Array.isArray(payload.assignments) ? payload.assignments : [];
          if (assignments.length === 0) {
            addRow({});
          } else {
            assignments.forEach(addRow);
          }
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }

        function closeModal() {
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
        }

        function onOpenClick(event) {
          var button = event.currentTarget;
          var raw = button.getAttribute('data-so-assign-payload') || '{}';
          var payload = {};
          try {
            payload = JSON.parse(raw);
          } catch (e) {
            payload = {};
          }
          openModal(payload);
        }

        function onContainerClick(event) {
          var remove = event.target.closest('[data-so-qa-remove="1"]');
          if (!remove) {
            return;
          }
          var row = remove.closest('.so-row');
          if (row) {
            row.parentNode.removeChild(row);
          }
          if (!container.querySelector('.so-row')) {
            addRow({});
          }
        }

        async function onSubmit(event) {
          event.preventDefault();
          var fd = new FormData();
          var csrfField = form.querySelector('[name="csrf_token"]');
          if (csrfField && csrfField.value) {
            fd.append('csrf_token', csrfField.value);
          }
          fd.append('action', 'save_service_order_assignments');
          fd.append('service_order_id', idInput.value || '');

          var rows = container.querySelectorAll('.so-row');
          rows.forEach(function (row, idx) {
            fd.append('assignments[' + idx + '][technician_id]', row.querySelector('[data-so-qa-tech="1"]').value || '');
            fd.append('assignments[' + idx + '][work_date]', row.querySelector('[data-so-qa-date="1"]').value || '');
            fd.append('assignments[' + idx + '][start_time]', row.querySelector('[data-so-qa-start="1"]').value || '');
            fd.append('assignments[' + idx + '][end_time]', row.querySelector('[data-so-qa-end="1"]').value || '');
            fd.append('assignments[' + idx + '][notas]', row.querySelector('[data-so-qa-notas="1"]').value || '');
          });

          try {
            await postTechnicianAjax(fd);
            closeModal();
          } catch (error) {
            window.alert(error && error.message ? error.message : 'No se pudieron guardar las asignaciones.');
          }
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

        openButtons.forEach(function (button) {
          button.addEventListener('click', onOpenClick);
        });
        closeButtons.forEach(function (button) {
          button.addEventListener('click', closeModal);
        });
        addButton.addEventListener('click', function () { addRow({}); });
        container.addEventListener('click', onContainerClick);
        form.addEventListener('submit', onSubmit);
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);

        serviceOrderAssignModalCleanup = function () {
          openButtons.forEach(function (button) {
            button.removeEventListener('click', onOpenClick);
          });
          closeButtons.forEach(function (button) {
            button.removeEventListener('click', closeModal);
          });
          container.removeEventListener('click', onContainerClick);
          form.removeEventListener('submit', onSubmit);
          modal.removeEventListener('click', onBackdropClick);
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
            'descuento_pct', 'validez_override', 'entrega_override', 'condicion_de_pago_override',
            'moneda_override', 'terminos_condiciones_adicionales', 'observaciones'
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
          var itemType = String(data.tipo || 'normal').toLowerCase() === 'text' ? 'text' : 'normal';
          var qty = Object.prototype.hasOwnProperty.call(data, 'cantidad') ? String(data.cantidad) : '1';
          var price = Object.prototype.hasOwnProperty.call(data, 'precio') ? String(data.precio) : '0';
          if (itemType !== 'text') {
            if (qty.trim() === '' || Number(qty) <= 0) {
              qty = '1';
            }
            if (price.trim() === '' || !isFinite(Number(price)) || Number(price) < 0) {
              price = '0';
            }
          }
          var isBold = String(data.negrita || '0') === '1';
          var tr = document.createElement('tr');
          tr.setAttribute('data-item-row', '1');
          tr.setAttribute('data-item-type', itemType);
          tr.setAttribute('data-item-bold', isBold ? '1' : '0');
          tr.innerHTML = [
            '<td>' +
              '<input type="text" name="item_descripcion[]" value="' + escapeHtml(desc) + '" data-item-descripcion="1" required>' +
              '<input type="hidden" name="item_tipo[]" value="' + escapeHtml(itemType) + '" data-item-type-input="1">' +
              '<input type="hidden" name="item_negrita[]" value="' + (isBold ? '1' : '0') + '" data-item-bold-input="1">' +
            '</td>',
            '<td>' +
              '<input type="number" name="item_cantidad[]" value="' + escapeHtml(qty) + '" min="0.01" step="0.01" data-item-cantidad="1" required>' +
              '<span class="item-dash" data-item-dash="qty" style="display:none;">-</span>' +
            '</td>',
            '<td>' +
              '<input type="number" name="item_precio[]" value="' + escapeHtml(price) + '" min="0" step="0.01" data-item-precio="1" required>' +
              '<span class="item-dash" data-item-dash="price" style="display:none;">-</span>' +
            '</td>',
            '<td><span class="line-total" data-line-total="1">$0</span></td>',
            '<td>' +
              '<div class="item-style-tools">' +
                '<button class="btn item-style-btn' + (isBold ? ' active' : '') + '" type="button" data-item-bold-toggle="1" title="Negrita">N</button>' +
                '<button class="btn item-style-btn' + (itemType === 'text' ? ' active' : '') + '" type="button" data-item-type-toggle="1" title="Texto sin precio">T</button>' +
              '</div>' +
            '</td>',
            '<td><button class="btn danger" type="button" data-quote-remove-item="1">X</button></td>'
          ].join('');
          syncItemRowState(tr);
          return tr;
        }

        function syncItemRowState(row) {
          if (!row) {
            return;
          }
          var typeInput = row.querySelector('[data-item-type-input="1"]');
          var boldInput = row.querySelector('[data-item-bold-input="1"]');
          var qtyInput = row.querySelector('[data-item-cantidad="1"]');
          var priceInput = row.querySelector('[data-item-precio="1"]');
          var qtyDash = row.querySelector('[data-item-dash="qty"]');
          var priceDash = row.querySelector('[data-item-dash="price"]');
          var boldBtn = row.querySelector('[data-item-bold-toggle="1"]');
          var typeBtn = row.querySelector('[data-item-type-toggle="1"]');

          var itemType = typeInput && String(typeInput.value).toLowerCase() === 'text' ? 'text' : 'normal';
          var isBold = boldInput && String(boldInput.value) === '1';

          row.setAttribute('data-item-type', itemType);
          row.setAttribute('data-item-bold', isBold ? '1' : '0');

          if (qtyInput) {
            qtyInput.disabled = false;
            qtyInput.readOnly = itemType === 'text';
            qtyInput.required = itemType !== 'text';
            qtyInput.style.display = itemType === 'text' ? 'none' : '';
            if (itemType === 'text') {
              qtyInput.value = '';
            }
            if (itemType !== 'text') {
              var qtyVal = Number(qtyInput.value);
              if (!isFinite(qtyVal) || qtyVal <= 0) {
                qtyInput.value = '1';
              }
            }
          }
          if (priceInput) {
            priceInput.disabled = false;
            priceInput.readOnly = itemType === 'text';
            priceInput.required = itemType !== 'text';
            priceInput.style.display = itemType === 'text' ? 'none' : '';
            if (itemType === 'text') {
              priceInput.value = '';
            }
            if (itemType !== 'text') {
              var priceVal = Number(priceInput.value);
              if (!isFinite(priceVal) || priceVal < 0) {
                priceInput.value = '0';
              }
            }
          }
          if (qtyDash) {
            qtyDash.style.display = itemType === 'text' ? '' : 'none';
          }
          if (priceDash) {
            priceDash.style.display = itemType === 'text' ? '' : 'none';
          }
          if (boldBtn) {
            boldBtn.classList.toggle('active', isBold);
          }
          if (typeBtn) {
            typeBtn.classList.toggle('active', itemType === 'text');
          }
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
            'validez_override',
            'entrega_override',
            'condicion_de_pago_override',
            'moneda_override',
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
            syncItemRowState(row);
            var typeInput = row.querySelector('[data-item-type-input="1"]');
            var itemType = typeInput && String(typeInput.value).toLowerCase() === 'text' ? 'text' : 'normal';
            var qtyInput = row.querySelector('[data-item-cantidad="1"]');
            var priceInput = row.querySelector('[data-item-precio="1"]');
            var lineLabel = row.querySelector('[data-line-total="1"]');
            if (itemType === 'text') {
              if (lineLabel) {
                lineLabel.textContent = '-';
              }
              return;
            }
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
          var boldBtn = event.target.closest('[data-item-bold-toggle="1"]');
          if (boldBtn && itemsBody) {
            var boldRow = boldBtn.closest('tr');
            if (boldRow) {
              var boldInput = boldRow.querySelector('[data-item-bold-input="1"]');
              if (boldInput) {
                boldInput.value = String(boldInput.value) === '1' ? '0' : '1';
                syncItemRowState(boldRow);
              }
            }
            return;
          }

          var typeBtn = event.target.closest('[data-item-type-toggle="1"]');
          if (typeBtn && itemsBody) {
            var typeRow = typeBtn.closest('tr');
            if (typeRow) {
              var typeInput = typeRow.querySelector('[data-item-type-input="1"]');
              var qtyInput = typeRow.querySelector('[data-item-cantidad="1"]');
              var priceInput = typeRow.querySelector('[data-item-precio="1"]');
              if (typeInput) {
                var wasText = String(typeInput.value).toLowerCase() === 'text';
                typeInput.value = wasText ? 'normal' : 'text';
                if (wasText) {
                  if (qtyInput) {
                    var qtyNum = Number(qtyInput.value);
                    qtyInput.value = (!isFinite(qtyNum) || qtyNum <= 0) ? '1' : String(qtyNum);
                  }
                  if (priceInput) {
                    var priceNum = Number(priceInput.value);
                    priceInput.value = (!isFinite(priceNum) || priceNum < 0) ? '0' : String(priceNum);
                  }
                } else {
                  if (qtyInput) {
                    qtyInput.value = '';
                  }
                  if (priceInput) {
                    priceInput.value = '';
                  }
                }
                syncItemRowState(typeRow);
                refreshTotals();
              }
            }
            return;
          }

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

      function bindQuoteEmailModal() {
        if (typeof quoteEmailCleanup === 'function') {
          quoteEmailCleanup();
          quoteEmailCleanup = null;
        }

        var emailModal = document.getElementById('quoteEmailModal');
        if (!emailModal) {
          return;
        }

        var triggerButtons = document.querySelectorAll('[data-open-quote-email="1"]');
        var closeButtons = emailModal.querySelectorAll('[data-close-quote-email="1"]');
        var idInput = emailModal.querySelector('[data-quote-email-id="1"]');
        var emailForm = emailModal.querySelector('#quoteEmailForm');
        var toInput = emailModal.querySelector('[data-quote-email-to="1"]');
        var subjectInput = emailModal.querySelector('[data-quote-email-subject="1"]');
        var messageInput = emailModal.querySelector('[data-quote-email-message="1"]');
        var metaLabel = emailModal.querySelector('[data-quote-email-meta="1"]');
        var submitLabel = emailModal.querySelector('[data-quote-email-submit-label="1"]');
        var sendingModal = document.getElementById('quoteEmailSendingModal');
        var isSending = false;
        var defaultMessage = messageInput ? messageInput.value : '';

        function openSendingModal() {
          if (!sendingModal) {
            return;
          }
          sendingModal.classList.add('open');
          sendingModal.setAttribute('aria-hidden', 'false');
        }

        function closeSendingModal() {
          if (!sendingModal) {
            return;
          }
          sendingModal.classList.remove('open');
          sendingModal.setAttribute('aria-hidden', 'true');
        }

        function openModal() {
          emailModal.classList.add('open');
          emailModal.setAttribute('aria-hidden', 'false');
          if (toInput) {
            toInput.focus();
          }
        }

        function closeModal() {
          emailModal.classList.remove('open');
          emailModal.setAttribute('aria-hidden', 'true');
        }

        function onFormSubmit(event) {
          if (isSending) {
            event.preventDefault();
            return;
          }
          isSending = true;
          if (submitLabel) {
            submitLabel.disabled = true;
            submitLabel.textContent = 'Enviando...';
          }
          openSendingModal();
        }

        function onBackdropClick(event) {
          if (event.target === emailModal) {
            closeModal();
          }
        }

        function onEsc(event) {
          if (event.key === 'Escape' && emailModal.classList.contains('open')) {
            closeModal();
          }
        }

        function onOpenClick(event) {
          var button = event.currentTarget;
          var quoteId = button.getAttribute('data-quote-id') || '';
          var quoteNumber = button.getAttribute('data-quote-number') || '';
          var customerName = button.getAttribute('data-customer-name') || '';
          var customerContact = button.getAttribute('data-customer-contact') || '';
          var customerEmail = button.getAttribute('data-customer-email') || '';
          var printUrl = button.getAttribute('data-print-url') || '';

          if (idInput) {
            idInput.value = quoteId;
          }
          if (toInput) {
            toInput.value = customerEmail;
          }
          if (subjectInput) {
            subjectInput.value = quoteNumber ? ('Cotizacion ' + quoteNumber) : 'Cotizacion';
          }
          if (messageInput) {
            var recipientName = customerContact || customerName;
            var hello = recipientName ? ('Hola ' + recipientName + ',') : 'Hola,';
            messageInput.value = hello + '\n\nTe compartimos la cotizacion ' + quoteNumber + '.\n\nQuedo atento a tus comentarios.';
          }
          if (metaLabel) {
            metaLabel.textContent = printUrl
              ? ('Se incluira tambien el enlace a la vista imprimible: ' + printUrl)
              : 'Se incluira tambien el enlace a la vista imprimible de la cotizacion.';
          }

          openModal();
        }

        triggerButtons.forEach(function (button) {
          button.addEventListener('click', onOpenClick);
        });
        closeButtons.forEach(function (button) {
          button.addEventListener('click', closeModal);
        });

        emailModal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);
        if (emailForm) {
          emailForm.addEventListener('submit', onFormSubmit);
        }

        quoteEmailCleanup = function () {
          triggerButtons.forEach(function (button) {
            button.removeEventListener('click', onOpenClick);
          });
          closeButtons.forEach(function (button) {
            button.removeEventListener('click', closeModal);
          });
          emailModal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
          if (emailForm) {
            emailForm.removeEventListener('submit', onFormSubmit);
          }
          isSending = false;
          closeSendingModal();
          if (submitLabel) {
            submitLabel.disabled = false;
            submitLabel.textContent = 'Enviar correo';
          }
          if (messageInput && messageInput.value === '') {
            messageInput.value = defaultMessage;
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

      function bindReportForm() {
        if (typeof reportFormCleanup === 'function') {
          reportFormCleanup();
          reportFormCleanup = null;
        }

        var modal = document.getElementById('serviceReportModal');
        if (!modal) {
          return;
        }

        var openButtons = document.querySelectorAll('[data-open-report-modal="1"]');
        var editButtons = document.querySelectorAll('[data-edit-service-report="1"]');
        var closeButtons = modal.querySelectorAll('[data-close-report-modal="1"]');
        var form = modal.querySelector('form#serviceReportFormModal');
        var actionInput = form.querySelector('[data-report-action="1"]');
        var reportIdInput = form.querySelector('[data-report-id="1"]');
        var existingWrap = form.querySelector('[data-report-existing-wrap="1"]');
        var existingGrid = form.querySelector('[data-report-existing-grid="1"]');
        var existingJsonInput = form.querySelector('[data-report-existing-json="1"]');
        var modalTitle = modal.querySelector('#serviceReportModalTitle');
        var techSelect = modal.querySelector('[data-report-tech="1"]');
        var soSelect = modal.querySelector('[data-report-so="1"]');
        var photoInput = modal.querySelector('[data-report-photo-input="1"]');
        var photoPreview = modal.querySelector('[data-report-photo-preview="1"]');
        var formsContainer = modal.querySelector('[data-report-forms-container="1"]');
        var formsPayloadInput = modal.querySelector('[data-report-forms-payload="1"]');
        var existingFormPhotosInput = modal.querySelector('[data-report-existing-form-photos="1"]');
        var reportListKeys = ['work_done', 'external_purchases', 'observations'];
        if (!techSelect || !soSelect || !form) {
          return;
        }

        var defaultModalTitle = 'Nuevo reporte tecnico';

        var previewObjectUrls = [];
        var existingPhotosState = [];
        var reportListState = {
          work_done: [],
          external_purchases: [],
          observations: []
        };
        var reportListAddHandlers = [];
        var signaturePadCleanups = [];
        var signaturePads = {
          technician: null,
          customer: null
        };
        var MAX_TOTAL_UPLOAD_BYTES = 7.5 * 1024 * 1024;
        var reportFormsCatalog = {};
        var currentFormsPayload = [];
        var currentExistingFormPhotos = [];

        try {
          var catalogNode = document.getElementById('reportFormsCatalogJson');
          if (catalogNode) {
            var parsedCatalog = JSON.parse(String(catalogNode.textContent || '{}'));
            if (parsedCatalog && typeof parsedCatalog === 'object') {
              reportFormsCatalog = parsedCatalog;
            }
          }
        } catch (error) {
          reportFormsCatalog = {};
        }

        function parseJsonArray(raw) {
          try {
            var parsed = JSON.parse(String(raw || '[]'));
            return Array.isArray(parsed) ? parsed : [];
          } catch (e) {
            return [];
          }
        }

        function templatesForServiceOrder(serviceOrderId) {
          var key = String(serviceOrderId || '').trim();
          if (key === '' || !reportFormsCatalog || typeof reportFormsCatalog !== 'object') {
            return [];
          }
          var rows = reportFormsCatalog[key];
          return Array.isArray(rows) ? rows : [];
        }

        function findAnswerValue(payloadRows, templateId, fieldKey, prop) {
          if (!Array.isArray(payloadRows)) {
            return '';
          }
          for (var i = 0; i < payloadRows.length; i += 1) {
            var tpl = payloadRows[i] || {};
            if (String(tpl.template_id || '') !== String(templateId || '')) {
              continue;
            }
            var answers = Array.isArray(tpl.answers) ? tpl.answers : [];
            for (var j = 0; j < answers.length; j += 1) {
              var ans = answers[j] || {};
              if (String(ans.key || '') !== String(fieldKey || '')) {
                continue;
              }
              return String(ans[prop] || '');
            }
          }
          return '';
        }

        function countExistingFormPhotos(templateId, fieldKey) {
          if (!Array.isArray(currentExistingFormPhotos)) {
            return 0;
          }
          var count = 0;
          currentExistingFormPhotos.forEach(function (row) {
            if (!row || typeof row !== 'object') {
              return;
            }
            if (String(row.template_id || '') === String(templateId || '') && String(row.field_key || '') === String(fieldKey || '')) {
              count += 1;
            }
          });
          return count;
        }

        function renderDynamicForms() {
          if (!formsContainer) {
            return;
          }
          formsContainer.innerHTML = '';
          var selectedSoId = String(soSelect.value || '').trim();
          if (selectedSoId === '') {
            return;
          }
          var templates = templatesForServiceOrder(selectedSoId);
          if (!templates.length) {
            return;
          }

          templates.forEach(function (tpl) {
            var tplId = String((tpl && tpl.id) || '').trim();
            var fields = Array.isArray(tpl.fields) ? tpl.fields : [];
            if (tplId === '' || !fields.length) {
              return;
            }

            var block = document.createElement('div');
            block.className = 'report-form-template-block';
            block.setAttribute('data-template-id', tplId);

            var title = document.createElement('h4');
            title.textContent = String((tpl && tpl.name) || ('Plantilla #' + tplId));
            block.appendChild(title);

            fields.forEach(function (field) {
              var fieldKey = String((field && field.key) || '').trim();
              if (fieldKey === '') {
                return;
              }
              var fieldType = String((field && field.type) || 'texto_corto').trim();
              var wrap = document.createElement('div');
              wrap.className = 'field';
              wrap.setAttribute('data-form-field', '1');
              wrap.setAttribute('data-template-id', tplId);
              wrap.setAttribute('data-field-key', fieldKey);
              wrap.setAttribute('data-field-type', fieldType);

              var label = document.createElement('label');
              label.textContent = String((field && field.label) || fieldKey);
              wrap.appendChild(label);

              if (fieldType === 'texto_largo') {
                var ta = document.createElement('textarea');
                ta.rows = 3;
                ta.setAttribute('data-answer-value', 'text');
                ta.value = findAnswerValue(currentFormsPayload, tplId, fieldKey, 'text');
                wrap.appendChild(ta);
              } else if (fieldType === 'texto_corto') {
                var inp = document.createElement('input');
                inp.type = 'text';
                inp.setAttribute('data-answer-value', 'text');
                inp.value = findAnswerValue(currentFormsPayload, tplId, fieldKey, 'text');
                wrap.appendChild(inp);
              } else if (fieldType === 'text_check') {
                var txt = document.createElement('input');
                txt.type = 'text';
                txt.setAttribute('data-answer-value', 'text');
                txt.value = findAnswerValue(currentFormsPayload, tplId, fieldKey, 'text');
                wrap.appendChild(txt);

                var chkLabel = document.createElement('label');
                chkLabel.className = 'so-chk-toggle';
                var chk = document.createElement('input');
                chk.type = 'checkbox';
                chk.setAttribute('data-answer-value', 'checked');
                chk.checked = findAnswerValue(currentFormsPayload, tplId, fieldKey, 'checked') === '1';
                chkLabel.appendChild(chk);
                var chkText = document.createTextNode(' ' + String((field && field.check_label) || 'Conforme'));
                chkLabel.appendChild(chkText);
                wrap.appendChild(chkLabel);
              } else if (fieldType === 'semaforo') {
                var sel = document.createElement('select');
                sel.setAttribute('data-answer-value', 'status');
                [['green', String((field && field.semaforo_green) || 'Correcto')], ['yellow', String((field && field.semaforo_yellow) || 'Advertencia')], ['red', String((field && field.semaforo_red) || 'Critico')]].forEach(function (optDef) {
                  var opt = document.createElement('option');
                  opt.value = optDef[0];
                  opt.textContent = optDef[1];
                  sel.appendChild(opt);
                });
                var statusValue = findAnswerValue(currentFormsPayload, tplId, fieldKey, 'status');
                if (statusValue !== '') {
                  sel.value = statusValue;
                }
                wrap.appendChild(sel);

                var note = document.createElement('input');
                note.type = 'text';
                note.placeholder = 'Detalle del estado';
                note.setAttribute('data-answer-value', 'text');
                note.value = findAnswerValue(currentFormsPayload, tplId, fieldKey, 'text');
                wrap.appendChild(note);
              } else if (fieldType === 'imagenes') {
                var inputFile = document.createElement('input');
                inputFile.type = 'file';
                inputFile.name = 'form_images[' + tplId + '__' + fieldKey + '][]';
                inputFile.accept = 'image/jpeg,image/png,image/webp';
                inputFile.multiple = true;
                wrap.appendChild(inputFile);

                var existingCount = countExistingFormPhotos(tplId, fieldKey);
                var hint = document.createElement('small');
                hint.textContent = existingCount > 0
                  ? ('Imagenes actuales en este campo: ' + existingCount + '. Puedes agregar mas imagenes en este envio.')
                  : 'Sin imagenes registradas en este campo.';
                wrap.appendChild(hint);
              }

              block.appendChild(wrap);
            });

            formsContainer.appendChild(block);
          });
        }

        function serializeDynamicForms() {
          if (!formsPayloadInput) {
            return;
          }
          if (!formsContainer) {
            formsPayloadInput.value = '[]';
            return;
          }

          var grouped = {};
          var fields = formsContainer.querySelectorAll('[data-form-field="1"]');
          fields.forEach(function (fieldWrap) {
            var templateId = String(fieldWrap.getAttribute('data-template-id') || '').trim();
            var fieldKey = String(fieldWrap.getAttribute('data-field-key') || '').trim();
            var fieldType = String(fieldWrap.getAttribute('data-field-type') || 'texto_corto').trim();
            if (templateId === '' || fieldKey === '') {
              return;
            }
            if (!grouped[templateId]) {
              grouped[templateId] = {
                template_id: Number(templateId),
                answers: []
              };
            }

            var answer = {
              key: fieldKey,
              type: fieldType,
              text: '',
              checked: '0',
              status: ''
            };

            var textInput = fieldWrap.querySelector('[data-answer-value="text"]');
            if (textInput) {
              answer.text = String(textInput.value || '').trim();
            }
            var checkInput = fieldWrap.querySelector('[data-answer-value="checked"]');
            if (checkInput) {
              answer.checked = checkInput.checked ? '1' : '0';
            }
            var statusInput = fieldWrap.querySelector('[data-answer-value="status"]');
            if (statusInput) {
              answer.status = String(statusInput.value || '').trim();
            }

            grouped[templateId].answers.push(answer);
          });

          var rows = Object.keys(grouped).map(function (key) {
            return grouped[key];
          });
          formsPayloadInput.value = JSON.stringify(rows);
        }

        function setExistingFormPhotosState(rows) {
          currentExistingFormPhotos = Array.isArray(rows) ? rows : [];
          if (existingFormPhotosInput) {
            existingFormPhotosInput.value = JSON.stringify(currentExistingFormPhotos);
          }
        }

        function setupSignaturePad(role) {
          var canvas = form.querySelector('[data-signature-canvas="' + role + '"]');
          var clearButton = form.querySelector('[data-signature-clear="' + role + '"]');
          var hiddenInput = form.querySelector('[data-signature-data="' + role + '"]');
          var existingInput = form.querySelector('[data-signature-existing="' + role + '"]');
          if (!canvas || !hiddenInput || !existingInput) {
            return null;
          }

          var ctx = canvas.getContext('2d');
          if (!ctx) {
            return null;
          }

          var drawing = false;
          var hasDrawing = false;
          var changed = false;

          function configureBrush() {
            ctx.lineWidth = 2.2;
            ctx.lineCap = 'round';
            ctx.lineJoin = 'round';
            ctx.strokeStyle = '#0f172a';
          }

          function clearCanvas(markChanged) {
            ctx.setTransform(1, 0, 0, 1, 0, 0);
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            configureBrush();
            hasDrawing = false;
            hiddenInput.value = '';
            if (markChanged) {
              changed = true;
              existingInput.value = '';
            }
          }

          function toCanvasPoint(event) {
            var rect = canvas.getBoundingClientRect();
            var clientX = Number(event.clientX || 0);
            var clientY = Number(event.clientY || 0);
            return {
              x: (clientX - rect.left) * (canvas.width / rect.width),
              y: (clientY - rect.top) * (canvas.height / rect.height)
            };
          }

          function onPointerDown(event) {
            event.preventDefault();
            drawing = true;
            changed = true;
            hasDrawing = true;
            existingInput.value = '';
            var p = toCanvasPoint(event);
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
          }

          function onPointerMove(event) {
            if (!drawing) {
              return;
            }
            event.preventDefault();
            var p = toCanvasPoint(event);
            ctx.lineTo(p.x, p.y);
            ctx.stroke();
          }

          function onPointerUp(event) {
            if (!drawing) {
              return;
            }
            event.preventDefault();
            drawing = false;
            ctx.closePath();
          }

          function loadFromUrl(url, existingPath) {
            clearCanvas(false);
            hiddenInput.value = '';
            existingInput.value = String(existingPath || '').trim();
            var sourceUrl = String(url || '').trim();
            if (sourceUrl === '') {
              changed = false;
              return;
            }

            var image = new Image();
            image.onload = function () {
              clearCanvas(false);
              ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
              hasDrawing = true;
              changed = false;
            };
            image.onerror = function () {
              clearCanvas(false);
              changed = false;
            };
            image.src = sourceUrl;
          }

          function serializeForSubmit() {
            if (!hasDrawing) {
              hiddenInput.value = '';
              existingInput.value = '';
              return false;
            }
            if (changed) {
              hiddenInput.value = canvas.toDataURL('image/png');
            } else {
              hiddenInput.value = '';
            }
            return true;
          }

          configureBrush();
          clearCanvas(false);

          canvas.addEventListener('pointerdown', onPointerDown);
          canvas.addEventListener('pointermove', onPointerMove);
          canvas.addEventListener('pointerup', onPointerUp);
          canvas.addEventListener('pointerleave', onPointerUp);
          canvas.addEventListener('pointercancel', onPointerUp);
          if (clearButton) {
            clearButton.addEventListener('click', function () {
              clearCanvas(true);
            });
          }

          signaturePadCleanups.push(function () {
            canvas.removeEventListener('pointerdown', onPointerDown);
            canvas.removeEventListener('pointermove', onPointerMove);
            canvas.removeEventListener('pointerup', onPointerUp);
            canvas.removeEventListener('pointerleave', onPointerUp);
            canvas.removeEventListener('pointercancel', onPointerUp);
          });

          return {
            clear: function () {
              clearCanvas(false);
              changed = false;
              existingInput.value = '';
              hiddenInput.value = '';
            },
            loadFromUrl: loadFromUrl,
            serializeForSubmit: serializeForSubmit
          };
        }

        function setupSignaturePads() {
          signaturePads.technician = setupSignaturePad('technician');
          signaturePads.customer = setupSignaturePad('customer');
        }

        function resetSignaturePads() {
          if (signaturePads.technician) {
            signaturePads.technician.clear();
          }
          if (signaturePads.customer) {
            signaturePads.customer.clear();
          }
        }

        function loadSignaturePadsFromUrls(techUrl, techPath, customerUrl, customerPath) {
          if (signaturePads.technician) {
            signaturePads.technician.loadFromUrl(techUrl, techPath);
          }
          if (signaturePads.customer) {
            signaturePads.customer.loadFromUrl(customerUrl, customerPath);
          }
        }

        function parseReportItemsText(raw) {
          var text = String(raw || '').replace(/\r/g, '\n').trim();
          if (!text) {
            return [];
          }
          return text
            .split('\n')
            .map(function (line) {
              return String(line || '').replace(/^[-*•\s]+/, '').trim();
            })
            .filter(function (line) {
              return line !== '';
            });
        }

        function serializeReportItems(items) {
          if (!Array.isArray(items) || items.length === 0) {
            return '';
          }
          return items
            .map(function (item) {
              return String(item || '').trim();
            })
            .filter(function (item) {
              return item !== '';
            })
            .join('\n');
        }

        function getReportHiddenInput(key) {
          return form.querySelector('[data-report-hidden="' + key + '"]');
        }

        function ensureAtLeastOneRow(key) {
          if (key !== 'work_done') {
            return;
          }
          if (!Array.isArray(reportListState[key]) || reportListState[key].length === 0) {
            reportListState[key] = [''];
          }
        }

        function syncReportHiddenFields() {
          reportListKeys.forEach(function (key) {
            var hiddenInput = getReportHiddenInput(key);
            if (!hiddenInput) {
              return;
            }
            hiddenInput.value = serializeReportItems(reportListState[key]);
          });
        }

        function renderReportItems(key) {
          var wrap = form.querySelector('[data-report-list-items="' + key + '"]');
          if (!wrap) {
            return;
          }

          ensureAtLeastOneRow(key);
          wrap.innerHTML = '';

          reportListState[key].forEach(function (value, idx) {
            var row = document.createElement('div');
            row.className = 'report-list-row';

            var input = document.createElement('input');
            input.type = 'text';
            input.placeholder = 'Escribe un item';
            input.value = String(value || '');
            input.addEventListener('input', function () {
              reportListState[key][idx] = String(input.value || '');
              syncReportHiddenFields();
            });
            row.appendChild(input);

            var removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'danger';
            removeBtn.textContent = 'Quitar';
            removeBtn.addEventListener('click', function () {
              reportListState[key].splice(idx, 1);
              renderReportItems(key);
              syncReportHiddenFields();
            });
            row.appendChild(removeBtn);

            wrap.appendChild(row);
          });

          syncReportHiddenFields();
        }

        function setReportItemsFromText(key, rawText) {
          reportListState[key] = parseReportItemsText(rawText);
          renderReportItems(key);
        }

        function bindReportListAddButtons() {
          reportListAddHandlers = [];
          reportListKeys.forEach(function (key) {
            var addBtn = form.querySelector('[data-add-report-item="' + key + '"]');
            if (!addBtn) {
              return;
            }
            var handler = function () {
              if (!Array.isArray(reportListState[key])) {
                reportListState[key] = [];
              }
              reportListState[key].push('');
              renderReportItems(key);
              var wrap = form.querySelector('[data-report-list-items="' + key + '"]');
              var lastInput = wrap ? wrap.querySelector('.report-list-row:last-child input') : null;
              if (lastInput) {
                lastInput.focus();
              }
            };
            addBtn.addEventListener('click', handler);
            reportListAddHandlers.push({ button: addBtn, handler: handler });
          });
        }

        function clearPhotoPreview() {
          previewObjectUrls.forEach(function (url) {
            try {
              URL.revokeObjectURL(url);
            } catch (e) {}
          });
          previewObjectUrls = [];
          if (photoPreview) {
            photoPreview.innerHTML = '';
          }
        }

        function formatBytes(bytes) {
          if (!Number.isFinite(bytes) || bytes <= 0) {
            return '0 KB';
          }
          var kb = bytes / 1024;
          if (kb < 1024) {
            return kb.toFixed(0) + ' KB';
          }
          return (kb / 1024).toFixed(2) + ' MB';
        }

        function renderPhotoPreview(files) {
          if (!photoPreview) {
            return;
          }
          clearPhotoPreview();

          if (!files || !files.length) {
            return;
          }

          var totalBytes = 0;
          Array.prototype.forEach.call(files, function (file) {
            totalBytes += Number(file.size || 0);
            var card = document.createElement('div');
            card.className = 'report-photo-card';

            var image = document.createElement('img');
            var objectUrl = URL.createObjectURL(file);
            previewObjectUrls.push(objectUrl);
            image.src = objectUrl;
            image.alt = file.name || 'Foto seleccionada';
            card.appendChild(image);

            var meta = document.createElement('span');
            meta.textContent = (file.name || 'imagen') + ' (' + formatBytes(Number(file.size || 0)) + ')';
            card.appendChild(meta);

            photoPreview.appendChild(card);
          });

          var summary = document.createElement('span');
          summary.style.gridColumn = '1 / -1';
          summary.style.fontSize = '.72rem';
          summary.style.color = totalBytes > MAX_TOTAL_UPLOAD_BYTES ? '#ffb4b4' : '#b8c9e8';
          summary.textContent = 'Total actual: ' + formatBytes(totalBytes) + ' (limite sugerido: 7.5 MB por envio).';
          photoPreview.appendChild(summary);
        }

        function compressImageFile(file) {
          return new Promise(function (resolve) {
            if (!file || !String(file.type || '').match(/^image\//i)) {
              resolve(file);
              return;
            }

            var reader = new FileReader();
            reader.onload = function () {
              var img = new Image();
              img.onload = function () {
                var maxW = 1920;
                var maxH = 1920;
                var width = img.width;
                var height = img.height;

                if (width > maxW || height > maxH) {
                  var ratio = Math.min(maxW / width, maxH / height);
                  width = Math.max(1, Math.round(width * ratio));
                  height = Math.max(1, Math.round(height * ratio));
                }

                var canvas = document.createElement('canvas');
                canvas.width = width;
                canvas.height = height;
                var ctx = canvas.getContext('2d');
                if (!ctx) {
                  resolve(file);
                  return;
                }

                ctx.drawImage(img, 0, 0, width, height);
                canvas.toBlob(function (blob) {
                  if (!blob) {
                    resolve(file);
                    return;
                  }

                  if (blob.size >= file.size) {
                    resolve(file);
                    return;
                  }

                  var compressedName = (file.name || 'imagen').replace(/\.[^.]+$/, '') + '.jpg';
                  resolve(new File([blob], compressedName, { type: 'image/jpeg' }));
                }, 'image/jpeg', 0.82);
              };
              img.onerror = function () {
                resolve(file);
              };
              img.src = String(reader.result || '');
            };
            reader.onerror = function () {
              resolve(file);
            };
            reader.readAsDataURL(file);
          });
        }

        async function optimizeSelectedPhotos(files) {
          var optimized = [];
          for (var i = 0; i < files.length; i += 1) {
            optimized.push(await compressImageFile(files[i]));
          }
          return optimized;
        }

        function onPhotoInputChange() {
          if (!photoInput) {
            return;
          }
          renderPhotoPreview(photoInput.files);
        }

        function serializeExistingPhotosState() {
          if (!existingJsonInput) {
            return;
          }
          if (!Array.isArray(existingPhotosState) || existingPhotosState.length === 0) {
            existingJsonInput.value = '[]';
            return;
          }
          existingJsonInput.value = JSON.stringify(existingPhotosState.map(function (row) {
            return {
              path: String(row.path || '').trim(),
              name: String(row.name || '').trim(),
            };
          }));
        }

        function renderExistingPhotosEditor() {
          if (!existingWrap || !existingGrid) {
            return;
          }

          existingGrid.innerHTML = '';
          if (!Array.isArray(existingPhotosState) || existingPhotosState.length === 0) {
            existingWrap.style.display = 'none';
            serializeExistingPhotosState();
            return;
          }

          existingWrap.style.display = 'grid';
          existingPhotosState.forEach(function (photo, idx) {
            var card = document.createElement('div');
            card.className = 'report-existing-card';

            var image = document.createElement('img');
            image.src = String(photo.url || '');
            image.alt = String(photo.name || 'Foto reporte');
            card.appendChild(image);

            var nameInput = document.createElement('input');
            nameInput.type = 'text';
            nameInput.value = String(photo.name || '');
            nameInput.placeholder = 'Nombre visible de la imagen';
            nameInput.addEventListener('input', function () {
              existingPhotosState[idx].name = String(nameInput.value || '').trim();
              serializeExistingPhotosState();
            });
            card.appendChild(nameInput);

            var actions = document.createElement('div');
            actions.className = 'report-existing-actions';

            var editBtn = document.createElement('button');
            editBtn.type = 'button';
            editBtn.textContent = 'Editar nombre';
            editBtn.addEventListener('click', function () {
              nameInput.focus();
              nameInput.select();
            });
            actions.appendChild(editBtn);

            var removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'danger';
            removeBtn.textContent = 'Eliminar';
            removeBtn.addEventListener('click', function () {
              existingPhotosState.splice(idx, 1);
              renderExistingPhotosEditor();
            });
            actions.appendChild(removeBtn);

            card.appendChild(actions);
            existingGrid.appendChild(card);
          });

          serializeExistingPhotosState();
        }

        function setExistingPhotosState(rows) {
          existingPhotosState = [];
          if (Array.isArray(rows)) {
            rows.forEach(function (row) {
              if (!row || typeof row !== 'object') {
                return;
              }
              var path = String(row.path || '').trim();
              var url = String(row.url || '').trim();
              if (path === '' || url === '') {
                return;
              }
              existingPhotosState.push({
                path: path,
                url: url,
                name: String(row.name || '').trim(),
              });
            });
          }
          renderExistingPhotosEditor();
        }

        function openModal() {
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }

        function closeModal() {
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
        }

        function syncServiceOrderOptions() {
          var selectedTech = String(techSelect.value || '');
          var hasVisible = false;
          var options = soSelect.querySelectorAll('option');

          options.forEach(function (opt, idx) {
            if (idx === 0) {
              opt.hidden = false;
              return;
            }
            var techId = String(opt.getAttribute('data-tech-id') || '');
            var visible = selectedTech !== '' && techId === selectedTech;
            opt.hidden = !visible;
            if (visible) {
              hasVisible = true;
            }
          });

          var current = soSelect.options[soSelect.selectedIndex] || null;
          var keepCurrent = !!(current && !current.hidden && current.value !== '');
          if (!keepCurrent) {
            soSelect.value = '';
          }
          soSelect.disabled = !hasVisible;
          renderDynamicForms();
        }

        function onSoChange() {
          renderDynamicForms();
        }

        function onOpenClick() {
          if (actionInput) {
            actionInput.value = 'add_service_report';
          }
          if (reportIdInput) {
            reportIdInput.value = '';
          }
          if (existingJsonInput) {
            existingJsonInput.value = '[]';
          }
          if (formsPayloadInput) {
            formsPayloadInput.value = '[]';
          }
          currentFormsPayload = [];
          setExistingFormPhotosState([]);
          setExistingPhotosState([]);
          if (modalTitle) {
            modalTitle.textContent = defaultModalTitle;
          }
          setReportItemsFromText('work_done', '');
          setReportItemsFromText('external_purchases', '');
          setReportItemsFromText('observations', '');
          renderDynamicForms();
          resetSignaturePads();
          openModal();
        }

        function onEditClick(event) {
          event.preventDefault();
          event.stopPropagation();
          var button = event.currentTarget;

          var reportId = String(button.getAttribute('data-report-id') || '').trim();
          if (reportId === '') {
            return;
          }

          if (actionInput) {
            actionInput.value = 'update_service_report';
          }
          if (reportIdInput) {
            reportIdInput.value = reportId;
          }
          if (modalTitle) {
            modalTitle.textContent = 'Editar reporte tecnico';
          }

          var techId = String(button.getAttribute('data-report-technician-id') || '').trim();
          var soId = String(button.getAttribute('data-report-service-order-id') || '').trim();
          techSelect.value = techId;
          syncServiceOrderOptions();
          soSelect.value = soId;

          var reportDateInput = form.querySelector('[name="report_date"]');
          var additionalInput = form.querySelector('[name="additional_details"]');
          var formsNoteInput = form.querySelector('[name="forms_note"]');
          var techSignNameInput = form.querySelector('[name="technician_sign_name"]');
          var techSignRutInput = form.querySelector('[name="technician_sign_rut"]');
          var customerSignNameInput = form.querySelector('[name="customer_sign_name"]');
          var customerSignRutInput = form.querySelector('[name="customer_sign_rut"]');

          if (reportDateInput) {
            reportDateInput.value = String(button.getAttribute('data-report-date') || '').trim();
          }
          setReportItemsFromText('work_done', String(button.getAttribute('data-report-work-done') || '').trim());
          setReportItemsFromText('external_purchases', String(button.getAttribute('data-report-external-purchases') || '').trim());
          setReportItemsFromText('observations', String(button.getAttribute('data-report-observations') || '').trim());
          if (additionalInput) {
            additionalInput.value = String(button.getAttribute('data-report-additional-details') || '').trim();
          }
          if (formsNoteInput) {
            formsNoteInput.value = String(button.getAttribute('data-report-forms-note') || '').trim();
          }
          currentFormsPayload = parseJsonArray(button.getAttribute('data-report-forms-payload') || '[]');
          if (techSignNameInput) {
            techSignNameInput.value = String(button.getAttribute('data-report-technician-sign-name') || '').trim();
          }
          if (techSignRutInput) {
            techSignRutInput.value = String(button.getAttribute('data-report-technician-sign-rut') || '').trim();
          }
          if (customerSignNameInput) {
            customerSignNameInput.value = String(button.getAttribute('data-report-customer-sign-name') || '').trim();
          }
          if (customerSignRutInput) {
            customerSignRutInput.value = String(button.getAttribute('data-report-customer-sign-rut') || '').trim();
          }

          loadSignaturePadsFromUrls(
            String(button.getAttribute('data-report-technician-sign-draw-url') || '').trim(),
            String(button.getAttribute('data-report-technician-sign-draw-path') || '').trim(),
            String(button.getAttribute('data-report-customer-sign-draw-url') || '').trim(),
            String(button.getAttribute('data-report-customer-sign-draw-path') || '').trim()
          );

          var rawPhotoRows = String(button.getAttribute('data-report-photo-records') || '[]').trim();
          var photoRows = [];
          try {
            var parsedPhotos = JSON.parse(rawPhotoRows);
            if (Array.isArray(parsedPhotos)) {
              photoRows = parsedPhotos;
            }
          } catch (e) {
            photoRows = [];
          }
          setExistingPhotosState(photoRows);
          var rawFormPhotoRows = String(button.getAttribute('data-report-form-photo-records') || '[]').trim();
          setExistingFormPhotosState(parseJsonArray(rawFormPhotoRows));
          renderDynamicForms();

          if (photoInput) {
            try {
              photoInput.value = '';
            } catch (e) {}
          }
          clearPhotoPreview();
          openModal();
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

        async function onFormSubmit(event) {
          syncReportHiddenFields();
          serializeDynamicForms();

          if (!signaturePads.technician || !signaturePads.customer) {
            event.preventDefault();
            alert('No se pudo inicializar la captura de firma digital. Recarga la pagina.');
            return;
          }

          if (!signaturePads.technician.serializeForSubmit()) {
            event.preventDefault();
            alert('Debes dibujar la firma digital del tecnico.');
            return;
          }
          if (!signaturePads.customer.serializeForSubmit()) {
            event.preventDefault();
            alert('Debes dibujar la firma digital del cliente que recepciona.');
            return;
          }

          var workDoneText = serializeReportItems(reportListState.work_done || []);
          if (workDoneText.trim() === '') {
            event.preventDefault();
            alert('Debes agregar al menos un item en Trabajo realizado.');
            var workWrap = form.querySelector('[data-report-list-items="work_done"]');
            var firstInput = workWrap ? workWrap.querySelector('input') : null;
            if (firstInput) {
              firstInput.focus();
            }
            return;
          }

          serializeExistingPhotosState();

          if (!photoInput || !photoInput.files || photoInput.files.length === 0) {
            return;
          }

          var submitButton = form.querySelector('button[type="submit"]');
          if (submitButton && submitButton.dataset.optimizedOnce === '1') {
            return;
          }

          event.preventDefault();

          if (submitButton) {
            submitButton.disabled = true;
            submitButton.dataset.optimizedOnce = '1';
            submitButton.dataset.originalLabel = submitButton.textContent || 'Guardar reporte';
            submitButton.textContent = 'Optimizando fotos...';
          }

          try {
            var optimizedFiles = await optimizeSelectedPhotos(photoInput.files);
            var dt = new DataTransfer();
            var totalBytes = 0;
            optimizedFiles.forEach(function (file) {
              dt.items.add(file);
              totalBytes += Number(file.size || 0);
            });

            if (totalBytes > MAX_TOTAL_UPLOAD_BYTES) {
              alert('Las fotos seleccionadas pesan ' + formatBytes(totalBytes) + '. Divide el envio en menos fotos para evitar el error 413.');
              if (submitButton) {
                submitButton.disabled = false;
                submitButton.dataset.optimizedOnce = '';
                submitButton.textContent = submitButton.dataset.originalLabel || 'Guardar reporte';
              }
              return;
            }

            photoInput.files = dt.files;
            renderPhotoPreview(photoInput.files);
            form.submit();
          } catch (err) {
            alert('No fue posible optimizar las fotos. Intenta con menos imagenes o menor tamano.');
            if (submitButton) {
              submitButton.disabled = false;
              submitButton.dataset.optimizedOnce = '';
              submitButton.textContent = submitButton.dataset.originalLabel || 'Guardar reporte';
            }
          }
        }

        techSelect.addEventListener('change', syncServiceOrderOptions);
        soSelect.addEventListener('change', onSoChange);
        openButtons.forEach(function (button) {
          button.addEventListener('click', onOpenClick);
        });
        editButtons.forEach(function (button) {
          button.addEventListener('click', onEditClick);
        });
        closeButtons.forEach(function (button) {
          button.addEventListener('click', closeModal);
        });
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);
        if (photoInput) {
          photoInput.addEventListener('change', onPhotoInputChange);
        }
        setupSignaturePads();
        bindReportListAddButtons();
        setReportItemsFromText('work_done', ((getReportHiddenInput('work_done') || {}).value || ''));
        setReportItemsFromText('external_purchases', ((getReportHiddenInput('external_purchases') || {}).value || ''));
        setReportItemsFromText('observations', ((getReportHiddenInput('observations') || {}).value || ''));
        currentFormsPayload = parseJsonArray((formsPayloadInput && formsPayloadInput.value) ? formsPayloadInput.value : '[]');
        form.addEventListener('submit', onFormSubmit);
        syncServiceOrderOptions();
        renderDynamicForms();
        if (photoInput && photoInput.files && photoInput.files.length > 0) {
          renderPhotoPreview(photoInput.files);
        }

        reportFormCleanup = function () {
          techSelect.removeEventListener('change', syncServiceOrderOptions);
          soSelect.removeEventListener('change', onSoChange);
          openButtons.forEach(function (button) {
            button.removeEventListener('click', onOpenClick);
          });
          editButtons.forEach(function (button) {
            button.removeEventListener('click', onEditClick);
          });
          closeButtons.forEach(function (button) {
            button.removeEventListener('click', closeModal);
          });
          modal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
          if (photoInput) {
            photoInput.removeEventListener('change', onPhotoInputChange);
          }
          reportListAddHandlers.forEach(function (row) {
            if (row && row.button && row.handler) {
              row.button.removeEventListener('click', row.handler);
            }
          });
          reportListAddHandlers = [];
          form.removeEventListener('submit', onFormSubmit);
          clearPhotoPreview();
          signaturePadCleanups.forEach(function (cleanup) {
            try {
              cleanup();
            } catch (e) {}
          });
          signaturePadCleanups = [];
        };
      }

      function bindReportHistoryModal() {
        if (typeof reportHistoryCleanup === 'function') {
          reportHistoryCleanup();
          reportHistoryCleanup = null;
        }

        var modal = document.getElementById('serviceReportDetailModal');
        if (!modal) {
          return;
        }

        var openButtons = document.querySelectorAll('[data-open-report-detail-btn="1"]');
        if (!openButtons.length) {
          return;
        }

        var closeButtons = modal.querySelectorAll('[data-close-report-detail="1"]');
        var dateEl = modal.querySelector('[data-report-detail-date="1"]');
        var osEl = modal.querySelector('[data-report-detail-os="1"]');
        var technicianEl = modal.querySelector('[data-report-detail-technician="1"]');
        var customerEl = modal.querySelector('[data-report-detail-customer="1"]');
        var workEl = modal.querySelector('[data-report-detail-work="1"]');
        var purchasesEl = modal.querySelector('[data-report-detail-purchases="1"]');
        var observationsEl = modal.querySelector('[data-report-detail-observations="1"]');
        var additionalEl = modal.querySelector('[data-report-detail-additional="1"]');
        var photosEl = modal.querySelector('[data-report-detail-photos="1"]');
        var signTechEl = modal.querySelector('[data-report-detail-sign-tech="1"]');
        var signCustomerEl = modal.querySelector('[data-report-detail-sign-customer="1"]');

        if (!dateEl || !osEl || !technicianEl || !customerEl || !workEl || !purchasesEl || !observationsEl || !additionalEl || !photosEl || !signTechEl || !signCustomerEl) {
          return;
        }

        function safeText(value) {
          var text = String(value || '').trim();
          return text !== '' ? text : '-';
        }

        function clearPhotos() {
          photosEl.innerHTML = '';
        }

        function renderPhotos(photos) {
          clearPhotos();
          if (!Array.isArray(photos) || photos.length === 0) {
            var empty = document.createElement('p');
            empty.className = 'detail-value';
            empty.textContent = 'Sin fotos';
            photosEl.appendChild(empty);
            return;
          }

          photos.forEach(function (photo) {
            var url = String((photo && photo.url) || '').trim();
            if (url === '') {
              return;
            }
            var label = safeText((photo && photo.label) || 'Foto reporte');

            var link = document.createElement('a');
            link.className = 'detail-photo-link';
            link.href = url;
            link.target = '_blank';
            link.rel = 'noopener';

            var image = document.createElement('img');
            image.src = url;
            image.alt = label;
            link.appendChild(image);

            var caption = document.createElement('span');
            caption.textContent = label;
            link.appendChild(caption);

            photosEl.appendChild(link);
          });

          if (!photosEl.children.length) {
            var fallback = document.createElement('p');
            fallback.className = 'detail-value';
            fallback.textContent = 'Sin fotos';
            photosEl.appendChild(fallback);
          }
        }

        function openModal(payload) {
          dateEl.textContent = safeText(payload.date);
          osEl.textContent = safeText(payload.service_order_code) + ' - ' + safeText(payload.service_order_title);
          technicianEl.textContent = safeText(payload.technician_name);
          customerEl.textContent = safeText(payload.customer_name);
          workEl.textContent = safeText(payload.work_done);
          purchasesEl.textContent = safeText(payload.external_purchases);
          observationsEl.textContent = safeText(payload.observations);

          var additionalText = safeText(payload.additional_details);
          var formsText = String(payload.forms_note || '').trim();
          if (formsText !== '') {
            additionalText += '\n\nFormularios: ' + formsText;
          }
          if (Array.isArray(payload.forms_payload) && payload.forms_payload.length > 0) {
            additionalText += '\n\nPlantillas respondidas: ' + payload.forms_payload.length;
          }
          additionalEl.textContent = additionalText;

          signTechEl.textContent = safeText(payload.technician_signature);
          signCustomerEl.textContent = safeText(payload.customer_signature);
          renderPhotos(payload.photos);

          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }

        function closeModal() {
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
          clearPhotos();
        }

        function handleOpenFromButton(button) {
          var row = button ? button.closest('tr') : null;
          var raw = row ? (row.getAttribute('data-report-detail') || '') : '';
          if (!raw) {
            return;
          }
          try {
            var payload = JSON.parse(raw);
            openModal(payload || {});
          } catch (e) {}
        }

        function onOpenClick(event) {
          event.preventDefault();
          event.stopPropagation();
          handleOpenFromButton(event.currentTarget);
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

        openButtons.forEach(function (button) {
          button.addEventListener('click', onOpenClick);
        });
        closeButtons.forEach(function (button) {
          button.addEventListener('click', closeModal);
        });
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onEsc);

        reportHistoryCleanup = function () {
          openButtons.forEach(function (button) {
            button.removeEventListener('click', onOpenClick);
          });
          closeButtons.forEach(function (button) {
            button.removeEventListener('click', closeModal);
          });
          modal.removeEventListener('click', onBackdropClick);
          document.removeEventListener('keydown', onEsc);
        };
      }

      function bindFormTemplateBuilder() {
        if (typeof formTemplateBuilderCleanup === 'function') {
          formTemplateBuilderCleanup();
          formTemplateBuilderCleanup = null;
        }

        var form = document.getElementById('formTemplateBuilderForm');
        var modal = document.getElementById('formTemplateModal');
        if (!form) {
          return;
        }

        var container = form.querySelector('[data-template-fields-container="1"]');
        var addButton = form.querySelector('[data-template-add-field="1"]');
        var hidden = form.querySelector('[data-template-fields-json="1"]');
        var openBuilderButtons = document.querySelectorAll('[data-open-form-template-builder="1"]');
        var closeBuilderButtons = modal ? modal.querySelectorAll('[data-close-form-template-modal="1"]') : [];
        if (!container || !addButton || !hidden) {
          return;
        }

        var rowsState = [];

        function syncHidden() {
          hidden.value = JSON.stringify(rowsState);
        }

        function addRow(data) {
          rowsState.push({
            label: String((data && data.label) || '').trim(),
            type: String((data && data.type) || 'texto_corto').trim(),
            required: String((data && data.required) || '0') === '1' ? '1' : '0',
            check_label: String((data && data.check_label) || 'Conforme').trim(),
            semaforo_green: String((data && data.semaforo_green) || 'Correcto').trim(),
            semaforo_yellow: String((data && data.semaforo_yellow) || 'Advertencia').trim(),
            semaforo_red: String((data && data.semaforo_red) || 'Critico').trim()
          });
          render();
        }

        function removeRow(index) {
          if (index < 0 || index >= rowsState.length) {
            return;
          }
          rowsState.splice(index, 1);
          render();
        }

        function render() {
          container.innerHTML = '';
          rowsState.forEach(function (row, idx) {
            var card = document.createElement('div');
            card.className = 'so-row form-template-row';

            var label = document.createElement('input');
            label.type = 'text';
            label.placeholder = 'Etiqueta del campo';
            label.value = row.label;
            label.addEventListener('input', function () {
              rowsState[idx].label = String(label.value || '').trim();
              syncHidden();
            });
            card.appendChild(label);

            var typeSel = document.createElement('select');
            [['text_check', 'Texto + check'], ['semaforo', 'Semaforo'], ['texto_corto', 'Texto corto'], ['texto_largo', 'Texto largo'], ['imagenes', 'Imagenes']].forEach(function (pair) {
              var opt = document.createElement('option');
              opt.value = pair[0];
              opt.textContent = pair[1];
              typeSel.appendChild(opt);
            });
            typeSel.value = row.type || 'texto_corto';
            typeSel.addEventListener('change', function () {
              rowsState[idx].type = String(typeSel.value || 'texto_corto');
              render();
            });
            card.appendChild(typeSel);

            var reqWrap = document.createElement('label');
            reqWrap.className = 'so-chk-toggle';
            var req = document.createElement('input');
            req.type = 'checkbox';
            req.checked = row.required === '1';
            req.addEventListener('change', function () {
              rowsState[idx].required = req.checked ? '1' : '0';
              syncHidden();
            });
            reqWrap.appendChild(req);
            reqWrap.appendChild(document.createTextNode(' Requerido'));
            card.appendChild(reqWrap);

            var aux1 = document.createElement('input');
            var aux2 = document.createElement('input');
            var aux3 = document.createElement('input');
            aux1.type = aux2.type = aux3.type = 'text';

            if ((row.type || '') === 'text_check') {
              aux1.placeholder = 'Etiqueta check';
              aux1.value = row.check_label || 'Conforme';
              aux1.addEventListener('input', function () {
                rowsState[idx].check_label = String(aux1.value || '').trim();
                syncHidden();
              });
              aux2.placeholder = '-';
              aux2.disabled = true;
              aux3.placeholder = '-';
              aux3.disabled = true;
            } else if ((row.type || '') === 'semaforo') {
              aux1.placeholder = 'Texto verde';
              aux2.placeholder = 'Texto amarillo';
              aux3.placeholder = 'Texto rojo';
              aux1.value = row.semaforo_green || 'Correcto';
              aux2.value = row.semaforo_yellow || 'Advertencia';
              aux3.value = row.semaforo_red || 'Critico';
              aux1.addEventListener('input', function () {
                rowsState[idx].semaforo_green = String(aux1.value || '').trim();
                syncHidden();
              });
              aux2.addEventListener('input', function () {
                rowsState[idx].semaforo_yellow = String(aux2.value || '').trim();
                syncHidden();
              });
              aux3.addEventListener('input', function () {
                rowsState[idx].semaforo_red = String(aux3.value || '').trim();
                syncHidden();
              });
            } else {
              aux1.placeholder = '-';
              aux2.placeholder = '-';
              aux3.placeholder = '-';
              aux1.disabled = true;
              aux2.disabled = true;
              aux3.disabled = true;
            }

            card.appendChild(aux1);
            card.appendChild(aux2);
            card.appendChild(aux3);

            var remove = document.createElement('button');
            remove.type = 'button';
            remove.className = 'danger';
            remove.textContent = 'Quitar';
            remove.addEventListener('click', function () {
              removeRow(idx);
            });
            card.appendChild(remove);

            container.appendChild(card);
          });

          syncHidden();
        }

        function onAddClick() {
          addRow({ type: 'texto_corto' });
        }

        function onSubmit(event) {
          syncHidden();
          if (!rowsState.length) {
            event.preventDefault();
            window.alert('Agrega al menos un campo en la plantilla.');
            return;
          }
          var hasValidLabel = rowsState.some(function (row) {
            return String(row.label || '').trim() !== '';
          });
          if (!hasValidLabel) {
            event.preventDefault();
            window.alert('Debes definir una etiqueta para al menos un campo.');
          }
        }

        function onOpenBuilderClick() {
          if (modal) {
            modal.classList.add('open');
            modal.setAttribute('aria-hidden', 'false');
          }
          var nameInput = form.querySelector('[name="template_name"]');
          if (nameInput) {
            nameInput.focus();
          }
          if (!rowsState.length) {
            addRow({ type: 'texto_corto' });
          }
        }

        function onCloseBuilderClick() {
          if (!modal) {
            return;
          }
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
        }

        function onModalBackdropClick(event) {
          if (event.target === modal) {
            onCloseBuilderClick();
          }
        }

        function onEsc(event) {
          if (event.key === 'Escape' && modal && modal.classList.contains('open')) {
            onCloseBuilderClick();
          }
        }

        addButton.addEventListener('click', onAddClick);
        form.addEventListener('submit', onSubmit);
        openBuilderButtons.forEach(function (button) {
          button.addEventListener('click', onOpenBuilderClick);
        });
        closeBuilderButtons.forEach(function (button) {
          button.addEventListener('click', onCloseBuilderClick);
        });
        if (modal) {
          modal.addEventListener('click', onModalBackdropClick);
        }
        document.addEventListener('keydown', onEsc);
        addRow({ type: 'texto_corto' });

        formTemplateBuilderCleanup = function () {
          addButton.removeEventListener('click', onAddClick);
          form.removeEventListener('submit', onSubmit);
          openBuilderButtons.forEach(function (button) {
            button.removeEventListener('click', onOpenBuilderClick);
          });
          closeBuilderButtons.forEach(function (button) {
            button.removeEventListener('click', onCloseBuilderClick);
          });
          if (modal) {
            modal.removeEventListener('click', onModalBackdropClick);
          }
          document.removeEventListener('keydown', onEsc);
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
        var title = modal.querySelector('[data-delete-confirm-title="1"]');
        var description = modal.querySelector('[data-delete-confirm-description="1"]');
        var stepOne = modal.querySelector('[data-delete-step-one="1"]');
        var stepOneText = modal.querySelector('[data-delete-step-one-text="1"]');
        var stepTwo = modal.querySelector('[data-delete-step-two="1"]');
        var stepTwoText = modal.querySelector('[data-delete-step-two-text="1"]');
        var checkWrap = modal.querySelector('[data-delete-check-wrap="1"]');
        var checkText = modal.querySelector('[data-delete-check-text="1"]');
        var goStepTwoButton = modal.querySelector('[data-delete-go-step-two="1"]');
        var backStepOneButton = modal.querySelector('[data-delete-back-step-one="1"]');
        var confirmCheckbox = modal.querySelector('[data-delete-confirm-checkbox="1"]');
        var submitButton = modal.querySelector('[data-delete-submit="1"]');
        var submitLabel = modal.querySelector('[data-delete-submit-label="1"]');

        var pendingAction = '';
        var pendingIdField = '';
        var pendingIdValue = '';
        var pendingMode = 'trash';

        function resetState(clearPending) {
          if (clearPending) {
            pendingAction = '';
            pendingIdField = '';
            pendingIdValue = '';
            pendingMode = 'trash';
          }
          if (confirmCheckbox) {
            confirmCheckbox.checked = false;
          }
          if (submitButton) {
            submitButton.disabled = true;
          }
          if (goStepTwoButton) {
            goStepTwoButton.textContent = 'Continuar';
          }
          if (backStepOneButton) {
            backStepOneButton.style.display = '';
          }
          if (checkWrap) {
            checkWrap.style.display = 'flex';
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
          pendingMode = button.getAttribute('data-delete-mode') || 'trash';
          resetState(false);

          var entity = button.getAttribute('data-delete-entity') || 'registro';
          var desc = button.getAttribute('data-delete-description') || '';

          if (pendingMode === 'trash') {
            if (title) {
              title.textContent = 'Mover a la papelera';
            }
            if (description) {
              description.textContent = desc !== ''
                ? 'Se movera el ' + entity + ': ' + desc + ' a la papelera de reciclaje. Podras eliminarlo de forma definitiva desde el modulo Papelera.'
                : 'Se movera este ' + entity + ' a la papelera de reciclaje. Podras eliminarlo de forma definitiva desde el modulo Papelera.';
            }
            if (stepOneText) {
              stepOneText.textContent = 'Primer paso: confirma que deseas mover este elemento a la papelera de reciclaje.';
            }
            if (stepTwoText) {
              stepTwoText.textContent = '';
            }
            if (checkWrap) {
              checkWrap.style.display = 'none';
            }
            if (goStepTwoButton) {
              goStepTwoButton.textContent = 'Mover a papelera';
            }
            if (submitLabel) {
              submitLabel.textContent = 'Confirmar movimiento';
            }
          } else if (pendingMode === 'restore') {
            if (title) {
              title.textContent = 'Restaurar desde papelera';
            }
            if (description) {
              description.textContent = desc !== ''
                ? 'Se restaurara el ' + entity + ': ' + desc + ' y volvera a estar disponible en los modulos activos.'
                : 'Se restaurara este ' + entity + ' y volvera a estar disponible en los modulos activos.';
            }
            if (stepOneText) {
              stepOneText.textContent = 'Primer paso: confirma que deseas restaurar este elemento desde la papelera.';
            }
            if (stepTwoText) {
              stepTwoText.textContent = 'Segundo paso: marca la casilla de acuerdo para habilitar la restauracion.';
            }
            if (checkText) {
              checkText.textContent = 'Estoy de acuerdo con restaurar este dato.';
            }
            if (submitLabel) {
              submitLabel.textContent = 'Confirmar restauracion';
            }
          } else {
            if (title) {
              title.textContent = 'Eliminacion definitiva';
            }
            if (description) {
              description.textContent = desc !== ''
                ? 'Se eliminara definitivamente el ' + entity + ': ' + desc + '. Esta accion es irreversible y puede eliminar datos relacionados. Al continuar, aceptas que no podras reclamar por la recuperacion de datos relacionados eliminados.'
                : 'Se eliminara definitivamente este ' + entity + '. Esta accion es irreversible y puede eliminar datos relacionados. Al continuar, aceptas que no podras reclamar por la recuperacion de datos relacionados eliminados.';
            }
            if (stepOneText) {
              stepOneText.textContent = 'Primer paso: confirma que entiendes la eliminacion definitiva e irreversible.';
            }
            if (stepTwoText) {
              stepTwoText.textContent = 'Segundo paso: marca la casilla de acuerdo para habilitar la eliminacion definitiva.';
            }
            if (checkText) {
              checkText.textContent = 'Estoy de acuerdo con borrar este dato y los relacionados que correspondan.';
            }
            if (submitLabel) {
              submitLabel.textContent = 'Confirmar eliminacion definitiva';
            }
          }

          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }

        function closeModal() {
          modal.classList.remove('open');
          modal.setAttribute('aria-hidden', 'true');
          resetState(true);
        }

        async function submitDelete() {
          if (!pendingAction || !pendingIdField || !pendingIdValue) {
            return;
          }

          if (isTechniciansModuleActive() && pendingAction === 'delete_technician') {
            var ajaxForm = new FormData();
            var csrfTokenAjax = modal.getAttribute('data-delete-csrf-token') || '';
            if (csrfTokenAjax !== '') {
              ajaxForm.append('csrf_token', csrfTokenAjax);
            }
            ajaxForm.append('action', pendingAction);
            ajaxForm.append(pendingIdField, pendingIdValue);
            try {
              await postTechnicianAjax(ajaxForm);
              closeModal();
            } catch (error) {
              showTechError(error && error.message ? error.message : 'No se pudo eliminar el tecnico.');
            }
            return;
          }

          if (pendingAction === 'delete_inventory_item') {
            var ajaxFormInv = new FormData();
            var csrfTokenInv = modal.getAttribute('data-delete-csrf-token') || '';
            if (csrfTokenInv !== '') {
              ajaxFormInv.append('csrf_token', csrfTokenInv);
            }
            ajaxFormInv.append('action', pendingAction);
            ajaxFormInv.append(pendingIdField, pendingIdValue);
            try {
              await postTechnicianAjax(ajaxFormInv);
              closeModal();
            } catch (error) {
              window.alert(error && error.message ? error.message : 'No se pudo eliminar el item.');
            }
            return;
          }

          if (pendingAction === 'restore_inventory_item' || pendingAction === 'purge_inventory_item') {
            var ajaxFormTrash = new FormData();
            var csrfTokenTrash = modal.getAttribute('data-delete-csrf-token') || '';
            if (csrfTokenTrash !== '') {
              ajaxFormTrash.append('csrf_token', csrfTokenTrash);
            }
            ajaxFormTrash.append('action', pendingAction);
            ajaxFormTrash.append(pendingIdField, pendingIdValue);
            try {
              await postTechnicianAjax(ajaxFormTrash);
              closeModal();
            } catch (error) {
              window.alert(error && error.message ? error.message : 'No se pudo completar la accion.');
            }
            return;
          }

          if (pendingAction === 'delete_service_order' || pendingAction === 'restore_service_order' || pendingAction === 'purge_service_order') {
            var ajaxFormSo = new FormData();
            var csrfTokenSo = modal.getAttribute('data-delete-csrf-token') || '';
            if (csrfTokenSo !== '') {
              ajaxFormSo.append('csrf_token', csrfTokenSo);
            }
            ajaxFormSo.append('action', pendingAction);
            ajaxFormSo.append(pendingIdField, pendingIdValue);
            try {
              await postTechnicianAjax(ajaxFormSo);
              closeModal();
            } catch (error) {
              window.alert(error && error.message ? error.message : 'No se pudo completar la accion en la orden de servicio.');
            }
            return;
          }

          if (pendingAction === 'delete_service_report' || pendingAction === 'move_service_report_to_trash' || pendingAction === 'restore_service_report' || pendingAction === 'purge_service_report') {
            var ajaxFormReport = new FormData();
            var csrfTokenReport = modal.getAttribute('data-delete-csrf-token') || '';
            if (csrfTokenReport !== '') {
              ajaxFormReport.append('csrf_token', csrfTokenReport);
            }
            ajaxFormReport.append('action', pendingAction);
            ajaxFormReport.append(pendingIdField, pendingIdValue);
            try {
              await postTechnicianAjax(ajaxFormReport);
              closeModal();
            } catch (error) {
              window.alert(error && error.message ? error.message : 'No se pudo completar la accion en el reporte.');
            }
            return;
          }

          var form = document.createElement('form');
          form.method = 'post';
          form.style.display = 'none';

          var csrfToken = modal.getAttribute('data-delete-csrf-token') || '';
          if (csrfToken !== '') {
            var csrfField = document.createElement('input');
            csrfField.type = 'hidden';
            csrfField.name = 'csrf_token';
            csrfField.value = csrfToken;
            form.appendChild(csrfField);
          }

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

        function onCheckboxChange() {
          if (!submitButton || !confirmCheckbox) {
            return;
          }
          submitButton.disabled = !confirmCheckbox.checked;
        }

        function onOpenClick(event) {
          openModal(event.currentTarget);
        }

        function goStepTwo() {
          if (pendingMode === 'trash') {
            submitDelete();
            return;
          }
          if (stepOne) {
            stepOne.style.display = 'none';
          }
          if (stepTwo) {
            stepTwo.style.display = 'block';
          }
          if (confirmCheckbox) {
            confirmCheckbox.focus();
          }
        }

        function goStepOne() {
          if (stepOne) {
            stepOne.style.display = 'block';
          }
          if (stepTwo) {
            stepTwo.style.display = 'none';
          }
          if (confirmCheckbox) {
            confirmCheckbox.checked = false;
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
        if (confirmCheckbox) {
          confirmCheckbox.addEventListener('change', onCheckboxChange);
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
          if (confirmCheckbox) {
            confirmCheckbox.removeEventListener('change', onCheckboxChange);
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
          bindTechnicianModal();
          bindTechnicianAssetModal();
          bindInventoryModal();
          bindInventoryMovementModal();
          bindInventoryHistoryModal();
          bindServiceOrderModal();
          bindServiceOrderAssignQuickModal();
          bindServiceOrderListInteractions();
          bindQuoteModal();
          bindQuoteEmailModal();
          bindQuotePreview();
          bindReportForm();
          bindReportHistoryModal();
          bindFormTemplateBuilder();
          bindDeleteConfirmModal();
          bindQuoteFilters();
          bindQuoteQuickState();
          bindCartaGanttModule();
          bindToasts();
          bindSideMenuToggle();

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
      bindTechnicianModal();
      bindTechnicianAssetModal();
      bindInventoryModal();
      bindInventoryMovementModal();
      bindInventoryHistoryModal();
      bindServiceOrderModal();
      bindServiceOrderAssignQuickModal();
      bindServiceOrderListInteractions();
      bindQuoteModal();
      bindQuoteEmailModal();
      bindQuotePreview();
      bindReportForm();
      bindReportHistoryModal();
      bindFormTemplateBuilder();
      bindDeleteConfirmModal();
      bindQuoteFilters();
      bindQuoteQuickState();
      bindCartaGanttModule();
      bindToasts();
      bindSideMenuToggle();
    })();
  </script>
  <style>
    .idle-warning-overlay {
      position: fixed;
      inset: 0;
      background: rgba(3, 10, 28, 0.72);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 9999;
      padding: 16px;
    }
    .idle-warning-overlay.visible {
      display: flex;
    }
    .idle-warning-box {
      width: min(480px, 100%);
      background: #ffffff;
      border-radius: 14px;
      border: 1px solid #d7def0;
      padding: 20px;
      box-shadow: 0 18px 55px rgba(9, 15, 35, 0.3);
    }
    .idle-warning-box h3 {
      margin: 0 0 10px;
      color: #111f43;
    }
    .idle-warning-box p {
      margin: 0;
      color: #344266;
      line-height: 1.45;
    }
    .idle-warning-actions {
      margin-top: 16px;
      display: flex;
      gap: 10px;
      justify-content: flex-end;
    }
    .idle-warning-actions .btn {
      min-width: 130px;
    }
  </style>
  <div class="idle-warning-overlay" id="idleWarning" aria-live="polite" aria-hidden="true">
    <div class="idle-warning-box" role="dialog" aria-modal="true" aria-labelledby="idleWarningTitle">
      <h3 id="idleWarningTitle">Tu sesion esta por expirar</h3>
      <p>
        Por seguridad, tu sesion se cerrara por inactividad en
        <strong id="idleWarningCountdown">05:00</strong>.
      </p>
      <div class="idle-warning-actions">
        <button class="btn" type="button" id="idleStaySigned">Seguir en sesion</button>
        <button class="btn ghost" type="button" id="idleLeaveNow">Cerrar ahora</button>
      </div>
    </div>
  </div>
  <script>
    (function () {
      var warningMs = <?= (int)$sessionWarningSeconds ?> * 1000;
      var expiresAtMs = <?= (int)$sessionExpiresAt ?> * 1000;

      var overlay = document.getElementById('idleWarning');
      var countdown = document.getElementById('idleWarningCountdown');
      var keepAliveBtn = document.getElementById('idleStaySigned');
      var leaveBtn = document.getElementById('idleLeaveNow');

      if (!overlay || !countdown || !keepAliveBtn || !leaveBtn) {
        return;
      }

      function formatCountdown(ms) {
        var total = Math.max(0, Math.ceil(ms / 1000));
        var minutes = Math.floor(total / 60);
        var seconds = total % 60;
        return String(minutes).padStart(2, '0') + ':' + String(seconds).padStart(2, '0');
      }

      function showWarning() {
        overlay.classList.add('visible');
        overlay.setAttribute('aria-hidden', 'false');
      }

      function hideWarning() {
        overlay.classList.remove('visible');
        overlay.setAttribute('aria-hidden', 'true');
      }

      function redirectToLogin() {
        window.location.href = '/login/?session_timeout=1';
      }

      async function keepSessionAlive() {
        keepAliveBtn.disabled = true;
        try {
          var url = new URL(window.location.href);
          url.searchParams.set('keepalive', '1');
          var res = await fetch(url.toString(), {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'Accept': 'application/json' }
          });
          if (!res.ok) {
            redirectToLogin();
            return;
          }
          var payload = await res.json();
          if (!payload || payload.ok !== true || typeof payload.expires_at !== 'number') {
            redirectToLogin();
            return;
          }
          expiresAtMs = payload.expires_at * 1000;
          hideWarning();
        } catch (err) {
          redirectToLogin();
        } finally {
          keepAliveBtn.disabled = false;
        }
      }

      keepAliveBtn.addEventListener('click', function () {
        void keepSessionAlive();
      });

      leaveBtn.addEventListener('click', function () {
        redirectToLogin();
      });

      window.setInterval(function () {
        var remaining = expiresAtMs - Date.now();
        if (remaining <= 0) {
          redirectToLogin();
          return;
        }

        if (remaining <= warningMs) {
          showWarning();
          countdown.textContent = formatCountdown(remaining);
        } else {
          hideWarning();
        }
      }, 1000);

      document.addEventListener('visibilitychange', function () {
        if (!document.hidden && (expiresAtMs - Date.now()) <= warningMs) {
          countdown.textContent = formatCountdown(expiresAtMs - Date.now());
          showWarning();
        }
      });
    })();
  </script>
</body>
</html>
