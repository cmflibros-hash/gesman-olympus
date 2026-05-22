<?php
$year = date('Y');
$updated = '19 de mayo de 2026';
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Política de Privacidad | GesMan OLYMPUS</title>
  <meta name="description" content="Política de Privacidad de GesMan OLYMPUS.">
  <link rel="icon" type="image/svg+xml" href="assets/img/favicon-olympus.svg">
  <link rel="shortcut icon" href="assets/img/favicon-olympus.svg" type="image/svg+xml">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:#0A0E1F;
      --bg2:#0E1530;
      --panel:#121A3D;
      --gold:#E0B564;
      --gold-soft:#F2D08C;
      --text:#F1F1F4;
      --muted:#A8B0C0;
      --line:rgba(224,181,100,.18);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: radial-gradient(ellipse at 20% 0%, rgba(224,181,100,.08), transparent 45%), linear-gradient(180deg, var(--bg), var(--bg2));
      color: var(--text);
      font-family: 'Inter', sans-serif;
      line-height: 1.65;
    }
    .wrap { width: min(980px, 92%); margin: 0 auto; }
    .top {
      position: sticky;
      top: 0;
      backdrop-filter: blur(10px);
      background: rgba(10,14,31,.75);
      border-bottom: 1px solid var(--line);
      z-index: 10;
    }
    .top-inner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      padding: .9rem 0;
    }
    .brand { font-family: 'Cinzel', serif; letter-spacing: .12em; text-decoration: none; color: var(--text); }
    .brand strong { color: var(--gold); }
    .back { color: var(--muted); text-decoration: none; border: 1px solid var(--line); border-radius: 999px; padding: .45rem .75rem; }
    .back:hover { color: var(--gold-soft); border-color: rgba(224,181,100,.45); }
    main { padding: 2rem 0 4rem; }
    .card {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(180deg, rgba(18,26,61,.82), rgba(12,18,43,.9));
      padding: 1.4rem;
    }
    h1,h2 { font-family: 'Cinzel', serif; line-height: 1.2; }
    h1 { margin: .2rem 0 .7rem; font-size: clamp(1.8rem, 5vw, 2.6rem); }
    h2 { margin: 1.5rem 0 .5rem; font-size: 1.05rem; color: var(--gold-soft); letter-spacing: .04em; }
    p, li { color: var(--muted); }
    ul { padding-left: 1.1rem; }
    .meta { margin: 0 0 1rem; color: var(--muted); font-size: .9rem; }
    .warn {
      border: 1px solid rgba(224,181,100,.32);
      border-radius: 12px;
      padding: .8rem;
      background: rgba(224,181,100,.06);
      color: #F4E6C0;
      font-size: .92rem;
    }
  </style>
</head>
<body>
  <header class="top">
    <div class="wrap top-inner">
      <a class="brand" href="index.php">GESMAN <strong>OLYMPUS</strong></a>
      <a class="back" href="index.php#contacto">Volver al sitio</a>
    </div>
  </header>

  <main class="wrap">
    <article class="card">
      <h1>Política de Privacidad</h1>
      <p class="meta">Última actualización: <?= htmlspecialchars($updated, ENT_QUOTES, 'UTF-8') ?></p>

      <p>
        En GesMan OLYMPUS respetamos la privacidad de las personas usuarias y protegemos los datos personales que tratamos en el contexto
        de demos, suscripciones, pagos y soporte comercial/técnico.
      </p>

      <div class="warn">
        Este documento es una base operativa para publicación inmediata. Antes de habilitar pagos en producción, debe completarse con los datos del responsable del tratamiento
        (razón social, RUT/ID fiscal, domicilio legal y correo de privacidad) y validarse con asesoría legal local.
      </div>

      <h2>1. Responsable del Tratamiento</h2>
      <p>
        Responsable: GesMan OLYMPUS (completar razón social legal).<br>
        Correo de privacidad: contacto@gesmanolympus.com (o el correo designado formalmente).<br>
        Domicilio legal: completar.
      </p>

      <h2>2. Datos que recopilamos</h2>
      <ul>
        <li>Datos de identificación y contacto: nombre, correo, teléfono, empresa y cargo.</li>
        <li>Datos operativos: solicitudes de demo, tickets de contacto y comunicaciones.</li>
        <li>Datos de facturación: identificadores tributarios y datos administrativos para emitir cobros.</li>
        <li>Metadatos de uso y seguridad: IP, fecha/hora, navegador, eventos técnicos y registros antifraude.</li>
      </ul>

      <h2>3. Datos de pago y tarjetas</h2>
      <p>
        GesMan OLYMPUS no debe almacenar números completos de tarjeta ni códigos CVV en su infraestructura.
        Los cobros deben procesarse mediante pasarelas certificadas (por ejemplo, Flow o Webpay) usando checkout/tokenización del proveedor.
      </p>

      <h2>4. Finalidades del tratamiento</h2>
      <ul>
        <li>Gestionar el alta de cuentas, suscripciones y cobros.</li>
        <li>Proveer soporte comercial y técnico.</li>
        <li>Cumplir obligaciones legales, contables y tributarias.</li>
        <li>Prevenir fraudes, abusos y accesos no autorizados.</li>
      </ul>

      <h2>5. Base legal</h2>
      <ul>
        <li>Ejecución de contrato o medidas precontractuales (servicio solicitado).</li>
        <li>Cumplimiento de obligaciones legales (fiscales y contables).</li>
        <li>Interés legítimo en seguridad y continuidad operacional.</li>
        <li>Consentimiento para finalidades opcionales (por ejemplo, cookies no esenciales).</li>
      </ul>

      <h2>6. Conservación de datos</h2>
      <p>
        Conservamos la información por el tiempo necesario para la prestación del servicio y por los plazos exigidos por normativa aplicable.
        Luego aplicamos eliminación o anonimización segura.
      </p>

      <h2>7. Compartición con terceros</h2>
      <p>
        Compartimos datos solo con proveedores necesarios para la operación (hosting, pasarela de pagos, correo transaccional, analítica autorizada),
        bajo contratos de confidencialidad y seguridad.
      </p>

      <h2>8. Seguridad de la información</h2>
      <ul>
        <li>Canales cifrados (HTTPS/TLS) y controles de acceso por rol.</li>
        <li>Registros de auditoría y monitoreo de eventos críticos.</li>
        <li>Mínimo privilegio, credenciales segregadas y rotación periódica.</li>
        <li>Backups cifrados y plan de respuesta ante incidentes.</li>
      </ul>

      <h2>9. Derechos de titulares</h2>
      <p>
        Las personas pueden solicitar acceso, rectificación, actualización, eliminación y/o limitación de tratamiento conforme a la ley aplicable.
        Para ello deben escribir a contacto@gesmanolympus.com.
      </p>

      <h2>10. Cambios a esta política</h2>
      <p>
        Podremos actualizar esta política por cambios normativos, técnicos o de negocio. La versión vigente se publicará en esta misma URL.
      </p>

      <p class="meta">© <?= $year ?> GesMan OLYMPUS</p>
    </article>
  </main>
</body>
</html>
