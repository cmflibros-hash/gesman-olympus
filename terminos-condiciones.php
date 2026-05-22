<?php
$year = date('Y');
$updated = '19 de mayo de 2026';
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Términos y Condiciones | GesMan OLYMPUS</title>
  <meta name="description" content="Términos y Condiciones de GesMan OLYMPUS.">
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
    .note { border: 1px solid rgba(224,181,100,.28); border-radius: 12px; background: rgba(224,181,100,.06); padding: .75rem; color: #F4E6C0; }
  </style>
</head>
<body>
  <header class="top">
    <div class="wrap top-inner">
      <a class="brand" href="index.php">GESMAN <strong>OLYMPUS</strong></a>
      <a class="back" href="index.php#top">Volver al sitio</a>
    </div>
  </header>

  <main class="wrap">
    <article class="card">
      <h1>Términos y Condiciones</h1>
      <p class="meta">Última actualización: <?= htmlspecialchars($updated, ENT_QUOTES, 'UTF-8') ?></p>

      <p>
        Estos términos regulan el uso del sitio GesMan OLYMPUS y la contratación de servicios/suscripciones de software.
      </p>

      <p class="note">
        Debes completar datos legales del prestador (razón social, RUT/ID fiscal, domicilio y jurisdicción aplicable)
        antes de operar cobros en producción.
      </p>

      <h2>1. Aceptación</h2>
      <p>
        Al navegar, registrarte o contratar servicios, aceptas estos términos y las políticas de privacidad/cookies vigentes.
      </p>

      <h2>2. Servicio</h2>
      <p>
        GesMan OLYMPUS presenta y comercializa soluciones de gestión empresarial. La activación de cuentas, módulos y funcionalidades
        puede depender del plan contratado y de la validación comercial/técnica.
      </p>

      <h2>3. Cuentas y acceso</h2>
      <ul>
        <li>La persona usuaria es responsable de la veracidad de los datos proporcionados.</li>
        <li>Las credenciales son personales y deben mantenerse confidenciales.</li>
        <li>El uso indebido o fraudulento puede implicar suspensión o cancelación.</li>
      </ul>

      <h2>4. Planes, precios y pagos</h2>
      <ul>
        <li>Los precios, ciclos de facturación y moneda se informan al momento de contratar.</li>
        <li>Los cobros pueden procesarse mediante terceros certificados (ej. Flow/Webpay).</li>
        <li>No almacenamos números completos de tarjeta ni CVV en servidores propios.</li>
        <li>En caso de rechazo de pago, la continuidad del servicio puede verse afectada.</li>
      </ul>

      <h2>5. Suscripciones y renovaciones</h2>
      <p>
        Si el plan es recurrente, la renovación se realizará según el ciclo contratado, salvo cancelación previa conforme a las reglas comerciales informadas.
      </p>

      <h2>6. Reembolsos y anulaciones</h2>
      <p>
        Las devoluciones, notas de crédito y anulaciones se revisan caso a caso, según estado del servicio, condiciones comerciales y normativa aplicable.
      </p>

      <h2>7. Propiedad intelectual</h2>
      <p>
        Todo contenido del sitio y software asociado pertenece a GesMan y/o sus licenciantes. Queda prohibida la reproducción no autorizada.
      </p>

      <h2>8. Limitación de responsabilidad</h2>
      <p>
        GesMan OLYMPUS no será responsable por interrupciones o daños indirectos fuera de su control razonable, sin perjuicio de derechos irrenunciables del consumidor.
      </p>

      <h2>9. Protección de datos</h2>
      <p>
        El tratamiento de datos personales se rige por la Política de Privacidad publicada en el sitio.
      </p>

      <h2>10. Modificaciones</h2>
      <p>
        Podemos actualizar estos términos por cambios regulatorios, técnicos o de modelo de negocio. La versión vigente será la publicada en esta URL.
      </p>

      <h2>11. Ley aplicable y jurisdicción</h2>
      <p>
        Completar según país/territorio de operación principal de GesMan.
      </p>

      <p class="meta">© <?= $year ?> GesMan OLYMPUS</p>
    </article>
  </main>
</body>
</html>
