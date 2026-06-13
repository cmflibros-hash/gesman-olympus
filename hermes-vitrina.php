<?php
// GesMan OLYMPUS — Vitrina de HERMES dentro del dominio olympus
// Muestra HERMES como producto con identidad visual de OLYMPUS
// y botones para ir al dominio real gesmanhermes.com
$year = date('Y');
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GesMan HERMES — Software de Gestión de Servicio Técnico | GesMan OLYMPUS</title>
  <meta name="description" content="Conoce GesMan HERMES, el sistema de gestión de servicios técnicos de la suite GesMan. Cotizaciones, órdenes de servicio, técnicos y tablero operativo.">
  <meta name="theme-color" content="#0A0E1F">
  <meta name="robots" content="index,follow">
  <meta property="og:title" content="GesMan HERMES | Software de Gestión de Servicio Técnico">
  <meta property="og:description" content="Conoce HERMES, el Mensajero del Olimpo. Gestiona clientes, cotizaciones, técnicos y órdenes de servicio en un solo flujo.">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://gesmanolympus.com/hermes-vitrina">
  <link rel="canonical" href="https://gesmanolympus.com/hermes-vitrina">
  <link rel="icon" type="image/svg+xml" href="/assets/img/favicon-olympus.svg">
  <link rel="shortcut icon" href="/assets/img/favicon-olympus.svg" type="image/svg+xml">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0A0E1F;
      color: #F1F1F4;
      line-height: 1.6;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }
    h1, h2, h3, .display { font-family: 'Cinzel', serif; letter-spacing: .02em; font-weight: 600; }
    a { color: inherit; text-decoration: none; }
    img, svg { display: block; max-width: 100%; }

    :root {
      --bg:        #0A0E1F;
      --bg-2:      #111733;
      --bg-3:      #1A2150;
      --gold:      #E0B564;
      --gold-soft: #F2D08C;
      --cyan:      #5BC0BE;
      --text:      #F1F1F4;
      --muted:     #A8B0C0;
      --line:      rgba(224,181,100,0.18);
    }

    .container { width: min(1180px, 92%); margin-inline: auto; }
    .eyebrow {
      display: inline-block;
      font-family: 'Cinzel', serif;
      font-size: .78rem;
      letter-spacing: .32em;
      text-transform: uppercase;
      color: var(--gold);
      padding: .35rem .9rem;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(224,181,100,0.05);
    }
    .section-title {
      font-size: clamp(1.8rem, 3.6vw, 2.6rem);
      margin: 1rem 0 .5rem;
      color: var(--text);
    }
    .section-title em { font-style: normal; color: var(--gold); }
    .lead { color: var(--muted); font-size: 1.05rem; max-width: 680px; }
    .lead-cta { color: var(--muted); font-size: 1.05rem; }

    /* ===== NAV (OLYMPUS) ===== */
    .nav {
      position: fixed; top: 0; left: 0; right: 0;
      z-index: 50;
      padding: 1rem 0;
      transition: background .35s ease, backdrop-filter .35s ease, border-color .35s ease;
      border-bottom: 1px solid transparent;
    }
    .nav.scrolled {
      background: rgba(10,14,31,.78);
      backdrop-filter: saturate(140%) blur(12px);
      -webkit-backdrop-filter: saturate(140%) blur(12px);
      border-bottom-color: var(--line);
    }
    .nav-inner { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
    .brand { display: flex; align-items: center; gap: .7rem; font-family: 'Cinzel', serif; font-weight: 700; font-size: 1.05rem; letter-spacing: .18em; }
    .brand-mark {
      width: 36px; height: 36px;
      display: grid; place-items: center;
      border-radius: 10px;
      background: radial-gradient(circle at 30% 30%, #1A2150, #0A0E1F 70%);
      border: 1px solid var(--line);
    }
    .brand-mark svg { width: 22px; height: 22px; }
    .brand-text { color: var(--text); }
    .brand-text span { color: var(--gold); }
    .nav-links { display: flex; gap: 1.75rem; font-size: .92rem; color: var(--muted); }
    .nav-links a { transition: color .2s ease; }
    .nav-links a:hover { color: var(--gold); }
    .nav-cta {
      display: inline-flex; align-items: center; gap: .5rem;
      padding: .55rem 1.05rem; border-radius: 999px;
      border: 1px solid var(--gold);
      color: var(--gold); font-size: .88rem; font-weight: 500;
      transition: background .25s ease, color .25s ease, transform .25s ease;
    }
    .nav-cta:hover { background: var(--gold); color: #0A0E1F; transform: translateY(-1px); }
    @media (max-width: 820px) { .nav-links { display: none; } }

    /* ===== HERO VITRINA ===== */
    .hero-vitrina {
      position: relative;
      min-height: 70svh;
      display: grid; place-items: center;
      padding: 8rem 0 4rem;
      overflow: hidden;
      isolation: isolate;
    }
    .hero-vitrina::before {
      content: ""; position: absolute; inset: 0; z-index: -3;
      background:
        radial-gradient(ellipse at 20% 10%, rgba(91,192,190,.12), transparent 55%),
        radial-gradient(ellipse at 80% 0%, rgba(224,181,100,.10), transparent 55%),
        linear-gradient(180deg, #0A0E1F 0%, #0E1530 55%, #0A0E1F 100%);
    }
    .stars {
      position: absolute; inset: 0; z-index: -2; pointer-events: none;
      background-image:
        radial-gradient(1px 1px at 12% 18%, rgba(255,255,255,.7), transparent 60%),
        radial-gradient(1px 1px at 23% 60%, rgba(255,255,255,.55), transparent 60%),
        radial-gradient(1.5px 1.5px at 35% 30%, rgba(242,208,140,.8), transparent 60%),
        radial-gradient(1px 1px at 50% 12%, rgba(255,255,255,.6), transparent 60%),
        radial-gradient(1px 1px at 68% 40%, rgba(255,255,255,.7), transparent 60%),
        radial-gradient(1.5px 1.5px at 82% 22%, rgba(91,192,190,.75), transparent 60%),
        radial-gradient(1px 1px at 90% 65%, rgba(255,255,255,.55), transparent 60%),
        radial-gradient(1px 1px at 8%  72%, rgba(255,255,255,.45), transparent 60%),
        radial-gradient(1px 1px at 44% 78%, rgba(255,255,255,.5),  transparent 60%);
      animation: twinkle 6s ease-in-out infinite alternate;
    }
    @keyframes twinkle {
      0%   { opacity: .55; }
      50%  { opacity: 1; }
      100% { opacity: .65; }
    }
    .hero-content { text-align: center; position: relative; z-index: 1; }
    .hero-vitrina h1 {
      font-size: clamp(2.4rem, 7vw, 4.5rem);
      line-height: 1.05;
      margin: 1rem 0 .5rem;
      background: linear-gradient(180deg, #FFF 0%, #F2D08C 55%, #E0B564 100%);
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
      text-shadow: 0 4px 40px rgba(224,181,100,.18);
    }
    .hero-vitrina .subtitle {
      font-family: 'Cinzel', serif;
      font-size: clamp(.95rem, 1.5vw, 1.15rem);
      letter-spacing: .25em;
      text-transform: uppercase;
      color: var(--cyan);
      margin-bottom: 1rem;
    }
    .hero-vitrina .tagline {
      max-width: 700px;
      margin: .75rem auto 2rem;
      color: var(--muted);
      font-size: clamp(.95rem, 1.3vw, 1.1rem);
    }
    .hero-ctas { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }
    .btn {
      display: inline-flex; align-items: center; gap: .55rem;
      padding: .95rem 1.6rem;
      border-radius: 999px;
      font-weight: 600; font-size: .98rem;
      transition: transform .25s ease, box-shadow .25s ease, background .25s ease, color .25s ease;
      cursor: pointer; border: 0;
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--gold), var(--gold-soft));
      color: #0A0E1F;
      box-shadow: 0 10px 30px -10px rgba(224,181,100,.55);
    }
    .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 15px 35px -10px rgba(224,181,100,.7); }
    .btn-ghost {
      background: transparent;
      color: var(--text);
      border: 1px solid rgba(255,255,255,.18);
    }
    .btn-ghost:hover { border-color: var(--cyan); color: var(--cyan); }
    .btn-outline-cyan {
      background: transparent;
      color: var(--cyan);
      border: 1px solid var(--cyan);
    }
    .btn-outline-cyan:hover { background: var(--cyan); color: #0A0E1F; }

    section { padding: 5rem 0; position: relative; }
    .section-head { max-width: 760px; margin: 0 auto 3rem; text-align: center; }
    .section-head .lead { margin-inline: auto; }

    /* ===== Banner informativo ===== */
    .domain-banner {
      background: rgba(91,192,190,.08);
      border: 1px solid rgba(91,192,190,.25);
      border-radius: 14px;
      padding: 1rem 1.25rem;
      margin-bottom: 2rem;
      display: flex;
      align-items: center;
      gap: .75rem;
      flex-wrap: wrap;
      color: var(--cyan);
      font-size: .95rem;
    }
    .domain-banner strong { color: var(--gold-soft); }
    .domain-banner a {
      color: var(--gold);
      text-decoration: underline;
      text-underline-offset: 2px;
      white-space: nowrap;
    }
    .domain-banner a:hover { color: var(--gold-soft); }

    /* ===== Funciones detalle ===== */
    .features-sec { background: var(--bg); }
    .features-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1.25rem;
    }
    @media (max-width: 980px) { .features-grid { grid-template-columns: repeat(2, 1fr); } }
    @media (max-width: 640px)  { .features-grid { grid-template-columns: 1fr; } }
    .feature-card {
      padding: 1.6rem;
      border-radius: 16px;
      background: linear-gradient(165deg, #131A3A 0%, #0E1530 100%);
      border: 1px solid var(--line);
      transition: transform .35s ease, border-color .35s ease, box-shadow .35s ease;
    }
    .feature-card:hover { transform: translateY(-4px); border-color: var(--gold); box-shadow: 0 20px 40px -25px rgba(0,0,0,.6); }
    .feature-ico {
      width: 44px; height: 44px; border-radius: 12px;
      display: grid; place-items: center;
      background: rgba(91,192,190,.12);
      color: var(--cyan);
      margin-bottom: .9rem;
    }
    .feature-card h3 {
      font-family: 'Inter', sans-serif;
      font-size: 1.05rem;
      margin: 0 0 .4rem;
      color: var(--text);
    }
    .feature-card p { margin: 0; color: var(--muted); font-size: .94rem; }

    /* ===== Planes ===== */
    .plans {
      background:
        radial-gradient(ellipse at 50% 0%, rgba(224,181,100,.10), transparent 60%),
        var(--bg);
      border-top: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
    }
    .plans-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1.1rem;
    }
    @media (max-width: 1100px) { .plans-grid { grid-template-columns: repeat(2, 1fr); } }
    @media (max-width: 640px)  { .plans-grid { grid-template-columns: 1fr; } }
    .plan-card {
      display: flex;
      flex-direction: column;
      gap: .9rem;
      padding: 1.4rem;
      border-radius: 16px;
      background: linear-gradient(165deg, #131A3A 0%, #0E1530 100%);
      border: 1px solid var(--line);
      transition: transform .3s ease, border-color .3s ease, box-shadow .3s ease;
    }
    .plan-card:hover { transform: translateY(-3px); border-color: var(--gold); box-shadow: 0 20px 40px -25px rgba(0,0,0,.6); }
    .plan-card.featured {
      border-color: rgba(224,181,100,.65);
      background: linear-gradient(165deg, #1A2150 0%, #0E1530 100%);
      box-shadow: 0 24px 42px -30px rgba(224,181,100,.6);
    }
    .plan-top { display: flex; justify-content: space-between; align-items: flex-start; gap: .65rem; }
    .plan-name {
      margin: 0;
      font-family: 'Cinzel', serif;
      letter-spacing: .05em;
      font-size: 1.12rem;
      color: var(--text);
    }
    .plan-badge {
      display: inline-block;
      font-size: .7rem;
      font-weight: 700;
      letter-spacing: .08em;
      text-transform: uppercase;
      color: #0A0E1F;
      background: linear-gradient(180deg, #F2D08C, #E0B564);
      border-radius: 999px;
      padding: .22rem .55rem;
    }
    .plan-price {
      margin: .1rem 0 0;
      font-size: 1.35rem;
      font-weight: 800;
      color: var(--gold-soft);
    }
    .plan-price small { font-size: .78rem; font-weight: 600; color: var(--muted); }
    .plan-desc { margin: 0; color: var(--muted); font-size: .92rem; }
    .plan-list {
      margin: .25rem 0 0;
      padding: 0;
      list-style: none;
      display: grid;
      gap: .45rem;
      color: var(--muted);
      font-size: .89rem;
    }
    .plan-list li {
      position: relative;
      padding-left: 1.05rem;
      line-height: 1.4;
    }
    .plan-list li::before {
      content: '';
      position: absolute;
      left: 0;
      top: .5em;
      width: .38rem;
      height: .38rem;
      border-radius: 50%;
      background: var(--gold);
      box-shadow: 0 0 0 2px rgba(224,181,100,.2);
    }
    .plans-note {
      margin-top: 1rem;
      padding: 1rem 1.1rem;
      border-radius: 14px;
      border: 1px solid rgba(224,181,100,.2);
      background: rgba(224,181,100,.06);
      color: var(--gold-soft);
      font-size: .9rem;
    }

    /* ===== CTA final ===== */
    .final-cta {
      background:
        radial-gradient(ellipse at 50% 0%, rgba(91,192,190,.10), transparent 60%),
        var(--bg);
      text-align: center;
    }
    .final-cta h2 { font-size: clamp(2rem, 4vw, 3rem); margin-bottom: 1rem; }
    .final-cta p { color: var(--muted); margin-bottom: 2rem; }

    /* ===== Footer ===== */
    footer {
      padding: 3rem 0 2rem;
      border-top: 1px solid var(--line);
      background: #07091A;
      color: var(--muted);
      font-size: .88rem;
    }
    .footer-grid {
      display: flex; flex-wrap: wrap;
      gap: 1.5rem; justify-content: space-between; align-items: center;
    }
    .footer-brand { display: flex; align-items: center; gap: .65rem; color: var(--text); }
    .footer-legal { display: flex; gap: .95rem; flex-wrap: wrap; font-size: .86rem; color: var(--muted); }
    .footer-legal a { color: var(--muted); border-bottom: 1px dashed rgba(224,181,100,.35); }
    .footer-legal a:hover { color: var(--gold); border-bottom-color: rgba(224,181,100,.75); }

    .reveal {
      opacity: 0; transform: translateY(28px);
      transition: opacity .8s ease, transform .8s ease;
    }
    .reveal.is-visible { opacity: 1; transform: translateY(0); }

    @media (prefers-reduced-motion: reduce) {
      .stars { animation: none !important; }
      .reveal { opacity: 1; transform: none; transition: none; }
    }
  </style>
</head>
<body>

  <!-- ===== NAV (OLYMPUS) ===== -->
  <header class="nav" id="nav">
    <div class="container nav-inner">
      <a class="brand" href="/">
        <span class="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 64 64" fill="none">
            <defs>
              <linearGradient id="brandGradV" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stop-color="#E0B564"/>
                <stop offset="100%" stop-color="#5BC0BE"/>
              </linearGradient>
            </defs>
            <path d="M4 52 L22 22 L32 38 L42 18 L60 52 Z" fill="url(#brandGradV)"/>
          </svg>
        </span>
        <span class="brand-text">GesMan <span>OLYMPUS</span></span>
      </a>
      <nav class="nav-links" aria-label="Principal">
        <a href="/">Inicio</a>
        <a href="/#heroes">Productos</a>
        <a href="/#contacto">Contacto</a>
      </nav>
      <a class="nav-cta" href="https://gesmanhermes.com/login/" target="_blank" rel="noopener">
        Login HERMES
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
      </a>
    </div>
  </header>

  <!-- ===== HERO VITRINA ===== -->
  <section class="hero-vitrina" id="top">
    <div class="stars" aria-hidden="true"></div>

    <div class="container hero-content">
      <span class="eyebrow">El Mensajero del Olimpo</span>
      <h1 class="display">HERMES</h1>
      <p class="subtitle">Software de Gestión de Servicio Técnico</p>
      <p class="tagline">
        <strong style="color:var(--gold)">GesMan HERMES</strong> conecta clientes, cotizaciones, técnicos y órdenes de servicio
        en un único flujo trazable. Diseñado para empresas que viven de cotizar, atender y resolver en terreno.
      </p>
      <div class="hero-ctas">
        <a class="btn btn-primary" href="https://gesmanhermes.com/" target="_blank" rel="noopener">
          Ir al sitio de HERMES
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/></svg>
        </a>
        <a class="btn btn-outline-cyan" href="https://gesmanhermes.com/login/" target="_blank" rel="noopener">
          Ir al Login de HERMES
        </a>
        <a class="btn btn-ghost" href="#funciones">Ver funciones</a>
      </div>
    </div>
  </section>

  <!-- ===== Banner informativo ===== -->
  <section style="padding: 2rem 0 0;">
    <div class="container">
      <div class="domain-banner reveal">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
        <span>
          <strong>¿Ya eres cliente de HERMES?</strong> El acceso a la aplicación está en
          <a href="https://gesmanhermes.com/login/" target="_blank" rel="noopener">gesmanhermes.com/login</a>.
          Esta página es una vitrina informativa dentro de GesMan OLYMPUS.
        </span>
      </div>
    </div>
  </section>

  <!-- ===== Funciones ===== -->
  <section class="features-sec" id="funciones">
    <div class="container">
      <div class="section-head reveal">
        <span class="eyebrow">Funciones de HERMES</span>
        <h2 class="section-title">Todo lo que necesitas para <em>gestionar servicio técnico</em>.</h2>
        <p class="lead">Las capacidades centrales de HERMES, organizadas para que la operación fluya sin fricción.</p>
      </div>

      <div class="features-grid">
        <article class="feature-card reveal">
          <div class="feature-ico" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 13.5V6.7a1.7 1.7 0 0 1 1.7-1.7h12.6A1.7 1.7 0 0 1 20 6.7v10.6a1.7 1.7 0 0 1-1.7 1.7H12"/><path d="M8 10h8M8 14h5"/></svg>
          </div>
          <h3>Clientes y contactos</h3>
          <p>Ficha unificada con historial comercial y de servicios para dar continuidad operativa a cada relación.</p>
        </article>

        <article class="feature-card reveal">
          <div class="feature-ico" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5h16v14H4z"/><path d="M7 9h10M7 13h6M15 17l2 2 4-4"/></svg>
          </div>
          <h3>Cotizaciones trazables</h3>
          <p>Creación profesional con estados claros desde borrador hasta aceptación y conversión a orden de servicio.</p>
        </article>

        <article class="feature-card reveal">
          <div class="feature-ico" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7h18M5 7v12h14V7"/><path d="M8 3v4M16 3v4"/></svg>
          </div>
          <h3>Órdenes de servicio</h3>
          <p>Asignación por técnico, prioridad y fecha en un flujo controlado que no pierde el hilo de la operación.</p>
        </article>

        <article class="feature-card reveal">
          <div class="feature-ico" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3"/><path d="M3 20a6 6 0 0 1 12 0"/><path d="m15 10 2 2 4-4"/></svg>
          </div>
          <h3>Coordinación de técnicos</h3>
          <p>Visibilidad de agenda y carga operativa para asignar con criterio y responder rápido a cada emergencia.</p>
        </article>

        <article class="feature-card reveal">
          <div class="feature-ico" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16v4H4z"/><path d="M4 13h16v4H4z"/></svg>
          </div>
          <h3>Inventario y adjuntos</h3>
          <p>Control de insumos, repuestos y documentos asociados a cada servicio para respaldar ejecución y costos.</p>
        </article>

        <article class="feature-card reveal">
          <div class="feature-ico" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 18V9M10 18V6M16 18v-4M22 18V11"/><path d="M3 18h20"/></svg>
          </div>
          <h3>Tablero operativo</h3>
          <p>Vista central para supervisar pendientes, avance diario y cumplimiento del equipo en tiempo real.</p>
        </article>
      </div>
    </div>
  </section>

  <!-- ===== Planes ===== -->
  <section class="plans" id="planes">
    <div class="container">
      <div class="section-head reveal">
        <span class="eyebrow">Planes HERMES</span>
        <h2 class="section-title">Elige el plan que mejor calza con <em>tu operación</em>.</h2>
        <p class="lead">Desde equipos pequeños hasta empresas con alta demanda operativa y múltiples técnicos.</p>
      </div>

      <div class="plans-grid">
        <article class="plan-card reveal">
          <div class="plan-top">
            <h3 class="plan-name">Mortal</h3>
          </div>
          <p class="plan-price">$9.990 <small>/ mes</small></p>
          <p class="plan-desc">Plan básico con las funciones actuales de HERMES.</p>
          <ul class="plan-list">
            <li>Clientes y contactos</li>
            <li>Cotizaciones trazables</li>
            <li>Órdenes de servicio</li>
            <li>Tablero operativo base</li>
          </ul>
        </article>

        <article class="plan-card featured reveal">
          <div class="plan-top">
            <h3 class="plan-name">Héroe</h3>
            <span class="plan-badge">Popular</span>
          </div>
          <p class="plan-price">$29.990 <small>/ mes</small></p>
          <p class="plan-desc">Funciones extendidas para operación en crecimiento.</p>
          <ul class="plan-list">
            <li>Hasta 5 usuarios técnicos</li>
            <li>Órdenes de servicio avanzadas</li>
            <li>Aplicación PWA</li>
            <li>Reportes de órdenes de servicio</li>
            <li>Carta Gantt</li>
          </ul>
        </article>

        <article class="plan-card reveal">
          <div class="plan-top">
            <h3 class="plan-name">Semidiós</h3>
          </div>
          <p class="plan-price">$49.990 <small>/ mes</small></p>
          <p class="plan-desc">Escala operacional para equipos de servicio más exigentes.</p>
          <ul class="plan-list">
            <li>Hasta 20 técnicos</li>
            <li>2 cuentas vendedor + 1 administrador interno</li>
            <li>Incluye todo Héroe</li>
            <li>Informes PDF por KPI</li>
            <li>Inventario para bodega interna</li>
            <li>Carta Gantt y cronograma</li>
          </ul>
        </article>

        <article class="plan-card reveal">
          <div class="plan-top">
            <h3 class="plan-name">Olímpico</h3>
          </div>
          <p class="plan-price">Personalizado</p>
          <p class="plan-desc">Plan corporativo para empresas con mayor volumen y requerimientos a medida.</p>
          <ul class="plan-list">
            <li>Todas las funciones de HERMES</li>
            <li>Hasta 50 técnicos</li>
            <li>Mayor límite de espacio</li>
            <li>Prioridad en tiempos de respuesta</li>
            <li>Configuración según necesidad</li>
          </ul>
        </article>
      </div>

      <div class="plans-note reveal" role="note">
        <strong>Reglas de uso de imágenes e informes:</strong>
        para mantener un rendimiento estable, se aplicarán límites de tamaño y cantidad de imágenes por informe.
        Estos límites se configurarán por plan para evitar saturación de la plataforma.
      </div>
    </div>
  </section>

  <!-- ===== CTA final ===== -->
  <section class="final-cta" id="contacto">
    <div class="container reveal">
      <span class="eyebrow">Comienza con HERMES</span>
      <h2 class="section-title">Ordena tu servicio técnico, <em>desde hoy</em>.</h2>
      <p class="lead" style="margin-inline:auto;">
        Cuéntanos cómo operas y te mostramos cómo aplicar HERMES a tu flujo real, sin frenar tu negocio.
      </p>
      <div class="hero-ctas" style="margin-top:1.5rem;">
        <a class="btn btn-primary" href="https://gesmanhermes.com/" target="_blank" rel="noopener">
          Ir al sitio de HERMES
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/></svg>
        </a>
        <a class="btn btn-ghost" href="https://gesmanhermes.com/login/" target="_blank" rel="noopener">
          Login app HERMES
        </a>
      </div>
    </div>
  </section>

  <!-- ===== Footer ===== -->
  <footer>
    <div class="container footer-grid">
      <div class="footer-brand">
        <span class="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 64 64" fill="none" width="22" height="22">
            <defs>
              <linearGradient id="footGV" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stop-color="#E0B564"/>
                <stop offset="100%" stop-color="#5BC0BE"/>
              </linearGradient>
            </defs>
            <path d="M4 52 L22 22 L32 38 L42 18 L60 52 Z" fill="url(#footGV)"/>
          </svg>
        </span>
        <span style="font-family:'Cinzel',serif;letter-spacing:.18em;">GesMan <span style="color:var(--gold)">OLYMPUS</span></span>
      </div>
      <div>
        © <?= $year ?> GesMan · El monte donde habitan los héroes del software de gestión.
        <div class="footer-legal" aria-label="Enlaces legales">
          <a href="/politica-privacidad.php">Política de Privacidad</a>
          <a href="/politica-cookies.php">Política de Cookies</a>
          <a href="/terminos-condiciones.php">Términos y Condiciones</a>
        </div>
        <div style="margin-top:.5rem;color:#a8b0c0;font-size:.86rem;">
          HERMES es un producto de la suite GesMan · 
          <a href="https://gesmanhermes.com/" target="_blank" rel="noopener" style="color:var(--muted);border-bottom:1px dashed rgba(224,181,100,.35);">Visitar gesmanhermes.com</a>
        </div>
      </div>
    </div>
  </footer>

  <script>
    // Navbar scroll state
    (function() {
      var nav = document.getElementById('nav');
      var onScroll = function() {
        if (window.scrollY > 24) nav.classList.add('scrolled');
        else nav.classList.remove('scrolled');
      };
      window.addEventListener('scroll', onScroll, { passive: true });
      onScroll();
    })();

    // Reveal on scroll
    (function() {
      if (!('IntersectionObserver' in window)) {
        document.querySelectorAll('.reveal').forEach(function(el){ el.classList.add('is-visible'); });
        return;
      }
      var io = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            io.unobserve(entry.target);
          }
        });
      }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
      document.querySelectorAll('.reveal').forEach(function(el){ io.observe(el); });
    })();
  </script>
</body>
</html>