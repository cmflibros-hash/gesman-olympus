<?php
// Enrutamiento por dominio para separar identidades de producto.
$host = strtolower(trim((string)($_SERVER['HTTP_HOST'] ?? '')));
$host = preg_replace('/:\d+$/', '', $host);
if (is_string($host) && str_contains($host, 'gesmanhermes.com')) {
  require __DIR__ . '/gesman-hermes.php';
  exit;
}

// GesMan OLYMPUS - Landing principal
// Vitrina institucional de los productos de la suite GesMan.
$year = date('Y');
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GesMan OLYMPUS — El Monte de los Sistemas de Gestión</title>
  <meta name="description" content="GesMan OLYMPUS es la vitrina de la suite GesMan. Conoce a ATLAS (CMMS) y HERMES (gestión de servicios técnicos), los héroes que llevan la operación de tu empresa al siguiente nivel.">
  <meta name="theme-color" content="#0A0E1F">
  <link rel="icon" type="image/svg+xml" href="assets/img/favicon-olympus.svg">
  <link rel="shortcut icon" href="assets/img/favicon-olympus.svg" type="image/svg+xml">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    /* ===== Reset & base ===== */
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

    /* ===== Colores ===== */
    :root {
      --bg: #0A0E1F;
      --bg-2: #111733;
      --bg-3: #1A2150;
      --gold: #E0B564;
      --gold-soft: #F2D08C;
      --cyan: #5BC0BE;
      --text: #F1F1F4;
      --muted: #A8B0C0;
      --line: rgba(224,181,100,0.18);
    }

    /* ===== Layout helpers ===== */
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
    .lead {
      color: var(--muted);
      font-size: 1.05rem;
      max-width: 680px;
    }

    /* ===== NAV ===== */
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

    /* ===== HERO ===== */
    .hero {
      position: relative;
      min-height: 100svh;
      display: grid; place-items: center;
      padding: 8rem 0 5rem;
      overflow: hidden;
      isolation: isolate;
    }
    .hero::before {
      content: ""; position: absolute; inset: 0; z-index: -3;
      background:
        radial-gradient(ellipse at 20% 10%, rgba(91,192,190,.12), transparent 55%),
        radial-gradient(ellipse at 80% 0%, rgba(224,181,100,.15), transparent 55%),
        linear-gradient(180deg, #0A0E1F 0%, #0E1530 55%, #0A0E1F 100%);
    }
    /* Cielo de estrellas */
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
    /* Silueta de la cordillera (horizonte limpio) */
    .mountain {
      position: absolute; left: 0; right: 0; bottom: -1px; z-index: -1;
      width: 100%; height: auto;
      filter: drop-shadow(0 -20px 40px rgba(0,0,0,.5));
    }
    /* Emblema heráldico central detrás del texto */
    .hero-emblem {
      position: absolute;
      top: 50%; left: 50%;
      transform: translate(-50%, -54%);
      width: min(640px, 78vmin);
      height: auto;
      z-index: -1;
      pointer-events: none;
      opacity: .14;
      filter: drop-shadow(0 0 30px rgba(224,181,100,.25));
      animation: emblemPulse 7s ease-in-out infinite alternate;
    }
    @keyframes emblemPulse {
      0%   { opacity: .10; filter: drop-shadow(0 0 18px rgba(224,181,100,.18)); }
      100% { opacity: .18; filter: drop-shadow(0 0 36px rgba(224,181,100,.38)); }
    }
    @media (max-width: 720px) {
      .hero-emblem { opacity: .11; width: 86vmin; }
    }

    .hero-content { text-align: center; position: relative; z-index: 1; }
    .hero h1 {
      font-size: clamp(3rem, 9vw, 6.5rem);
      line-height: .95;
      margin: 1.25rem 0 1rem;
      background: linear-gradient(180deg, #FFF 0%, #F2D08C 55%, #E0B564 100%);
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
      text-shadow: 0 4px 40px rgba(224,181,100,.18);
    }
    .hero .subtitle {
      font-family: 'Cinzel', serif;
      font-size: clamp(1rem, 1.6vw, 1.25rem);
      letter-spacing: .25em;
      text-transform: uppercase;
      color: var(--cyan);
      margin-bottom: 1.25rem;
    }
    .hero .tagline {
      max-width: 720px;
      margin: 1.25rem auto 2rem;
      color: var(--muted);
      font-size: clamp(1rem, 1.4vw, 1.15rem);
      text-shadow: 0 1px 2px rgba(0,0,0,.55), 0 0 18px rgba(10,14,31,.85);
    }
    .hero .tagline strong { text-shadow: 0 1px 2px rgba(0,0,0,.6); }
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
    .scroll-cue {
      position: absolute; bottom: 2rem; left: 50%; transform: translateX(-50%);
      color: var(--muted); font-size: .75rem; letter-spacing: .3em; text-transform: uppercase;
      display: flex; flex-direction: column; align-items: center; gap: .5rem;
      animation: bob 2.4s ease-in-out infinite;
    }
    .scroll-cue::after {
      content: ""; width: 1px; height: 36px;
      background: linear-gradient(180deg, var(--gold), transparent);
    }
    @keyframes bob { 0%,100% { transform: translate(-50%, 0);} 50% { transform: translate(-50%, 6px);} }

    /* ===== Sections ===== */
    section { padding: 6rem 0; position: relative; }
    .section-head { max-width: 760px; margin: 0 auto 3rem; text-align: center; }
    .section-head .lead { margin-inline: auto; }

    /* ===== "¿Qué es GesMan?" ===== */
    .about {
      background:
        radial-gradient(ellipse at 50% 0%, rgba(91,192,190,.08), transparent 60%),
        var(--bg);
      border-top: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
    }
    .about-grid {
      display: grid;
      grid-template-columns: 1.1fr 1fr;
      gap: 3rem;
      align-items: center;
    }
    @media (max-width: 880px) { .about-grid { grid-template-columns: 1fr; } }
    .about-grid h2 { font-size: clamp(1.8rem, 3.5vw, 2.4rem); margin: 1rem 0; }
    .about-grid p { color: var(--muted); margin-bottom: 1rem; }
    .about-grid strong { color: var(--gold); font-weight: 600; }
    .pillars {
      display: grid; gap: 1rem;
    }
    .pillar {
      display: flex; gap: 1rem; align-items: flex-start;
      padding: 1.1rem 1.25rem;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255,255,255,.02);
      transition: transform .3s ease, border-color .3s ease, background .3s ease;
    }
    .pillar:hover { transform: translateX(4px); border-color: var(--gold); background: rgba(224,181,100,.04); }
    .pillar-ico {
      flex: 0 0 auto; width: 40px; height: 40px; border-radius: 10px;
      display: grid; place-items: center;
      background: rgba(91,192,190,.12);
      color: var(--cyan);
    }
    .pillar h4 { margin: 0 0 .25rem; font-family: 'Inter', sans-serif; font-weight: 600; color: var(--text); font-size: 1rem; }
    .pillar p { margin: 0; color: var(--muted); font-size: .92rem; }

    /* ===== Productos (Los héroes del Olimpo) ===== */
    .heroes { background: var(--bg); }
    .heroes-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 2rem;
    }
    @media (max-width: 980px) { .heroes-grid { grid-template-columns: 1fr; } }

    .hero-card {
      position: relative;
      border-radius: 20px;
      padding: 2.25rem;
      background: linear-gradient(165deg, #131A3A 0%, #0E1530 100%);
      border: 1px solid var(--line);
      overflow: hidden;
      transition: transform .4s ease, border-color .4s ease, box-shadow .4s ease;
      display: flex; flex-direction: column;
    }
    .hero-card::before {
      content: ""; position: absolute; inset: -1px;
      border-radius: 20px; padding: 1px;
      background: linear-gradient(135deg, var(--gold), transparent 40%, transparent 60%, var(--cyan));
      -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
      -webkit-mask-composite: xor; mask-composite: exclude;
      opacity: 0; transition: opacity .4s ease;
      pointer-events: none;
    }
    .hero-card:hover { transform: translateY(-6px); box-shadow: 0 25px 60px -25px rgba(0,0,0,.6); }
    .hero-card:hover::before { opacity: 1; }
    .hero-card .glow {
      position: absolute; width: 320px; height: 320px;
      top: -120px; right: -120px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(224,181,100,.22), transparent 65%);
      filter: blur(40px);
      pointer-events: none;
    }
    .hero-card.hermes .glow {
      background: radial-gradient(circle, rgba(91,192,190,.22), transparent 65%);
    }
    .card-tag {
      font-family: 'Cinzel', serif;
      font-size: .72rem;
      letter-spacing: .32em;
      text-transform: uppercase;
      color: var(--gold);
    }
    .hero-card.hermes .card-tag { color: var(--cyan); }
    .card-logo {
      height: 56px;
      margin: 1rem 0 1.25rem;
      display: flex; align-items: center;
    }
    .card-logo img { height: 100%; width: auto; max-width: 100%; }
    .card-subtitle {
      font-family: 'Cinzel', serif;
      font-size: 1.05rem;
      color: var(--text);
      margin: 0 0 .25rem;
    }
    .card-desc { color: var(--muted); margin: .25rem 0 1.5rem; }
    .features { list-style: none; padding: 0; margin: 0 0 2rem; display: grid; gap: .65rem; }
    .features li {
      display: flex; gap: .6rem; align-items: flex-start;
      color: var(--text); font-size: .94rem;
    }
    .features li::before {
      content: ""; flex: 0 0 auto;
      width: 8px; height: 8px; margin-top: .55rem;
      border-radius: 50%;
      background: var(--gold);
      box-shadow: 0 0 12px var(--gold);
    }
    .hero-card.hermes .features li::before {
      background: var(--cyan);
      box-shadow: 0 0 12px var(--cyan);
    }
    .card-cta-row { margin-top: auto; display: flex; gap: .75rem; flex-wrap: wrap; }
    .card-cta {
      display: inline-flex; align-items: center; gap: .5rem;
      padding: .75rem 1.25rem;
      border-radius: 999px;
      font-size: .9rem; font-weight: 600;
      transition: transform .25s ease, background .25s ease, color .25s ease;
    }
    .card-cta.primary {
      background: var(--gold); color: #0A0E1F;
    }
    .hero-card.hermes .card-cta.primary { background: var(--cyan); color: #0A0E1F; }
    .card-cta.primary:hover { transform: translateY(-2px); }
    .card-cta.ghost {
      color: var(--muted);
      border: 1px solid rgba(255,255,255,.15);
    }
    .card-cta.ghost:hover { color: var(--text); border-color: rgba(255,255,255,.35); }
    .badge-soon {
      display: inline-block; margin-left: .5rem;
      font-size: .65rem; letter-spacing: .2em; text-transform: uppercase;
      padding: .15rem .55rem; border-radius: 999px;
      background: rgba(224,181,100,.12); color: var(--gold);
      border: 1px solid var(--line);
    }

    /* ===== Roadmap futuro ===== */
    .roadmap {
      background: linear-gradient(180deg, var(--bg) 0%, #0E1530 100%);
      border-top: 1px solid var(--line);
    }
    .roadmap-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      margin-top: 2rem;
    }
    .road-card {
      padding: 1.5rem;
      border: 1px dashed rgba(255,255,255,.12);
      border-radius: 14px;
      background: rgba(255,255,255,.015);
      transition: border-color .3s ease, transform .3s ease;
    }
    .road-card:hover { border-color: var(--gold); transform: translateY(-3px); }
    .road-card h4 {
      font-family: 'Cinzel', serif;
      letter-spacing: .15em;
      color: var(--gold);
      font-size: 1rem;
      margin: 0 0 .5rem;
    }
    .road-card p { margin: 0; color: var(--muted); font-size: .9rem; }

    /* ===== CTA final ===== */
    .final-cta {
      background:
        radial-gradient(ellipse at 50% 0%, rgba(224,181,100,.15), transparent 60%),
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

    /* ===== Cookies banner ===== */
    .cookie-banner {
      position: fixed;
      left: 1rem;
      right: 1rem;
      bottom: 1rem;
      z-index: 60;
      border: 1px solid rgba(224,181,100,.28);
      border-radius: 14px;
      background: linear-gradient(180deg, rgba(14,21,48,.98), rgba(10,14,31,.98));
      box-shadow: 0 18px 38px rgba(0,0,0,.45);
      padding: 1rem;
      display: none;
    }
    .cookie-banner.is-visible { display: block; }
    .cookie-inner { display: grid; gap: .9rem; }
    .cookie-title {
      margin: 0;
      font-family: 'Cinzel', serif;
      letter-spacing: .08em;
      color: var(--gold-soft);
      font-size: .98rem;
    }
    .cookie-text { margin: 0; color: var(--muted); font-size: .92rem; line-height: 1.5; }
    .cookie-actions { display: flex; gap: .6rem; flex-wrap: wrap; }
    .cookie-btn {
      border: 1px solid rgba(224,181,100,.35);
      background: transparent;
      color: var(--text);
      font-size: .86rem;
      padding: .6rem .85rem;
      border-radius: 10px;
      cursor: pointer;
      transition: .2s ease;
    }
    .cookie-btn:hover { border-color: rgba(224,181,100,.65); color: var(--gold-soft); }
    .cookie-btn.primary { background: linear-gradient(180deg, #F2D08C, #E0B564); color: #0A0E1F; border-color: transparent; font-weight: 700; }
    .cookie-links { display: flex; gap: .85rem; flex-wrap: wrap; font-size: .83rem; color: var(--muted); }
    .cookie-links a { color: var(--muted); text-decoration: underline; text-underline-offset: 2px; }
    .cookie-links a:hover { color: var(--gold); }
    @media (max-width: 720px) {
      .cookie-banner { left: .75rem; right: .75rem; bottom: .75rem; }
      .cookie-btn { width: 100%; }
    }

    /* ===== Reveal animation ===== */
    .reveal {
      opacity: 0; transform: translateY(28px);
      transition: opacity .8s ease, transform .8s ease;
    }
    .reveal.is-visible { opacity: 1; transform: translateY(0); }

    @media (prefers-reduced-motion: reduce) {
      .stars, .scroll-cue, .hero-emblem { animation: none !important; }
      .reveal { opacity: 1; transform: none; transition: none; }
    }
  </style>
</head>
<body>

  <!-- ============ NAV ============ -->
  <header class="nav" id="nav">
    <div class="container nav-inner">
      <a class="brand" href="#top">
        <span class="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 64 64" fill="none">
            <defs>
              <linearGradient id="brandGrad" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stop-color="#E0B564"/>
                <stop offset="100%" stop-color="#5BC0BE"/>
              </linearGradient>
            </defs>
            <path d="M4 52 L22 22 L32 38 L42 18 L60 52 Z" fill="url(#brandGrad)"/>
          </svg>
        </span>
        <span class="brand-text">GesMan <span>OLYMPUS</span></span>
      </a>
      <nav class="nav-links" aria-label="Principal">
        <a href="#about">GesMan</a>
        <a href="#heroes">Productos</a>
        <a href="#roadmap">Futuro</a>
        <a href="#contacto">Contacto</a>
      </nav>
      <a class="nav-cta" href="#heroes">
        Explorar el Olimpo
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
      </a>
    </div>
  </header>

  <!-- ============ HERO ============ -->
  <section class="hero" id="top">
    <div class="stars" aria-hidden="true"></div>

    <!-- Emblema heráldico del Olimpo (medallón decorativo central) -->
    <svg class="hero-emblem" viewBox="0 0 400 400" aria-hidden="true">
      <defs>
        <linearGradient id="emblemGold" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#F8E2A8"/>
          <stop offset="100%" stop-color="#D4A14A"/>
        </linearGradient>
        <radialGradient id="emblemHalo" cx=".5" cy=".5" r=".5">
          <stop offset="0%" stop-color="#F2D08C" stop-opacity=".55"/>
          <stop offset="70%" stop-color="#E0B564" stop-opacity=".06"/>
          <stop offset="100%" stop-color="#0A0E1F" stop-opacity="0"/>
        </radialGradient>
      </defs>

      <!-- Halo radial -->
      <circle cx="200" cy="200" r="195" fill="url(#emblemHalo)"/>

      <!-- Anillos -->
      <circle cx="200" cy="200" r="180" fill="none" stroke="url(#emblemGold)" stroke-width="1.4" opacity=".85"/>
      <circle cx="200" cy="200" r="168" fill="none" stroke="url(#emblemGold)" stroke-width=".6" opacity=".55"/>

      <!-- Ticks radiales (16) entre los dos anillos -->
      <g stroke="url(#emblemGold)" stroke-width="1" opacity=".55">
        <line x1="200" y1="173" x2="200" y2="180"/>
        <line x1="200" y1="220" x2="200" y2="227"/>
        <line x1="173" y1="200" x2="180" y2="200"/>
        <line x1="220" y1="200" x2="227" y2="200"/>
        <!-- diagonales 45° -->
        <line x1="181" y1="181" x2="186" y2="186"/>
        <line x1="219" y1="181" x2="214" y2="186"/>
        <line x1="181" y1="219" x2="186" y2="214"/>
        <line x1="219" y1="219" x2="214" y2="214"/>
        <!-- intermedios 22.5° -->
        <line x1="190" y1="174" x2="192" y2="181"/>
        <line x1="210" y1="174" x2="208" y2="181"/>
        <line x1="190" y1="226" x2="192" y2="219"/>
        <line x1="210" y1="226" x2="208" y2="219"/>
        <line x1="174" y1="190" x2="181" y2="192"/>
        <line x1="174" y1="210" x2="181" y2="208"/>
        <line x1="226" y1="190" x2="219" y2="192"/>
        <line x1="226" y1="210" x2="219" y2="208"/>
      </g>

      <!-- Silueta sutil de cumbre dentro del medallón -->
      <path d="M70 250 L130 195 L170 225 L200 180 L240 220 L280 195 L330 250 Z"
            fill="url(#emblemGold)" opacity=".10"/>

      <!-- Templo griego centrado -->
      <g stroke="url(#emblemGold)" fill="none" stroke-linecap="square">
        <!-- Frontón -->
        <path d="M-78 -40 L0 -90 L78 -40 Z" stroke-width="2.2" transform="translate(200 200)"/>
        <!-- Línea horizontal frontón -->
        <line x1="122" y1="160" x2="278" y2="160" stroke-width="2"/>
        <!-- Arquitrabe -->
        <rect x="124" y="160" width="152" height="10" stroke-width="2"/>
        <!-- Capitel (banda fina) -->
        <line x1="128" y1="172" x2="272" y2="172" stroke-width="1.4" opacity=".85"/>
        <!-- Columnas (6, dóricas estilizadas) -->
        <g stroke-width="2.2">
          <line x1="138" y1="172" x2="138" y2="242"/>
          <line x1="164" y1="172" x2="164" y2="242"/>
          <line x1="186" y1="172" x2="186" y2="242"/>
          <line x1="214" y1="172" x2="214" y2="242"/>
          <line x1="236" y1="172" x2="236" y2="242"/>
          <line x1="262" y1="172" x2="262" y2="242"/>
        </g>
        <!-- Estilóbato (escalones) -->
        <line x1="122" y1="242" x2="278" y2="242" stroke-width="2"/>
        <line x1="118" y1="248" x2="282" y2="248" stroke-width="2.4"/>
        <line x1="114" y1="254" x2="286" y2="254" stroke-width="2.8"/>
      </g>

      <!-- Estrella central en el frontón -->
      <circle cx="200" cy="135" r="2.4" fill="url(#emblemGold)"/>

      <!-- Coronas de laurel (ramas inferiores) -->
      <g fill="none" stroke="url(#emblemGold)" stroke-width="1.4" opacity=".8">
        <path d="M110 280 Q150 320 200 326"/>
        <path d="M290 280 Q250 320 200 326"/>
      </g>
      <g fill="url(#emblemGold)" opacity=".85">
        <!-- Hojas izquierda -->
        <ellipse cx="118" cy="288" rx="5" ry="2" transform="rotate(-35 118 288)"/>
        <ellipse cx="132" cy="302" rx="5" ry="2" transform="rotate(-25 132 302)"/>
        <ellipse cx="150" cy="314" rx="5" ry="2" transform="rotate(-15 150 314)"/>
        <ellipse cx="172" cy="322" rx="5" ry="2" transform="rotate(-5 172 322)"/>
        <!-- Hojas derecha -->
        <ellipse cx="282" cy="288" rx="5" ry="2" transform="rotate(35 282 288)"/>
        <ellipse cx="268" cy="302" rx="5" ry="2" transform="rotate(25 268 302)"/>
        <ellipse cx="250" cy="314" rx="5" ry="2" transform="rotate(15 250 314)"/>
        <ellipse cx="228" cy="322" rx="5" ry="2" transform="rotate(5 228 322)"/>
        <!-- Nudo central -->
        <circle cx="200" cy="328" r="3"/>
      </g>
    </svg>

    <!-- Silueta de la cordillera (horizonte limpio, sin templo) -->
    <svg class="mountain" viewBox="0 0 1440 420" preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient id="mountG1" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#1A2150"/>
          <stop offset="100%" stop-color="#0A0E1F"/>
        </linearGradient>
        <linearGradient id="mountG2" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#111733"/>
          <stop offset="100%" stop-color="#0A0E1F"/>
        </linearGradient>
        <linearGradient id="snow" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#F2D08C" stop-opacity=".55"/>
          <stop offset="100%" stop-color="#E0B564" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <!-- Cordillera lejana -->
      <path d="M0 320 L160 240 L280 285 L400 220 L520 275 L660 215 L800 260 L940 220 L1080 270 L1200 230 L1320 285 L1440 240 L1440 420 L0 420 Z" fill="url(#mountG2)" opacity=".7"/>
      <!-- Cordillera frontal con cumbre central destacada -->
      <path d="M0 380 L120 330 L240 360 L380 290 L520 330 L650 250 L760 190 L870 250 L1000 295 L1140 260 L1280 320 L1440 280 L1440 420 L0 420 Z" fill="url(#mountG1)"/>
      <!-- Suave reflejo dorado en la cumbre central (sutil, no protagonista) -->
      <path d="M720 218 L760 190 L800 218 L785 224 L760 220 L735 224 Z" fill="url(#snow)" opacity=".55"/>
    </svg>

    <div class="container hero-content">
      <span class="eyebrow">La Vitrina de la Suite GesMan</span>
      <h1 class="display">OLYMPUS</h1>
      <p class="subtitle">El Monte de los Sistemas de Gestión</p>
      <p class="tagline">
        En la cima del Olimpo habitan los héroes, dioses y semidioses que dan forma al futuro de
        <strong style="color:var(--gold)">GesMan</strong>. Cada uno es un sistema, una promesa de productividad y orden para tu empresa.
      </p>
      <div class="hero-ctas">
        <a class="btn btn-primary" href="#heroes">
          Conocer a los héroes
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
        </a>
        <a class="btn btn-ghost" href="#about">¿Qué es GesMan?</a>
      </div>
    </div>

    <div class="scroll-cue" aria-hidden="true">Descender</div>
  </section>

  <!-- ============ ¿Qué es GesMan? ============ -->
  <section class="about" id="about">
    <div class="container about-grid">
      <div class="reveal">
        <span class="eyebrow">Quiénes somos</span>
        <h2>Una suite, <em>muchos héroes.</em></h2>
        <p>
          <strong>GesMan</strong> es una familia de sistemas de gestión empresarial diseñados para resolver, cada uno,
          un dominio crítico de la operación: mantenimiento, servicios técnicos, comercial, terreno y más.
        </p>
        <p>
          <strong>OLYMPUS</strong> es la vitrina —el monte sagrado— donde se exhiben todos esos productos.
          Aquí no hablamos de un solo software: hablamos de un <em style="color:var(--cyan);font-style:normal">ecosistema</em> pensado para
          crecer contigo, módulo a módulo, héroe a héroe.
        </p>
      </div>
      <div class="pillars reveal">
        <div class="pillar">
          <div class="pillar-ico" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 L2 7 V17 L12 22 L22 17 V7 Z"/><path d="M2 7 L12 12 L22 7"/><path d="M12 22 V12"/></svg>
          </div>
          <div>
            <h4>Modular y especializado</h4>
            <p>Cada producto resuelve un dominio con profundidad real, no con funcionalidades de adorno.</p>
          </div>
        </div>
        <div class="pillar">
          <div class="pillar-ico" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3 a14 14 0 0 1 0 18 M12 3 a14 14 0 0 0 0 18"/></svg>
          </div>
          <div>
            <h4>Pensado para empresas reales</h4>
            <p>Construido desde la operación: terreno, oficina, técnicos, clientes. Sin atajos teóricos.</p>
          </div>
        </div>
        <div class="pillar">
          <div class="pillar-ico" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 L4 14 H12 L11 22 L20 10 H12 Z"/></svg>
          </div>
          <div>
            <h4>Dinámico, vivo, evolucionando</h4>
            <p>La suite crece. Nuevos héroes se incorporan al Olimpo a medida que se conquistan nuevos retos.</p>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- ============ HÉROES (Productos) ============ -->
  <section class="heroes" id="heroes">
    <div class="container">
      <div class="section-head reveal">
        <span class="eyebrow">Los héroes del Olimpo</span>
        <h2 class="section-title">Conoce a <em>los habitantes</em> del monte.</h2>
        <p class="lead">Sistemas dedicados, cada uno con su mitología, cada uno con su misión.</p>
      </div>

      <div class="heroes-grid">

        <!-- ===== ATLAS ===== -->
        <article class="hero-card atlas reveal">
          <div class="glow" aria-hidden="true"></div>
          <span class="card-tag">El Titán · CMMS</span>
          <div class="card-logo">
            <img src="assets/img/logo-atlas-white.svg" alt="GesMan ATLAS" loading="lazy" width="240" height="56">
          </div>
          <p class="card-subtitle">Sostiene el mundo del mantenimiento.</p>
          <p class="card-desc">
            <strong style="color:var(--gold)">GesMan ATLAS</strong> es el sistema CMMS dedicado a planificar, controlar y auditar
            la gestión de mantenimiento de activos. Diseñado para industrias que no pueden detenerse.
          </p>
          <ul class="features">
            <li>Gestión completa de activos, equipos y ubicaciones técnicas</li>
            <li>Órdenes de trabajo, planes preventivos y correctivos</li>
            <li>Inspecciones digitales con evidencia fotográfica y firma</li>
            <li>Inventario, repuestos y consumos por OT</li>
            <li>Indicadores, informes PDF y carta Gantt operativa</li>
            <li>Gestión de personal técnico, certificaciones y reuniones</li>
          </ul>
          <div class="card-cta-row">
            <a class="card-cta primary" href="gesman-atlas.php">Conoce sus funciones</a>
            <a class="card-cta ghost" href="#contacto">Hablar con ventas</a>
          </div>
        </article>

        <!-- ===== HERMES ===== -->
        <article class="hero-card hermes reveal">
          <div class="glow" aria-hidden="true"></div>
          <span class="card-tag">El Mensajero · Servicios Técnicos</span>
          <div class="card-logo">
            <img src="assets/img/logo-hermes-white.svg" alt="GesMan HERMES" loading="lazy" width="240" height="56">
          </div>
          <p class="card-subtitle">Conecta clientes, técnicos y servicio.</p>
          <p class="card-desc">
            <strong style="color:var(--cyan)">GesMan HERMES</strong> es el sistema de gestión de servicios técnicos pensado para empresas
            que cotizan, atienden y resuelven en terreno. Del primer contacto al cierre de la orden, en un solo flujo.
          </p>
          <ul class="features">
            <li>Gestión de clientes, contactos y datos de empresa</li>
            <li>Cotizaciones profesionales con seguimiento de estado</li>
            <li>Órdenes de servicio asignables a técnicos propios</li>
            <li>Administración de técnicos, agenda y carga de trabajo</li>
            <li>Inventario y adjuntos por orden / cotización</li>
            <li>Tablero operativo centralizado para el responsable</li>
          </ul>
          <div class="card-cta-row">
            <a class="card-cta primary" href="hermes-vitrina.php">Conoce sus funciones</a>
            <a class="card-cta ghost" href="https://gesmanhermes.com/" target="_blank" rel="noopener">Ir al sitio HERMES</a>
          </div>
        </article>

      </div>
    </div>
  </section>

  <!-- ============ Próximos héroes ============ -->
  <section class="roadmap" id="roadmap">
    <div class="container">
      <div class="section-head reveal">
        <span class="eyebrow">El Olimpo sigue creciendo</span>
        <h2 class="section-title">Próximos <em>héroes en camino</em>.</h2>
        <p class="lead">Cada nueva conquista operativa se convierte en un nuevo habitante del monte.</p>
      </div>
      <div class="roadmap-grid reveal">
        <div class="road-card">
          <h4>NUEVOS MÓDULOS</h4>
          <p>Extensiones especializadas para ATLAS y HERMES, según industria y operación.</p>
        </div>
        <div class="road-card">
          <h4>APP MÓVIL</h4>
          <p>Terreno conectado: técnicos ejecutando OT y servicios desde el celular, online u offline.</p>
        </div>
        <div class="road-card">
          <h4>INTEGRACIONES</h4>
          <p>Conexión con ERPs, facturación electrónica, IoT y sensores en planta.</p>
        </div>
        <div class="road-card">
          <h4>NUEVOS DIOSES</h4>
          <p>Más productos GesMan llegarán al Olimpo: comercial, terreno, BI operacional y más.</p>
        </div>
      </div>
    </div>
  </section>

  <!-- ============ CTA final ============ -->
  <section class="final-cta" id="contacto">
    <div class="container reveal">
      <span class="eyebrow">Subamos al Olimpo</span>
      <h2 class="section-title">¿Listo para que tu operación <em>habite la cumbre?</em></h2>
      <p class="lead" style="margin-inline:auto;">
        Cuéntanos qué sistema te interesa, agendamos una demo y diseñamos contigo el camino hacia el monte.
      </p>
      <div class="hero-ctas" style="margin-top:1.5rem;">
        <a class="btn btn-primary" href="mailto:contacto@gesmanolympus.com?subject=Quiero%20conocer%20la%20suite%20GesMan">
          Contactar al Olimpo
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16v12H4z"/><path d="M4 6l8 7 8-7"/></svg>
        </a>
        <a class="btn btn-ghost" href="#heroes">Ver productos de nuevo</a>
      </div>
    </div>
  </section>

  <!-- ============ FOOTER ============ -->
  <footer>
    <div class="container footer-grid">
      <div class="footer-brand">
        <span class="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 64 64" fill="none" width="22" height="22">
            <defs>
              <linearGradient id="footG" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stop-color="#E0B564"/>
                <stop offset="100%" stop-color="#5BC0BE"/>
              </linearGradient>
            </defs>
            <path d="M4 52 L22 22 L32 38 L42 18 L60 52 Z" fill="url(#footG)"/>
          </svg>
        </span>
        <span style="font-family:'Cinzel',serif;letter-spacing:.18em;">GesMan <span style="color:var(--gold)">OLYMPUS</span></span>
      </div>
      <div>
        © <?= $year ?> GesMan · El monte donde habitan los héroes del software de gestión.
        <div class="footer-legal" aria-label="Enlaces legales">
          <a href="politica-privacidad.php">Política de Privacidad</a>
          <a href="politica-cookies.php">Política de Cookies</a>
          <a href="terminos-condiciones.php">Términos y Condiciones</a>
        </div>
        <div style="margin-top:.55rem;color:#a8b0c0;font-size:.86rem;">
          Soporte comercial: <a href="mailto:contacto@gesmanolympus.com?subject=Soporte%20GesMan%20OLYMPUS">contacto@gesmanolympus.com</a>
          · Reportes de seguridad: <a href="mailto:contacto@gesmanolympus.com?subject=Incidente%20de%20seguridad%20OLYMPUS">canal de seguridad</a>
        </div>
      </div>
    </div>
  </footer>

  <aside class="cookie-banner" id="cookieBanner" role="dialog" aria-live="polite" aria-label="Consentimiento de cookies">
    <div class="cookie-inner">
      <h3 class="cookie-title">Privacidad y Cookies</h3>
      <p class="cookie-text">
        Utilizamos cookies esenciales para el funcionamiento del sitio. Con tu consentimiento, podremos habilitar cookies analíticas o de marketing.
        Puedes aceptar, rechazar las opcionales o revisar el detalle en nuestras políticas.
      </p>
      <div class="cookie-actions">
        <button type="button" class="cookie-btn primary" data-cookie-action="accept-all">Aceptar cookies</button>
        <button type="button" class="cookie-btn" data-cookie-action="essential-only">Solo esenciales</button>
      </div>
      <div class="cookie-links">
        <a href="politica-cookies.php">Ver Política de Cookies</a>
        <a href="politica-privacidad.php">Ver Política de Privacidad</a>
      </div>
    </div>
  </aside>

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

    // Consentimiento de cookies (almacenamiento local)
    (function() {
      var CONSENT_KEY = 'gesman_cookie_consent_v1';
      var banner = document.getElementById('cookieBanner');
      if (!banner) return;

      var current = null;
      try {
        current = localStorage.getItem(CONSENT_KEY);
      } catch (e) {
        current = null;
      }

      if (!current) {
        banner.classList.add('is-visible');
      }

      var sendConsent = function(payload) {
        try {
          fetch('/consent-track.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({
              consent_type: 'cookie_banner',
              decision: payload.decision,
              product_scope: 'olympus',
              policy_version: 'OLY-LEGAL-2026-05',
              source_page: window.location.pathname
            })
          });
        } catch (e) {
          // No interrumpe UX si la traza no se puede enviar.
        }
      };

      banner.addEventListener('click', function(event) {
        var target = event.target;
        if (!(target instanceof HTMLElement)) return;
        var action = target.getAttribute('data-cookie-action');
        if (!action) return;

        var payload = {
          decision: action === 'accept-all' ? 'accept_all' : 'essential_only',
          updatedAt: new Date().toISOString()
        };

        try {
          localStorage.setItem(CONSENT_KEY, JSON.stringify(payload));
        } catch (e) {
          // Si el navegador bloquea storage, solo ocultamos el banner durante la sesión.
        }

        sendConsent(payload);

        banner.classList.remove('is-visible');
      });
    })();
  </script>
</body>
</html>
