# AGENTS.md

## Objetivo
Este archivo define reglas operativas obligatorias para cualquier agente que trabaje en este workspace.

## Reglas de Comunicación
- Responder siempre en espanol.
- Si hay duda de alcance o impacto en produccion, detenerse y pedir confirmacion.
- No asumir rutas activas ni docroot: validar primero en servidor.

## Regla de Contexto Obligatorio (CRITICO)
Antes de cualquier accion, el agente debe declarar explicitamente:
`"Contexto activo: dominio [X] clasificado como [CORE/AFFILIATE]"`
- Esta clasificacion debe mantenerse durante toda la tarea.
- Si se cambia de dominio, se reinicia el contexto y se vuelve a declarar.
- Cualquier accion que cruce entre categorias sin reiniciar contexto queda prohibida.

## Clasificacion de Dominios
Antes de tocar cualquier archivo, el agente debe clasificar el dominio en una de estas categorias:

- **[CORE]** Dominios del producto principal GesMan:
  - `gesmanolympus.com` — Landing principal de la suite GesMan (OLYMPUS)
  - `gesmanhermes.com` — Producto HERMES (gestion de servicio tecnico)
  - Cualquier futuro dominio propio de la suite GesMan.

- **[AFFILIATE]** Dominios de paginas de afiliados (marketing):
  - Cualquier dominio o subdominio en el VPS que no pertenezca a GesMan.
  - Proyectos independientes de generacion de ingresos pasivos.
  - Landing pages simples, lead magnets, paginas de venta de productos de terceros.

## Reglas Basicas del VPS — [CORE] GesMan

### Dominio principal (`gesmanolympus.com`)
- Debe mantener el landing principal de la suite GesMan (OLYMPUS).
- Debe incluir y mantener operativas sus paginas esenciales:
  - Terminos y condiciones
  - Politica de cookies
  - Politica de privacidad

### Dominios secundarios de GesMan
- Se iran agregando mas dominios de productos de la suite.
- El primero es `gesmanhermes.com`.
- `gesmanhermes.com` debe tener:
  - Landing propio y diferente de OLYMPUS.
  - Sus paginas esenciales propias (terminos, cookies, privacidad).
  - Su login funcional de app web en `/login/`.

### Separacion estricta por dominio ([CORE])
- Nunca mezclar contenido, estilos, rutas o logica entre dominios.
- Nunca dejar que cambios de un dominio rompan o alteren el otro.
- Nunca redirigir automaticamente el root de `gesmanhermes.com` al login.
- Antes de cualquier deploy, validar siempre que cada dominio conserve su identidad y estructura.

## Reglas Basicas del VPS — [AFFILIATE] Afiliados

### Estructura de carpetas obligatoria
- Cada proyecto de afiliado debe residir en: `/var/www/affiliate/{nombre-proyecto}/`
- Cada proyecto tiene su propio virtual host o alias de Apache.
- No se permite codigo fuera de su carpeta asignada.
- No se permite compartir carpetas entre proyectos de afiliados.

### Aislamiento total entre categorias ([CORE] vs [AFFILIATE])
- Un cambio en [CORE] NUNCA debe afectar a [AFFILIATE].
- Un cambio en [AFFILIATE] NUNCA debe afectar a [CORE].
- Los proyectos de afiliados NO pueden:
  - Leer, escribir o depender de archivos de [CORE].
  - Compartir sesiones, cookies o variables de PHP con [CORE].
  - Usar la misma base de datos de GesMan.
  - Usar las mismas variables de entorno o credenciales.
  - Incluir (`require`, `include`) archivos de la suite GesMan.

### Reglas de implementacion para afiliados
- Priorizar simplicidad y velocidad de carga (no meter frameworks pesados).
- Usar tecnologias simples: HTML/CSS/JS estatico o PHP minimo.
- Los assets (CSS/JS/imagenes) deben ser locales al proyecto o CDN confiable.
- No implementar logica compleja de usuarios a menos que sea estrictamente necesario.
- No compartir estilos, branding o identidad visual con GesMan.

## Reglas de Cambios en Produccion ([CORE] y [AFFILIATE])
- Antes de editar/deploy en VPS:
  1. Verificar archivo objetivo y docroot real.
  2. Verificar si existe copia duplicada en otra ruta (`/var/www/...`).
- Despues de cada deploy:
  1. `php -l` del archivo remoto (si aplica).
  2. Validacion HTTP en vivo con `nocache`.
  3. Confirmar contenido esperado (texto o marcador clave).
- Si un cambio afecta routing (`index.php`, wrappers, login), validar explicitamente:
  - Root del dominio.
  - Ruta de login (si aplica).
  - Landing objetivo.

## Seguridad y Estabilidad
- Priorizar cambios pequenos, reversibles y verificables.
- Evitar cambios destructivos o de alto riesgo sin aprobacion explicita.
- Para hotfixes, dejar solucion robusta y sin fallbacks ambiguos.
- No introducir dependencias externas innecesarias.

## Diseño y Assets
- Preferir assets propios (SVG/CSS generados) para evitar problemas de propiedad intelectual.
- No usar recursos con licencia dudosa o no verificada.

## Regla de Planes (App HERMES — [CORE])
- Mantener en el sidemenu el apartado `Plan` con el detalle vigente del plan del cliente.
- Si cambia cualquier funcion, limite o beneficio de un plan, actualizar de inmediato el contenido del apartado `Plan` para reflejar el estado real.
- Validar despues de cada cambio que el texto del plan en UI y las capacidades efectivas del sistema no se contradigan.

## Deploy y Entregables
- No generar ZIP/hotfix empaquetado a menos que el usuario lo pida explicitamente.
- Si se pidiera ZIP para deploy:
  - No incluir `.htaccess` salvo solicitud explicita.
  - No incluir SQL dentro del ZIP; entregar SQL por separado.
  - Entregar ZIP plano (sin carpeta contenedora `public_html`).

## Flujo de Trabajo Esperado
- Implementar -> validar local -> deploy -> validar remoto -> confirmar resultados concretos.
- Reportar siempre:
  - Contexto activo (dominio y clasificacion CORE/AFFILIATE).
  - Que se cambio.
  - Donde se cambio.
  - Como se valido.
  - Estado final en vivo.