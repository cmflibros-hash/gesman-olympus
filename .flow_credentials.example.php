<?php
// Copia este archivo a .flow_credentials.php en el servidor y ajusta valores reales.
// Recomendado: permisos 600 y propietario del usuario del servicio web.
return [
    // 1 = habilitado, 0 = deshabilitado
    'is_enabled' => 0,

    // sandbox o production
    'environment' => 'sandbox',

    // Credenciales de Flow
    'api_key' => 'REEMPLAZAR_API_KEY',
    'secret_key' => 'REEMPLAZAR_SECRET_KEY',

    // URL publica HTTPS para confirmaciones server-to-server
    'webhook_url' => 'https://gesmanhermes.com/webhook/flow/',
];
