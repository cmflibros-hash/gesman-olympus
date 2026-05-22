<?php
$target = __DIR__ . '/../../hermes-webhook-flow.php';
if (!is_file($target)) {
    http_response_code(500);
    echo 'Webhook Flow no disponible';
    exit;
}
require $target;
