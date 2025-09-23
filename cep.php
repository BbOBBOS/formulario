<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

// ——— Segurança básica para endpoint JSON ———
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Opcional: travar método
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
  http_response_code(405);
  echo json_encode(['ok' => false, 'error' => 'Method not allowed']);
  exit;
}

// Anti-CSRF simples: validar token se você quiser (recomendado).
// Aqui, como a chamada é same-origin, podemos validar o mesmo token do form:
$csrfField = $_POST['csrf_token'] ?? '';
$csrfCookie = $_COOKIE['csrf_token'] ?? '';
if (!$csrfField || !$csrfCookie || !hash_equals($csrfCookie, $csrfField)) {
  http_response_code(400);
  echo json_encode(['ok' => false, 'error' => 'CSRF inválido']);
  exit;
}

// Captura e valida CEP
$cep_raw = (string)($_POST['cep'] ?? '');
$cep = preg_replace('/\D+/', '', $cep_raw);
if (strlen($cep) !== 8) {
  http_response_code(422);
  echo json_encode(['ok' => false, 'error' => 'CEP inválido', 'cep' => $cep]);
  exit;
}

// (Opcional) Cache curto com APCu (se disponível)
function apcu_get_or(string $key, callable $fn, int $ttl = 60) {
  if (function_exists('apcu_fetch')) {
    $hit = apcu_fetch($key, $ok);
    if ($ok) return $hit;
    $val = $fn();
    if ($val !== null) apcu_store($key, $val, $ttl);
    return $val;
  }
  return $fn();
}

try {
  $data = apcu_get_or('viacep_' . $cep, function() use ($cep) {
    $client = new Client([
      'base_uri' => 'https://viacep.com.br/ws/',
      'timeout' => 2.5,
      'connect_timeout' => 2.0,
      'http_errors' => false,
      'headers' => ['Accept' => 'application/json'],
    ]);

    // retries leves
    for ($i = 1; $i <= 3; $i++) {
      $resp = $client->get("{$cep}/json/");
      if ($resp->getStatusCode() === 200) {
        $json = json_decode((string)$resp->getBody(), true);
        if (is_array($json) && empty($json['erro'])) {
          return [
            'logradouro' => trim((string)($json['logradouro'] ?? '')),
            'bairro'     => trim((string)($json['bairro'] ?? '')),
            'localidade' => trim((string)($json['localidade'] ?? '')),
            'uf'         => strtoupper((string)($json['uf'] ?? '')),
          ];
        }
        // CEP inexistente
        return null;
      }
      usleep(150000 * $i);
    }
    return null;
  }, 180); // cache 3 minutos

  if ($data === null) {
    http_response_code(404);
    echo json_encode(['ok' => false, 'error' => 'CEP não encontrado']);
    exit;
  }

  http_response_code(200);
  echo json_encode(['ok' => true, 'cep' => $cep, 'data' => $data], JSON_UNESCAPED_UNICODE);

} catch (GuzzleException $e) {
  http_response_code(502);
  echo json_encode(['ok' => false, 'error' => 'Serviço de CEP indisponível']);
}
