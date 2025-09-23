<?php
declare(strict_types=1);

// ———————————— Cabeçalhos de segurança (ajuste CSP conforme seu domínio/recursos) ————————————
header("Content-Type: text/html; charset=utf-8");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: no-referrer-when-downgrade");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header("Cross-Origin-Opener-Policy: same-origin");
header("Cross-Origin-Resource-Policy: same-origin");
header("Cross-Origin-Embedder-Policy: require-corp");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
// CSP: permita apenas o necessário
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; base-uri 'none'; form-action 'self'");

// ———————————— Utilidades ————————————
function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function sanitize_string(?string $v): string {
  $v = $v ?? '';

  // 1) Decodifica entidades HTML (HTML5), ex.: "Ribeir&atilde;o" -> "Ribeirão"
  $v = html_entity_decode($v, ENT_QUOTES | ENT_HTML5, 'UTF-8');

  // 2) Garante UTF-8 válido (remove bytes inválidos silenciosamente)
  $v = iconv('UTF-8', 'UTF-8//IGNORE', $v);

  // 3) Normaliza Unicode (forma composta NFC) se tiver intl
  if (class_exists('Normalizer')) {
    $v = Normalizer::normalize($v, Normalizer::FORM_C);
  }

  // 4) Colapsa espaços e trim
  $v = preg_replace('/\s+/u', ' ', $v);
  $v = trim($v);

  // 5) (Opcional) Remove controles invisíveis
  $v = preg_replace('/\p{C}+/u', '', $v); // controla chars de categoria "Other"

  return $v;
}

function validar_email(string $email): bool {
  if (strlen($email) > 150) return false;
  return (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
}

function limpar_num(string $v): string { return preg_replace('/\D+/', '', $v); }

// CPF: valida dígitos verificadores
function validar_cpf(string $cpf): bool {
  $cpf = limpar_num($cpf);
  if (strlen($cpf) !== 11) return false;
  if (preg_match('/^(\d)\1{10}$/', $cpf)) return false; // todos iguais
  for ($t = 9; $t < 11; $t++) {
    $d = 0;
    for ($c = 0; $c < $t; $c++) $d += (int) $cpf[$c] * (($t + 1) - $c);
    $d = ((10 * $d) % 11) % 10;
    if ((int)$cpf[$t] !== $d) return false;
  }
  return true;
}

// Data ISO (Y-m-d) e maior de 14 anos (exemplo de regra)
function validar_data_nascimento(string $v): bool {
  if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $v)) return false;
  [$y,$m,$d] = array_map('intval', explode('-', $v));
  if (!checkdate($m, $d, $y)) return false;
  $nasc = DateTime::createFromFormat('Y-m-d', $v);
  $min = (new DateTime('now'))->modify('-14 years'); // ajuste a regra
  return $nasc <= $min;
}

// Salário BR ("R$ 1.234,56") -> decimal "1234.56"
function parse_salario_br(string $v): ?string {
  $v = trim($v);
  // remove "R$" e espaços
  $v = preg_replace('/[Rr]\$?|\s+/u', '', $v);
  // troca separadores
  $v = str_replace('.', '', $v);
  $v = str_replace(',', '.', $v);
  if (!is_numeric($v)) return null;
  $num = (float)$v;
  if ($num < 0 || $num > 1000000000) return null; // sanidade
  return number_format($num, 2, '.', '');
}

function validar_uf(string $uf): bool {
  $uf = strtoupper($uf);
  $ufs = ['AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG','PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO'];
  return in_array($uf, $ufs, true);
}

function validar_beneficios(array $vals): array {
  $permitidos = ['cesta basica','convenio','VT','VR'];
  $ok = [];
  foreach ($vals as $v) {
    $v = trim((string)$v);
    if ($v === '' || strtolower($v) === 'selecione') continue;
    if (in_array($v, $permitidos, true)) $ok[] = $v;
  }
  return array_values(array_unique($ok));
}

function bad_request(string $msg, array $errors = []): void {
  http_response_code(400);
  render_result(false, $msg, $errors);
  exit;
}

function render_result(bool $ok, string $msg, array $payload = []): void {
  ?>
  <!doctype html><html lang="pt-br"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title><?= $ok ? 'Sucesso' : 'Erro' ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  </head><body class="bg-light">
  <div class="container py-5">
    <div class="alert <?= $ok ? 'alert-success' : 'alert-danger' ?>">
      <strong><?= $ok ? 'Dados recebidos com sucesso.' : 'Falha na validação.' ?></strong> <?= e($msg) ?>
    </div>
    <?php if ($ok && !empty($payload)): ?>
      <div class="card">
        <div class="card-header">Resumo (sanitizado)</div>
        <div class="card-body">
          <pre class="mb-0"><code><?php
            // segurança: dump bonitinho e escapado
            echo e(json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
          ?></code></pre>
        </div>
      </div>
    <?php elseif (!$ok && !empty($payload)): ?>
      <ul class="mt-3 list-group">
        <?php foreach ($payload as $campo => $erro): ?>
          <li class="list-group-item"><strong><?= e($campo) ?>:</strong> <?= e($erro) ?></li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>
    <a class="btn btn-secondary mt-4" href="formulario.html">Voltar</a>
  </div>
  </body></html>
  <?php
}

// ———————————— Somente POST ————————————
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
  bad_request('Use o formulário para enviar os dados via POST.');
}

// ———————————— Anti-bot (honeypot) ————————————
if (!empty($_POST['website'] ?? '')) {
  bad_request('Requisição rejeitada.');
}

// ———————————— CSRF (double-submit cookie) ————————————
$csrfField = $_POST['csrf_token'] ?? '';
$csrfCookie = $_COOKIE['csrf_token'] ?? '';
if (!$csrfField || !$csrfCookie || !hash_equals($csrfCookie, $csrfField)) {
  bad_request('CSRF token inválido ou ausente.');
}

// ———————————— Coleta + Sanitização inicial ————————————
$input_defs = [
  'nome'            => FILTER_DEFAULT,
  'cpf'             => FILTER_DEFAULT,
  'email'           => FILTER_DEFAULT,
  'salario'         => FILTER_DEFAULT,
  'data_nascimento' => FILTER_DEFAULT,
  'genero'          => FILTER_DEFAULT,
  'beneficios'      => ['filter' => FILTER_DEFAULT, 'flags' => FILTER_REQUIRE_ARRAY],
  'cep'             => FILTER_DEFAULT,
  'rua'             => FILTER_DEFAULT,
  'estado'          => FILTER_DEFAULT,
  'cidade'          => FILTER_DEFAULT,
];
$data = filter_input_array(INPUT_POST, $input_defs, false) ?: [];

$errors = [];

// ———————————— Validações campo a campo ————————————
$nome = sanitize_string($data['nome'] ?? '');
if ($nome === '' || !preg_match('/^[A-Za-zÀ-ÖØ-öø-ÿ\'´`^~\- ]{2,120}$/u', $nome)) {
  $errors['nome'] = 'Nome inválido.';
}

$cpf = $data['cpf'] ?? '';
if (!validar_cpf($cpf)) {
  $errors['cpf'] = 'CPF inválido.';
}
$cpf_num = limpar_num($cpf);

$email = trim((string)($data['email'] ?? ''));
if (!validar_email($email)) {
  $errors['email'] = 'E-mail inválido.';
}
$email_sane = filter_var($email, FILTER_SANITIZE_EMAIL);

$salario_raw = (string)($data['salario'] ?? '');
$salario_dec = parse_salario_br($salario_raw);
if ($salario_dec === null) {
  $errors['salario'] = 'Salário inválido.';
}

$data_nasc = (string)($data['data_nascimento'] ?? '');
if (!validar_data_nascimento($data_nasc)) {
  $errors['data_nascimento'] = 'Data de nascimento inválida (ou idade mínima não atendida).';
}

$genero = strtolower(trim((string)($data['genero'] ?? '')));
if (!in_array($genero, ['masculino','feminino'], true)) {
  $errors['genero'] = 'Selecione masculino ou feminino.';
}

$beneficios = is_array($data['beneficios'] ?? null) ? $data['beneficios'] : [];
$beneficios_ok = validar_beneficios($beneficios);
if (count($beneficios_ok) === 0) {
  $errors['beneficios'] = 'Escolha ao menos 1 benefício válido.';
}

$cep = (string)($data['cep'] ?? '');
$cep_num = limpar_num($cep);
if (!preg_match('/^\d{8}$/', $cep_num)) {
  $errors['cep'] = 'CEP inválido.';
}

$rua = sanitize_string($data['rua'] ?? '');
if ($rua === '') {
  $errors['rua'] = 'Rua é obrigatória.';
}

$estado = strtoupper(trim((string)($data['estado'] ?? '')));
if (!validar_uf($estado)) {
  $errors['estado'] = 'UF inválida.';
}

$cidade = sanitize_string($data['cidade'] ?? '');
if ($cidade === '') {
  $errors['cidade'] = 'Cidade é obrigatória.';
}

// ———————————— Se erros, retorna 400 com lista ————————————
if (!empty($errors)) {
  bad_request('Corrija os campos destacados e envie novamente.', $errors);
}

// ———————————— Dados prontos (sanitizados / normalizados) ————————————
$payload = [
  'nome'            => $nome,
  'cpf'             => $cpf_num,
  'email'           => $email_sane,
  'salario'         => $salario_dec,          // ex.: "1234.56"
  'data_nascimento' => $data_nasc,            // "YYYY-MM-DD"
  'genero'          => $genero,
  'beneficios'      => $beneficios_ok,
  'endereco'        => [
    'cep'    => $cep_num,
    'rua'    => $rua,
    'estado' => $estado,
    'cidade' => $cidade,
  ],
];

// ———————————— EXEMPLO: inserção segura com PDO (DESCOMENTE E AJUSTE) ————————————
// try {
//   $pdo = new PDO('mysql:host=localhost;dbname=seu_banco;charset=utf8mb4','user','pass',[
//     PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
//     PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
//   ]);
//   $pdo->beginTransaction();
//   $stmt = $pdo->prepare('INSERT INTO candidatos
//     (nome, cpf, email, salario, data_nascimento, genero, cep, rua, estado, cidade)
//     VALUES (:nome, :cpf, :email, :salario, :data_nascimento, :genero, :cep, :rua, :estado, :cidade)');
//   $stmt->execute([
//     ':nome' => $payload['nome'],
//     ':cpf'  => $payload['cpf'],
//     ':email'=> $payload['email'],
//     ':salario' => $payload['salario'],
//     ':data_nascimento' => $payload['data_nascimento'],
//     ':genero' => $payload['genero'],
//     ':cep' => $payload['endereco']['cep'],
//     ':rua' => $payload['endereco']['rua'],
//     ':estado' => $payload['endereco']['estado'],
//     ':cidade' => $payload['endereco']['cidade'],
//   ]);
//   // Tabela de benefícios (N:N) — exemplo simples
//   $candId = (int)$pdo->lastInsertId();
//   $stmtB = $pdo->prepare('INSERT INTO candidato_beneficio (candidato_id, beneficio) VALUES (:id, :b)');
//   foreach ($payload['beneficios'] as $b) {
//     $stmtB->execute([':id'=>$candId, ':b'=>$b]);
//   }
//   $pdo->commit();
// } catch (Throwable $e) {
//   if (isset($pdo) && $pdo->inTransaction()) $pdo->rollBack();
//   bad_request('Erro ao salvar no banco (transação revertida).');
// }

// ———————————— Sucesso ————————————
render_result(true, 'Validação concluída. (Exemplo de persistência via PDO comentado no código.)', $payload);
