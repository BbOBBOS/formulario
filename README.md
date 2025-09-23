# Formulário Seguro em PHP + Bootstrap 5 + API busca CEP

Um projeto de demonstração que mostra como construir um **formulário robusto, validado e seguro**, utilizando:

- **Front-end:** HTML5 + [Bootstrap 5](https://getbootstrap.com/)
- **Validação Client-side:** JavaScript puro, com máscaras de campos (CPF, CEP, salário)
- **Back-end:** PHP 8.x (sem framework) com:
  - `filter_input` e `filter_var` para sanitização
  - Validação campo a campo (nome, CPF, e-mail, data, salário, CEP, etc.)
  - Normalização de strings e acentos (UTF-8 NFC)
  - Proteção contra **SQL Injection** com PDO preparado
  - Proteção contra **XSS** com escape na saída + CSP
  - **CSRF** com double-submit cookie
  - **Anti-bot Honeypot**  

---
## Estrutura do Projeto
```pag
 ├── formulario.html # Formulário com Bootstrap 5, máscaras e validação JS
 ├── formulario.php # Processamento, validação e integração preparada com PDO
 └── vendor/ # Dependências instaladas via Composer
```
## Campos do Formulário

- **nome:** texto (com acentos)
- **cpf:** máscara e validação de dígitos verificadores
- **email:** validação RFC + sanitização
- **salario:** máscara `R$ 0,00` → normalização para decimal
- **data_nascimento:** exige idade mínima de 14 anos
- **genero:** rádio (masculino/feminino)
- **beneficios:** múltipla escolha (`cesta basica`, `convenio`, `VT`, `VR`)
- **endereço:** CEP, rua, estado (UF), cidade

---

## Segurança Implementada

- **SQL Injection:**  
  Uso exclusivo de **Prepared Statements** via PDO. Exemplo:

  ```php
  $stmt = $pdo->prepare('INSERT INTO candidatos (nome, cpf, email, ...) VALUES (:nome, :cpf, :email, ...)');
  $stmt->execute([':nome'=>$payload['nome'], ':cpf'=>$payload['cpf'], ...]);

- XSS (Cross-Site Scripting):
- Entrada sanitizada (filter_var, html_entity_decode, Normalizer).
- Escape rigoroso na saída com htmlspecialchars.
- Cabeçalho CSP configurado para bloquear scripts injetados.
- CSRF (Cross-Site Request Forgery):
- Double-Submit Cookie: Token gerado no front e comparado com cookie no PHP.

## Proteção contra Bots:
- Campo oculto (honeypot) — se preenchido, request é rejeitado.

## Validações Backend:
- Nenhum dado confiado só pelo JavaScript.
- Regex e funções customizadas para CPF, datas, UF, etc.

## Headers de Segurança:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Strict-Transport-Security
- Permissions-Policy bloqueando câmera/microfone
- CSP com script-src 'self' https://cdn.jsdelivr.net 

## Dependências
- Instalação via Composer:
```php
composer require guzzlehttp/guzzle
 ```

## Melhorias Implementadas

- Sanitização de Acentos
- Consulta CEP Backend: Guzzle com 3 tentativas e timeout.
- Normaliza rua, cidade, UF de acordo com resposta oficial.
