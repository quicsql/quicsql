<?php
// quicSQL from PHP with nothing but ext-curl — the native JSON API.
// Works on any PHP 8.x, no extension install, no composer.
//
//   php main.php                       (env: QUICSQL_URL, QUICSQL_TOKEN)
//   # or without PHP installed (from this directory):
//   docker run --rm -v "$PWD:/app" -w /app \
//     -e QUICSQL_URL=http://host.docker.internal:7775 \
//     php:8.3-cli php main.php
//
// One endpoint per database: POST /<db>/query with {"sql","args"} or a
// {"statements":[...]} batch that runs as one all-or-nothing transaction.
// A failing batch statement returns HTTP 200 with an {"error","failed_index"}
// envelope — check for "error", not just the status code.

declare(strict_types=1);

$base = rtrim(getenv('QUICSQL_URL') ?: 'http://127.0.0.1:7775', '/');
$token = getenv('QUICSQL_TOKEN') ?: 'dev-token';

function query(array $body): array
{
    global $base, $token;
    $ch = curl_init("$base/app/query");
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($body, JSON_THROW_ON_ERROR),
        CURLOPT_HTTPHEADER => [
            "Authorization: Bearer $token",
            'Content-Type: application/json',
        ],
        CURLOPT_RETURNTRANSFER => true,
    ]);
    $raw = curl_exec($ch);
    if ($raw === false) {
        fwrite(STDERR, 'FAIL: ' . curl_error($ch) . PHP_EOL);
        exit(1);
    }
    $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    $out = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    if ($status >= 400 || isset($out['error'])) {
        fwrite(STDERR, "FAIL: query failed ($status): " . ($out['error']['message'] ?? 'unknown') . PHP_EOL);
        exit(1);
    }
    return $out;
}

function check(bool $cond, string $msg): void
{
    if (!$cond) {
        fwrite(STDERR, "FAIL: $msg" . PHP_EOL);
        exit(1);
    }
}

query(['sql' => 'CREATE TABLE IF NOT EXISTS users_php (id INTEGER PRIMARY KEY, name TEXT NOT NULL, balance INTEGER NOT NULL)']);
query(['sql' => 'DELETE FROM users_php']);

$ins = query(['sql' => 'INSERT INTO users_php(name, balance) VALUES (?, ?)', 'args' => ['ada', 100]]);
check($ins['last_insert_id'] > 0, 'insert returns last_insert_id');

// A statements batch: one explicit transaction, all-or-nothing.
query(['statements' => [
    ['sql' => 'INSERT INTO users_php(name, balance) VALUES (?, ?)', 'args' => ['bob', 100]],
    ['sql' => 'UPDATE users_php SET balance = balance - ? WHERE name = ?', 'args' => [30, 'ada']],
    ['sql' => 'UPDATE users_php SET balance = balance + ? WHERE name = ?', 'args' => [30, 'bob']],
]]);

$rs = query(['sql' => 'SELECT name, balance FROM users_php ORDER BY name']);
check($rs['columns'] === ['name', 'balance'], 'columns come back named');
check($rs['rows'] === [['ada', 70], ['bob', 130]], 'rows transferred exactly, got ' . json_encode($rs['rows']));

echo 'OK php-curl' . PHP_EOL;
