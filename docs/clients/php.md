# PHP

Two good paths: the **libSQL extension** (`turso-client-php`, a prebuilt native
extension for PHP 8.1–8.5) speaks Hrana with transactions and prepared
statements; or **plain curl** against the native JSON API — zero install, any
PHP 8.x, any shared host.

## The libSQL extension

Install via the composer-distributed installer, which downloads a prebuilt
binary for your PHP version and registers it in `php.ini`:

```sh
composer global require darkterminal/turso-php-installer
turso-php-installer install          # add -n --php-version=8.3 for non-interactive
```

```php
<?php
$db = new LibSQL("libsql:dbname=http://127.0.0.1:7775/app;authToken=your-token");

$db->execute('INSERT INTO users(name, balance) VALUES (?, ?)', ['ada', 100]);
$db->execute('INSERT INTO users(name, balance) VALUES (?, ?)', ['bob', 100]);

// An interactive transaction — both updates commit atomically.
$tx = $db->transaction();
$tx->execute('UPDATE users SET balance = balance - ? WHERE name = ?', [30, 'ada']);
$tx->execute('UPDATE users SET balance = balance + ? WHERE name = ?', [30, 'bob']);
$tx->commit();

$rows = $db->query('SELECT name, balance FROM users ORDER BY name')
    ->fetchArray(LibSQL::LIBSQL_ASSOC);
foreach ($rows as $row) {
    echo "{$row['name']}: {$row['balance']}\n";
}
$db->close();
```

The database is the URL path (`/app`); the token becomes
`Authorization: Bearer`. Prepared statements (`$db->prepare`) and
`executeBatch` work as documented in the
[extension's API reference](https://github.com/tursodatabase/turso-client-php/blob/main/docs/LibSQL-class.md).

**Prebuilt coverage:** linux-x86_64, macOS (arm64 + x86_64), Windows — but not
linux-aarch64. In an Apple Silicon Docker container, build/run the image with
`--platform linux/amd64`; on ARM Linux servers, use the curl path below.

## Zero install: curl + the native JSON API

Works on every PHP 8.x with `ext-curl` (or Guzzle, same request):

```php
<?php
function query(array $body): array
{
    $ch = curl_init('http://127.0.0.1:7775/app/query');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($body, JSON_THROW_ON_ERROR),
        CURLOPT_HTTPHEADER => ['Authorization: Bearer your-token', 'Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
    ]);
    $out = json_decode(curl_exec($ch), true, 512, JSON_THROW_ON_ERROR);
    curl_close($ch);
    if (isset($out['error'])) {
        throw new RuntimeException($out['error']['message']);
    }
    return $out;
}

$rs = query(['sql' => 'SELECT name, balance FROM users WHERE id = ?', 'args' => [7]]);

// A batch runs as ONE all-or-nothing transaction:
query(['statements' => [
    ['sql' => 'UPDATE users SET balance = balance - ? WHERE name = ?', 'args' => [30, 'ada']],
    ['sql' => 'UPDATE users SET balance = balance + ? WHERE name = ?', 'args' => [30, 'bob']],
]]);
```

Full shapes — including how batch errors come back — in the
[HTTP API reference](http-api.md).

## Runnable versions

[`examples/clients/php-libsql`](https://github.com/quicsql/quicsql/tree/main/examples/clients/php-libsql)
(with a ready-made Dockerfile) and
[`php-curl`](https://github.com/quicsql/quicsql/tree/main/examples/clients/php-curl)
run these exact flows against a real server in CI.
