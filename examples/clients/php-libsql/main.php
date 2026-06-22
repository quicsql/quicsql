<?php
// quicSQL from PHP via the libSQL extension (turso-client-php).
// quicSQL serves the Hrana pipeline the extension speaks, so it connects by
// URL alone — the database is the URL path.
//
//   See Dockerfile for the zero-install way to run this. With the extension
//   installed locally:  php main.php    (env: QUICSQL_URL, QUICSQL_TOKEN)

declare(strict_types=1);

$base = rtrim(getenv('QUICSQL_URL') ?: 'http://127.0.0.1:7775', '/');
$token = getenv('QUICSQL_TOKEN') ?: 'dev-token';

function check(bool $cond, string $msg): void
{
    if (!$cond) {
        fwrite(STDERR, "FAIL: $msg" . PHP_EOL);
        exit(1);
    }
}

$db = new LibSQL("libsql:dbname=$base/app;authToken=$token");

$db->execute('CREATE TABLE IF NOT EXISTS users_phplibsql (id INTEGER PRIMARY KEY, name TEXT NOT NULL, balance INTEGER NOT NULL)');
$db->execute('DELETE FROM users_phplibsql');

$db->execute('INSERT INTO users_phplibsql(name, balance) VALUES (?, ?)', ['ada', 100]);
$db->execute('INSERT INTO users_phplibsql(name, balance) VALUES (?, ?)', ['bob', 100]);

// An interactive transaction — both updates commit atomically.
$tx = $db->transaction();
$tx->execute('UPDATE users_phplibsql SET balance = balance - ? WHERE name = ?', [30, 'ada']);
$tx->execute('UPDATE users_phplibsql SET balance = balance + ? WHERE name = ?', [30, 'bob']);
$tx->commit();

$rows = $db->query('SELECT name, balance FROM users_phplibsql ORDER BY name')
    ->fetchArray(LibSQL::LIBSQL_ASSOC);
$got = implode(',', array_map(fn ($r) => "{$r['name']}={$r['balance']}", $rows));
check($got === 'ada=70,bob=130', "rows after transaction, got $got");

$db->close();
echo 'OK php-libsql' . PHP_EOL;
