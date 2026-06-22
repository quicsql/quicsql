# PHP 8.3 + the libSQL extension (turso-client-php), installed the documented
# way: composer -> turso-php-installer -> prebuilt extension binary.
# Build once, then run main.php against a quicSQL server on the host:
#
#   docker build --platform linux/amd64 -t quicsql-php-libsql .
#   docker run --rm --platform linux/amd64 \
#     -e QUICSQL_URL=http://host.docker.internal:7775 quicsql-php-libsql
#
# --platform linux/amd64 matters: the extension ships prebuilt for
# x86_64-unknown-linux-gnu (and macOS arm64/x86_64) but NOT linux-aarch64, so on
# Apple Silicon the container must run under amd64 emulation. Native local
# installs on macOS arm64 work fine — this is a Linux-container-only caveat.

FROM composer:2 AS composer

FROM php:8.3-cli
COPY --from=composer /usr/bin/composer /usr/bin/composer
RUN apt-get update && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*

# The installer downloads the prebuilt libsql extension for this PHP and
# registers it in php.ini (-n = non-interactive).
RUN composer global require darkterminal/turso-php-installer \
    && "$(composer config --global home)/vendor/bin/turso-php-installer" install -n --php-version=8.3

WORKDIR /app
COPY main.php .
CMD ["php", "main.php"]
