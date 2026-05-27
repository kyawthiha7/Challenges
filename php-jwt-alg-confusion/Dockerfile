FROM php:8.2-apache

# Generate RSA-2048 key pair at build time
RUN apt-get update -qq && apt-get install -y openssl --no-install-recommends && \
    mkdir -p /keys && \
    openssl genrsa -out /keys/private.pem 2048 2>/dev/null && \
    openssl rsa -in /keys/private.pem -pubout -out /keys/public.pem 2>/dev/null && \
    chmod 600 /keys/private.pem && \
    chmod 644 /keys/public.pem

COPY src/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html
