FROM php:8.2-apache
RUN echo "THISISTHEFLAG" > /flag.txt
RUN mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads
COPY src/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html
