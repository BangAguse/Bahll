FROM php:8.1-cli-alpine

# Install required extensions
RUN apk add --no-cache \
    openssl-dev \
    autoconf \
    build-base \
    && docker-php-ext-install \
    openssl \
    pdo_sqlite

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Set working directory
WORKDIR /app

# Copy application
COPY . /app

# Install dependencies
RUN composer install --no-dev --optimize-autoloader

# Create storage directories
RUN mkdir -p storage/{Data_encrypt,Data_decrypt,Decrypted,Encrypted} \
    && chmod -R 777 storage

# Expose port
EXPOSE 8000

# Set environment
ENV BAHLL_API_HOST=0.0.0.0 \
    BAHLL_API_PORT=8000 \
    BAHLL_JWT_SECRET=bahll-production-secret \
    BAHLL_DB_PATH=/app/storage/bahll.db \
    BAHLL_LOG_LEVEL=info

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD php -r "echo file_get_contents('http://localhost:8000/api/health');" | grep -q healthy || exit 1

# Run API server
CMD ["php", "api/index.php"]
