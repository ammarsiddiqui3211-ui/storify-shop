FROM php:8.1-apache

# Install PHP mysqli extension needed for database connection
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli

# Enable Apache rewrite module
RUN a2enmod rewrite

# Copy the PHP files to the web server root
COPY login.php /var/www/html/

# We don't copy the actual .env file for security, 
# because you will set the environment variables in the Render/Railway dashboard!

# Configure Apache to run on the PORT environment variable provided by cloud hosts
RUN sed -i 's/80/${PORT}/g' /etc/apache2/sites-available/000-default.conf /etc/apache2/ports.conf
