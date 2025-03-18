#!/bin/bash

# n8n Apache Virtual Host Installer (Lite Version)
# Copyright © 2025 Antonin Nvh - https://codequantum.io
# Licensed under MIT License

# Colors for terminal output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}This script requires root privileges.${NC}"
    echo -e "${YELLOW}Restarting with sudo...${NC}"
    sudo "$0" "$@"
    exit $?
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required packages
check_requirements() {
    echo -e "${BLUE}Checking system requirements...${NC}"

    # Check for Apache
    if ! command_exists apache2; then
        echo -e "${YELLOW}Apache2 is not installed. Installing...${NC}"
        apt-get update
        apt-get install -y apache2
    fi

    # Check for Node.js (required for n8n)
    if ! command_exists node; then
        echo -e "${YELLOW}Node.js is not installed. Installing LTS version...${NC}"
        apt-get update
        apt-get install -y ca-certificates curl gnupg
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
        echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_lts nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
        apt-get update
        apt-get install -y nodejs
    fi

    # Check for npm
    if ! command_exists npm; then
        echo -e "${YELLOW}npm is not installed. Installing...${NC}"
        apt-get install -y npm
    fi

    # Install additional required packages
    echo -e "${BLUE}Installing additional required packages...${NC}"
    apt-get install -y apache2-utils build-essential python3 python3-pip

    # Check for Apache modules
    echo -e "${BLUE}Enabling required Apache modules...${NC}"
    a2enmod proxy proxy_http proxy_wstunnel headers rewrite auth_basic authn_file ssl
}

# Install n8n
install_n8n() {
    echo -e "${BLUE}Installing n8n...${NC}"

    # Force a clean installation of the latest version (@next)
    echo -e "${BLUE}Installing the latest n8n version globally with safe permissions...${NC}"
    npm install -g n8n@next --unsafe-perm=true

    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install n8n. Trying with cache clean...${NC}"
        npm cache clean --force
        npm install -g n8n@next --unsafe-perm=true
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to install n8n. Please check npm configuration and try again.${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}n8n $(n8n --version 2>/dev/null || echo "unknown version") installed successfully.${NC}"

    # Create service file for n8n
    echo -e "${BLUE}Creating systemd service for n8n...${NC}"

    # Create directory for n8n data
    mkdir -p /var/lib/n8n
    chown -R root:root /var/lib/n8n

    # Create systemd service with proper environment variables and configuration
    cat > /etc/systemd/system/n8n.service << EOF
[Unit]
Description=n8n workflow automation
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/n8n
Environment=N8N_HOST=0.0.0.0
Environment=N8N_PORT=5678
Environment=NODE_ENV=production

# n8n should use HTTP locally (Apache handles HTTPS)
Environment=N8N_PROTOCOL=http

# Set public-facing URLs to HTTPS
Environment=N8N_EDITOR_BASE_URL=https://$domain
Environment=WEBHOOK_URL=https://$domain/
Environment=N8N_WEBSOCKET_URL=wss://$domain/

# Security settings
Environment=N8N_SECURE_COOKIES=true
Environment=N8N_ENCRYPTION_KEY="$(openssl rand -hex 16)"

# WebSocket configuration
Environment=N8N_PUSH_BACKEND=websocket
Environment=N8N_PUSH=1

# Skip self-signed certificate validation for local development
Environment=NODE_TLS_REJECT_UNAUTHORIZED=0

# Disable unnecessary notifications
Environment=N8N_METRICS=true
Environment=N8N_DIAGNOSTICS_ENABLED=true
Environment=N8N_HIRING_BANNER_ENABLED=false
Environment=N8N_VERSION_NOTIFICATIONS_ENABLED=false

# Performance tuning
Environment=NODE_OPTIONS="--max-old-space-size=4096"
ExecStart=$(which n8n) start --tunnel
Restart=always
RestartSec=10
LimitNOFILE=50000

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable n8n service
    systemctl daemon-reload
    systemctl enable n8n.service
}

# Create Apache configuration
create_apache_config() {
    local domain=$1
    local auth_file=$2

    echo -e "${BLUE}Creating Apache virtual host configuration for ${YELLOW}$domain${NC}"

    # Create the Apache config file
    cat > /etc/apache2/sites-available/$domain.conf << EOF
<VirtualHost *:80>
    ServerName $domain

    # Redirect all HTTP traffic to HTTPS
    RewriteEngine On
    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName $domain
    
    # SSL Configuration
    SSLEngine on
    
    # Using self-signed certificate by default
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    
    # Modern SSL configuration
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder on
    SSLCompression off
    
    # Proxy settings
    ProxyRequests Off
    ProxyPreserveHost On

    # Basic authentication
    <Location />
        AuthType Basic
        AuthName "Restricted Area"
        AuthUserFile $auth_file
        Require valid-user
    </Location>

    # WebSocket endpoints
    <Location /ws>
        ProxyPass ws://127.0.0.1:5678/ws
        RewriteEngine On
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule /(.*) ws://127.0.0.1:5678/$1 [P,L]
    </Location>
    
    <Location /socket.io/>
        ProxyPass ws://127.0.0.1:5678/socket.io/
        RewriteEngine On
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule socket.io/(.*) ws://127.0.0.1:5678/socket.io/$1 [P,L]
    </Location>
    
    # Main application proxy with WebSocket support
    <Location />
        # Handle all WebSocket connections
        RewriteEngine On
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule /(.*) ws://127.0.0.1:5678/$1 [P,L]
        
        # Handle regular HTTP requests
        ProxyPass http://127.0.0.1:5678/
        ProxyPassReverse http://127.0.0.1:5678/
    </Location>
    
    # Ensure WebSocket connection upgrade headers are passed
    RewriteEngine On
    RewriteCond %{HTTP:Connection} Upgrade [NC]
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:5678/$1 [P,L]
    
    # Prevent timeouts for long-running WebSocket connections
    ProxyTimeout 3600
    Timeout 3600
    
    # Logs
    ErrorLog \${APACHE_LOG_DIR}/$domain-error.log
    CustomLog \${APACHE_LOG_DIR}/$domain-access.log combined
</VirtualHost>
EOF

    # Enable the site
    a2ensite $domain.conf
    
    # Check if domain is a .local domain
    if [[ "$domain" == *".local" ]]; then
        echo -e "${GREEN}Using local domain: $domain${NC}"
        
        # Ensure domain is in hosts file
        if ! grep -q "$domain" /etc/hosts; then
            echo -e "${BLUE}Adding $domain to /etc/hosts...${NC}"
            echo "127.0.0.1 $domain" >> /etc/hosts
        fi
    fi
}

# Generate self-signed SSL certificate 
generate_self_signed_ssl() {
    local domain=$1
    
    echo -e "${BLUE}Setting up SSL with self-signed certificate...${NC}"
    
    # Create directory for certificates if it doesn't exist
    mkdir -p /etc/ssl/private
    
    # Generate SSL certificate with proper domain name
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/${domain}.key \
        -out /etc/ssl/certs/${domain}.crt \
        -subj "/CN=${domain}/O=n8n Installation/C=US"
        
    # Update Apache config to use the new certificate
    sed -i "s|SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem|SSLCertificateFile /etc/ssl/certs/${domain}.crt|" /etc/apache2/sites-available/$domain.conf
    sed -i "s|SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key|SSLCertificateKeyFile /etc/ssl/private/${domain}.key|" /etc/apache2/sites-available/$domain.conf
}

# Create password file
create_password_file() {
    local username=$1
    local auth_file=$2

    echo -e "${BLUE}Creating authentication file...${NC}"
    
    # Create password file directory if it doesn't exist
    mkdir -p $(dirname "$auth_file")
    
    # Create the password file
    htpasswd -c -B "$auth_file" "$username"
}

# Main function
main() {
    echo -e "${GREEN}=== n8n Apache Virtual Host Installer (Lite) ===${NC}"
    
    # Check system requirements
    check_requirements
    
    # Get hostname for default suggestion
    local hostname=$(hostname -s 2>/dev/null || echo "server")
    if [ -z "$hostname" ] || [ "$hostname" == "localhost" ]; then
        hostname="n8n-server"
    fi
    local default_domain="${hostname}-n8n.local"
    
    # Ask for domain with default suggestion
    read -p "Enter domain name for n8n [default: $default_domain]: " domain_name
    
    # Use default if empty
    if [ -z "$domain_name" ]; then
        domain_name="$default_domain"
        echo -e "${GREEN}Using default domain: $domain_name${NC}"
    fi
    
    # Ask for username
    read -p "Enter username for n8n authentication: " username
    if [ -z "$username" ]; then
        echo -e "${RED}Username cannot be empty.${NC}"
        exit 1
    fi
    
    # Define auth file location
    auth_file="/etc/apache2/.htpasswd-n8n"
    
    # Handle .local domain automatically
    if [[ "$domain_name" == *".local" ]]; then
        echo -e "${BLUE}Detected .local domain. This will be automatically configured for local use.${NC}"
        
        # Add domain to hosts file
        if ! grep -q "$domain_name" /etc/hosts; then
            echo -e "${BLUE}Adding $domain_name to /etc/hosts file...${NC}"
            echo "127.0.0.1 $domain_name" >> /etc/hosts
            echo -e "${GREEN}✓ Added to hosts file. You'll be able to access n8n using this hostname.${NC}"
        fi
    fi
    
    # Install n8n
    domain="$domain_name" install_n8n
    
    # Create Apache config
    create_apache_config "$domain_name" "$auth_file"
    
    # Generate self-signed SSL certificate
    generate_self_signed_ssl "$domain_name"
    
    # Create password file
    create_password_file "$username" "$auth_file"
    
    # Start n8n
    echo -e "${BLUE}Starting n8n service...${NC}"
    systemctl start n8n
    
    # Wait for services to start
    echo -e "${BLUE}Waiting for services to start...${NC}"
    sleep 5
    
    # Restart Apache
    systemctl restart apache2
    
    # Summary
    echo -e "\n${GREEN}=== Installation Complete ===${NC}"
    echo -e "n8n is now installed and configured with the following details:"
    echo -e "Domain: ${YELLOW}https://$domain_name${NC}"
    echo -e "Username: ${YELLOW}$username${NC}"
    echo -e "Password: ${YELLOW}(As entered)${NC}"
    echo -e "\nTo access n8n, open ${GREEN}https://$domain_name${NC} in your browser."
    
    echo -e "\n${BLUE}n8n service management:${NC}"
    echo -e "  Start: ${GREEN}systemctl start n8n${NC}"
    echo -e "  Stop: ${GREEN}systemctl stop n8n${NC}"
    echo -e "  Restart: ${GREEN}systemctl restart n8n${NC}"
    echo -e "  Status: ${GREEN}systemctl status n8n${NC}"
    echo -e "  View logs: ${GREEN}journalctl -u n8n -f${NC}"
}

# Run main function
main