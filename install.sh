#!/bin/bash

# n8n Apache Virtual Host Installer
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
    a2enmod proxy proxy_http proxy_wstunnel headers rewrite auth_basic authn_file ssl proxy_balancer proxy_connect http2 socache_shmcb
}

# Install n8n
install_n8n() {
    echo -e "${BLUE}Installing n8n...${NC}"

    # Force a clean installation
    echo -e "${BLUE}Installing n8n globally with safe permissions...${NC}"
    npm install -g n8n --unsafe-perm=true

    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install n8n. Trying with cache clean...${NC}"
        npm cache clean --force
        npm install -g n8n --unsafe-perm=true
        
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
Environment=N8N_HOST=localhost
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

# Skip self-signed certificate validation for local development
Environment=NODE_TLS_REJECT_UNAUTHORIZED=0

# Disable unnecessary notifications
Environment=N8N_METRICS=true
Environment=N8N_DIAGNOSTICS_ENABLED=true
Environment=N8N_HIRING_BANNER_ENABLED=false
Environment=N8N_VERSION_NOTIFICATIONS_ENABLED=false
Environment=N8N_USER_MANAGEMENT_DISABLED=false
Environment=N8N_CLUSTER_ENABLED=false
Environment=N8N_DIAGNOSTICS_CONFIG_STATS_SHARING_ENABLED=true

# Performance tuning
Environment=NODE_OPTIONS="--max-old-space-size=4096"
ExecStart=$(which n8n) start
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
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    # Comment out the above and uncomment below after you get a real certificate
    # SSLCertificateFile /etc/letsencrypt/live/$domain/fullchain.pem
    # SSLCertificateKeyFile /etc/letsencrypt/live/$domain/privkey.pem
    
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

    # Comprehensive proxy configuration with WebSocket support
    ProxyPass /favicon.ico http://localhost:5678/favicon.ico
    ProxyPassReverse /favicon.ico http://localhost:5678/favicon.ico
    ProxyPass /webhook http://localhost:5678/webhook
    ProxyPassReverse /webhook http://localhost:5678/webhook
    ProxyPass /rest http://localhost:5678/rest
    ProxyPassReverse /rest http://localhost:5678/rest
    
    # Comprehensive WebSocket proxy configuration for all endpoints
    # Direct WebSocket endpoint mappings
    ProxyPass /ws ws://localhost:5678/ws nocanon
    ProxyPassReverse /ws ws://localhost:5678/ws
    ProxyPass /socket.io/ ws://localhost:5678/socket.io/ nocanon
    ProxyPassReverse /socket.io/ ws://localhost:5678/socket.io/
    ProxyPass /webhooks/ ws://localhost:5678/webhooks/ nocanon
    ProxyPassReverse /webhooks/ ws://localhost:5678/webhooks/
    
    # Force HTTP protocol to use WebSockets
    <Location /ws>
        ProxyPass ws://localhost:5678/ws
        RewriteEngine On
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule /(.*) ws://localhost:5678/$1 [P,L]
    </Location>
    
    <Location /socket.io/>
        ProxyPass ws://localhost:5678/socket.io/
        RewriteEngine On
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule socket.io/(.*) ws://localhost:5678/socket.io/$1 [P,L]
    </Location>
    
    # Main application proxy with WebSocket support
    <Location />
        # Handle all WebSocket connections
        RewriteEngine On
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule /(.*) ws://localhost:5678/$1 [P,L]
        
        # Handle regular HTTP requests
        ProxyPass http://localhost:5678/
        ProxyPassReverse http://localhost:5678/
    </Location>
    
    # Set proper headers for WebSocket and proxy
    ProxyPreserveHost On
    ProxyAddHeaders On
    ProxyRequests Off
    
    # Forward proper headers to backend
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port "443"
    RequestHeader set X-Forwarded-For "%{REMOTE_ADDR}s"
    RequestHeader set Host "%{HTTP_HOST}s"
    
    # Specific WebSocket headers
    SetEnvIf Origin "^https?://(.+)$" ORIGIN=$1
    Header set Access-Control-Allow-Origin "*" env=ORIGIN
    Header set Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    Header set Access-Control-Allow-Headers "origin, x-requested-with, content-type, authorization"
    Header set Access-Control-Allow-Credentials "true"
    
    # Prevent timeouts for long-running WebSocket connections
    ProxyTimeout 3600
    Timeout 3600

    # Headers
    Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains;"

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
        
        # Ensure Avahi/mDNS is installed for better .local domain resolution
        if ! command_exists avahi-daemon && command_exists apt-get; then
            echo -e "${BLUE}Installing Avahi for better .local domain resolution...${NC}"
            apt-get update
            apt-get install -y avahi-daemon
            systemctl enable avahi-daemon
            systemctl start avahi-daemon
        fi
        
        # Ensure domain is in hosts file (should already be added earlier)
        if ! grep -q "$domain" /etc/hosts; then
            echo -e "${BLUE}Adding $domain to /etc/hosts...${NC}"
            echo "127.0.0.1 $domain" >> /etc/hosts
        fi
    fi
}

# Create password file
create_password_file() {
    local username=$1
    local auth_file=$2

    echo -e "${BLUE}Creating authentication file...${NC}"

    # Make sure htpasswd utility is installed
    if ! command_exists htpasswd; then
        echo -e "${YELLOW}htpasswd not found. Installing apache2-utils...${NC}"
        apt-get update
        apt-get install -y apache2-utils
    fi

    # Create password file and add user
    htpasswd -c $auth_file $username

    # Secure the password file
    chmod 640 $auth_file
    chown root:www-data $auth_file
}

# Fix common "Service Unavailable" issues
fix_service_unavailable() {
    local domain=$1
    
    echo -e "${BLUE}Checking for 'Service Unavailable' issues...${NC}"
    
    # Install curl if needed
    if ! command_exists curl; then
        echo -e "${YELLOW}Installing curl for connectivity testing...${NC}"
        apt-get update && apt-get install -y curl
    fi
    
    # Test n8n direct connection
    if ! curl -s http://localhost:5678/ > /dev/null; then
        echo -e "${YELLOW}Cannot connect to n8n directly. Fixing service issues...${NC}"
        
        # Check if port is in use by another process
        if netstat -tulpn | grep -q ":5678"; then
            echo -e "${RED}Port 5678 is in use by another process. Stopping conflicting process...${NC}"
            fuser -k 5678/tcp || true
            sleep 2
        fi
        
        # Check for common n8n service issues
        if ! systemctl is-active --quiet n8n; then
            echo -e "${YELLOW}n8n service is not running. Fixing service configuration...${NC}"
            
            # Fix service permissions
            echo -e "${BLUE}Setting correct permissions for n8n data directory...${NC}"
            mkdir -p /var/lib/n8n
            current_user=$(logname 2>/dev/null || echo "root")
            chown -R $current_user:$current_user /var/lib/n8n
            
            # Update service file with proper user
            sed -i "s/User=root/User=$current_user/" /etc/systemd/system/n8n.service
            
            # Fix common n8n startup issues
            echo -e "${BLUE}Applying common n8n startup fixes...${NC}"
            echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf
            sysctl -p
            
            # Reload and restart service
            systemctl daemon-reload
            systemctl restart n8n
            sleep 10
            
            if ! systemctl is-active --quiet n8n; then
                echo -e "${RED}n8n service still failing to start. Applying extended fixes...${NC}"
                
                # Reset n8n installation
                npm cache clean --force
                npm install -g n8n --unsafe-perm
                
                # Try a more permissive service configuration
                cat > /etc/systemd/system/n8n.service << EOF
[Unit]
Description=n8n workflow automation
After=network.target

[Service]
Type=simple
User=$current_user
WorkingDirectory=/var/lib/n8n
Environment=NODE_ENV=production
Environment=N8N_PROTOCOL=http
Environment=N8N_HOST=0.0.0.0
Environment=N8N_PORT=5678
Environment=N8N_EDITOR_BASE_URL=
Environment=N8N_PUSH_BACKEND=websocket
Environment=NODE_OPTIONS=--max-old-space-size=4096
ExecStart=$(which n8n) start
Restart=always
RestartSec=10
LimitNOFILE=50000

[Install]
WantedBy=multi-user.target
EOF
                
                systemctl daemon-reload
                systemctl restart n8n
                sleep 10
            fi
        fi
    fi
    
    # Check if Apache is properly configured and working
    local http_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5678/)
    if [[ "$http_status" == "000" ]]; then
        echo -e "${RED}Unable to connect to n8n. Port may be blocked or service not running properly.${NC}"
    elif [[ "$http_status" == "502" || "$http_status" == "503" ]]; then
        echo -e "${YELLOW}Received error $http_status from n8n. Checking Apache proxy configuration...${NC}"
        
        # Fix Apache proxy configuration
        echo -e "${BLUE}Fixing Apache proxy configuration...${NC}"
        sed -i 's/ProxyPass \/ http:\/\/localhost:5678\//ProxyPass \/ http:\/\/127.0.0.1:5678\//' /etc/apache2/sites-available/$domain.conf
        
        # Ensure proxy modules are enabled
        a2enmod proxy proxy_http headers proxy_wstunnel
        
        # Restart Apache
        systemctl restart apache2
    fi
}

# Test WebSocket connections
test_websockets() {
    local domain=$1
    
    echo -e "${BLUE}Testing WebSocket connections...${NC}"
    
    # Install necessary tools
    if ! command_exists nc; then
        echo -e "${YELLOW}Installing netcat for WebSocket testing...${NC}"
        apt-get update && apt-get install -y netcat-openbsd
    fi
    
    # Fix any "Service Unavailable" issues first
    fix_service_unavailable "$domain"
    
    # Test direct WebSocket connection to n8n
    echo -e "${BLUE}Testing direct WebSocket connection to n8n...${NC}"
    if timeout 5 bash -c "echo -e 'GET /ws HTTP/1.1\r\nHost: localhost:5678\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n' | nc -w 5 localhost 5678" | grep -q "101 Switching Protocols"; then
        echo -e "${GREEN}Direct WebSocket connection to n8n successful!${NC}"
    else
        echo -e "${YELLOW}Direct WebSocket connection failed. This might indicate an issue with n8n's WebSocket server.${NC}"
        echo -e "${BLUE}Applying WebSocket fixes to n8n configuration...${NC}"
        
        # Try to fix by explicitly setting WS backend and restarting
        # More robust sed pattern matching that won't fail if pattern not found
        if grep -q "N8N_PUSH_BACKEND=websocket" /etc/systemd/system/n8n.service; then
            sed -i '/Environment=N8N_PUSH_BACKEND=websocket/d' /etc/systemd/system/n8n.service
        fi
        
        # Add WebSocket configuration - safer approach
        if ! grep -q "N8N_PUSH=" /etc/systemd/system/n8n.service; then
            # Find NODE_ENV line and add after it
            sed -i '/Environment=NODE_ENV=production/a Environment=N8N_PUSH_BACKEND=websocket\nEnvironment=N8N_PUSH=1' /etc/systemd/system/n8n.service
        fi
        
        systemctl daemon-reload
        systemctl restart n8n
        sleep 5
    fi
    
    # Test proxied WebSocket connection
    echo -e "${BLUE}Testing proxied WebSocket connection through Apache...${NC}"
    if timeout 5 bash -c "echo -e 'GET /ws HTTP/1.1\r\nHost: $domain\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n' | nc -w 5 localhost 80" | grep -q "Switching Protocols"; then
        echo -e "${GREEN}Proxied WebSocket connection successful!${NC}"
    else
        echo -e "${YELLOW}Proxied WebSocket connection failed. Fixing Apache configuration...${NC}"
        
        # Check if Apache config file exists
        if [ -f "/etc/apache2/sites-available/$domain.conf" ]; then
            echo -e "${BLUE}Adding specific WebSocket fixes to Apache...${NC}"
            
            # Check if Location section exists, if not add it
            if ! grep -q "<Location \/>" "/etc/apache2/sites-available/$domain.conf"; then
                # Add Location section before the closing </VirtualHost>
                sed -i '/<\/VirtualHost>/i \
    <Location \/>\
        ProxyPass http:\/\/127.0.0.1:5678\/\
        ProxyPassReverse http:\/\/127.0.0.1:5678\/\
    <\/Location>' "/etc/apache2/sites-available/$domain.conf"
            fi
            
            # Now add WebSocket configuration to the Location section if not already there
            if ! grep -q "SetEnvIf Upgrade \"^WebSocket" "/etc/apache2/sites-available/$domain.conf"; then
                sed -i '/<Location \/>/a\        SetEnvIf Upgrade "^WebSocket$" WS=1\n        RequestHeader set Connection "upgrade" env=WS\n        RequestHeader set Upgrade "websocket" env=WS' "/etc/apache2/sites-available/$domain.conf"
            fi
            
            # Also add explicit WebSocket endpoints if not present
            if ! grep -q "ProxyPass \/socket.io\/" "/etc/apache2/sites-available/$domain.conf"; then
                sed -i '/<\/VirtualHost>/i \
    # WebSocket endpoints\
    ProxyPass \/socket.io\/ ws:\/\/127.0.0.1:5678\/socket.io\/ nocanon\
    ProxyPassReverse \/socket.io\/ ws:\/\/127.0.0.1:5678\/socket.io\/\
    ProxyPass \/ws ws:\/\/127.0.0.1:5678\/ws nocanon\
    ProxyPassReverse \/ws ws:\/\/127.0.0.1:5678\/ws' "/etc/apache2/sites-available/$domain.conf"
            fi
            
            systemctl restart apache2
        else
            echo -e "${RED}Apache configuration file for $domain not found.${NC}"
            echo -e "${YELLOW}Creating a minimal configuration file...${NC}"
            
            # Create a minimal Apache configuration file
            cat > "/etc/apache2/sites-available/$domain.conf" << EOF
<VirtualHost *:80>
    ServerName $domain
    RewriteEngine On
    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName $domain
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    
    ProxyPreserveHost On
    ProxyRequests Off
    
    <Location />
        ProxyPass http://127.0.0.1:5678/
        ProxyPassReverse http://127.0.0.1:5678/
        
        # WebSocket support
        SetEnvIf Upgrade "^WebSocket$" WS=1
        RequestHeader set Connection "upgrade" env=WS
        RequestHeader set Upgrade "websocket" env=WS
        
        RewriteEngine On
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule /(.*) ws://127.0.0.1:5678/$1 [P,L]
    </Location>
    
    # WebSocket endpoints
    ProxyPass /socket.io/ ws://127.0.0.1:5678/socket.io/ nocanon
    ProxyPassReverse /socket.io/ ws://127.0.0.1:5678/socket.io/
    ProxyPass /ws ws://127.0.0.1:5678/ws nocanon
    ProxyPassReverse /ws ws://127.0.0.1:5678/ws
</VirtualHost>
EOF
            
            a2ensite "$domain.conf"
            systemctl restart apache2
        fi
    fi
    
    # Final connectivity test to ensure service is available
    echo -e "${BLUE}Performing final connectivity check...${NC}"
    
    # Test using curl with proper host resolution for local domains
    local curl_params="-s -o /dev/null -w %{http_code} -k -L"
    
    # For .local domains, ensure we use --resolve to handle DNS resolution
    if [[ "$domain" == *".local" ]]; then
        # First ensure hosts file is correct
        if ! grep -q "$domain" /etc/hosts; then
            echo -e "${BLUE}Adding $domain to /etc/hosts for local testing...${NC}"
            echo "127.0.0.1 $domain" >> /etc/hosts
        fi
        
        # Use --resolve to specify IP for the hostname
        local final_status=$(curl $curl_params --resolve "$domain:443:127.0.0.1" "https://$domain/")
    else
        # Regular curl for normal domains
        local final_status=$(curl $curl_params "https://$domain/")
    fi
    
    if [[ "$final_status" == "401" ]]; then
        echo -e "${GREEN}n8n is successfully responding with authentication required (401). Service is properly configured!${NC}"
    elif [[ "$final_status" == "200" ]]; then
        echo -e "${GREEN}n8n is successfully responding with status 200. Service is properly configured!${NC}"
    else
        echo -e "${YELLOW}n8n is responding with status $final_status. Additional troubleshooting may be needed.${NC}"
        echo -e "${BLUE}Applying final emergency fixes...${NC}"
        
        # Apply emergency fixes for stubborn service unavailable errors
        echo -e "${BLUE}1. Ensuring all required Apache modules are enabled...${NC}"
        a2enmod proxy proxy_http proxy_wstunnel ssl rewrite headers
        
        echo -e "${BLUE}2. Ensuring n8n binding configuration is correct...${NC}"
        if grep -q "Environment=N8N_HOST=localhost" /etc/systemd/system/n8n.service; then
            sed -i 's/Environment=N8N_HOST=localhost/Environment=N8N_HOST=0.0.0.0/' /etc/systemd/system/n8n.service
        fi
        
        echo -e "${BLUE}3. Checking for port conflicts...${NC}"
        if n8n_pid=$(pgrep -f "n8n start" || echo ""); then
            echo -e "${GREEN}n8n process found with PID $n8n_pid${NC}"
        else
            echo -e "${YELLOW}No n8n process found running.${NC}"
        fi
        
        # Check if port 5678 is in use by another process
        if other_pid=$(netstat -tulpn 2>/dev/null | grep ":5678" | awk '{print $7}' | cut -d'/' -f1); then
            if [ -n "$other_pid" ] && [ "$other_pid" != "$n8n_pid" ]; then
                echo -e "${YELLOW}Another process (PID: $other_pid) is using port 5678. Stopping it...${NC}"
                kill -15 $other_pid 2>/dev/null || fuser -k 5678/tcp || true
                sleep 2
            fi
        fi
        
        echo -e "${BLUE}4. Restarting all services...${NC}"
        systemctl daemon-reload
        systemctl restart n8n
        sleep 5
        systemctl restart apache2
        
        # One final check after emergency fixes
        sleep 3
        if [[ "$domain" == *".local" ]]; then
            local final_check=$(curl $curl_params --resolve "$domain:443:127.0.0.1" "https://$domain/")
        else
            local final_check=$(curl $curl_params "https://$domain/")
        fi
        
        if [[ "$final_check" == "401" || "$final_check" == "200" ]]; then
            echo -e "${GREEN}Success! Emergency fixes resolved the issue. n8n is now responding properly.${NC}"
        else
            echo -e "${YELLOW}n8n is still responding with status $final_check.${NC}"
            echo -e "${YELLOW}All emergency fixes have been applied. Please try accessing https://$domain/ in your browser now.${NC}"
            echo -e "${YELLOW}If issues persist, check the logs with: journalctl -u n8n -n 50${NC}"
        fi
    fi
}

# Generate self-signed SSL certificate for domain
generate_self_signed_ssl() {
    local domain=$1
    
    echo -e "${BLUE}Setting up SSL with self-signed certificate for development...${NC}"
    
    # Install openssl if not already installed
    if ! command_exists openssl; then
        echo -e "${YELLOW}OpenSSL not found. Installing...${NC}"
        apt-get update
        apt-get install -y openssl
    fi
    
    # Create directory for certificates if it doesn't exist
    mkdir -p /etc/ssl/private
    
    # Only generate if we're not using the default snakeoil certs
    if [[ "$domain" != "localhost" && "$domain" != "127.0.0.1" ]]; then
        echo -e "${BLUE}Generating custom SSL certificate for $domain...${NC}"
        
        # Generate SSL certificate with proper domain name
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/${domain}.key \
            -out /etc/ssl/certs/${domain}.crt \
            -subj "/CN=${domain}/O=n8n Installation/C=US"
            
        # Update Apache config to use the new certificate
        sed -i "s|SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem|SSLCertificateFile /etc/ssl/certs/${domain}.crt|" /etc/apache2/sites-available/$domain.conf
        sed -i "s|SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key|SSLCertificateKeyFile /etc/ssl/private/${domain}.key|" /etc/apache2/sites-available/$domain.conf
        
        # Update n8n service to use the new certificate
        sed -i "s|N8N_SSL_CERT=/etc/ssl/certs/ssl-cert-snakeoil.pem|N8N_SSL_CERT=/etc/ssl/certs/${domain}.crt|" /etc/systemd/system/n8n.service
        sed -i "s|N8N_SSL_KEY=/etc/ssl/private/ssl-cert-snakeoil.key|N8N_SSL_KEY=/etc/ssl/private/${domain}.key|" /etc/systemd/system/n8n.service
        
        systemctl daemon-reload
    else
        echo -e "${YELLOW}Using default SSL certificate...${NC}"
    fi
}

# Main function
main() {
    echo -e "${GREEN}=== N8N Apache Virtual Host Installer ===${NC}"

    # Display installation options
    echo -e "${BLUE}Please choose an installation option:${NC}"
    echo -e "1) ${GREEN}Full installation${NC} - Install or reinstall n8n with Apache virtual host"
    echo -e "2) ${YELLOW}Repair WebSockets${NC} - Fix WebSocket connections on existing installation"
    echo -e "3) ${RED}Fix 'Service Unavailable'${NC} - Repair n8n service if you're seeing 503 errors"
    echo -e "4) ${RED}Cancel${NC} - Exit without making changes"
    
    read -p "Enter your choice (1-4): " install_option
    
    case $install_option in
        2)
            # WebSocket repair mode
            echo -e "${YELLOW}Starting WebSocket repair mode...${NC}"
            
            # Check if n8n is installed
            if ! command_exists n8n; then
                echo -e "${RED}n8n is not installed. Cannot repair WebSockets.${NC}"
                exit 1
            fi
            
            # Get hostname for default suggestion (with fallback)
            local hostname=$(hostname -s 2>/dev/null || echo "server")
            if [ -z "$hostname" ] || [ "$hostname" == "localhost" ]; then
                hostname="n8n-server"
            fi
            local default_domain="${hostname}-n8n.local"
            
            # Ask for domain with default suggestion
            read -p "Enter your existing n8n domain name [default: $default_domain]: " domain_name
            
            # Use default if empty
            if [ -z "$domain_name" ]; then
                domain_name="$default_domain"
                echo -e "${GREEN}Using default domain: $domain_name${NC}"
                
                # Ensure domain is in hosts file for .local domains
                if [[ "$domain_name" == *".local" ]] && ! grep -q "$domain_name" /etc/hosts; then
                    echo -e "${BLUE}Adding $domain_name to /etc/hosts file...${NC}"
                    echo "127.0.0.1 $domain_name" >> /etc/hosts
                    echo -e "${GREEN}✓ Added to hosts file. You'll be able to access n8n using this hostname.${NC}"
                fi
            fi
            
            # Check if Apache config exists
            if [ ! -f "/etc/apache2/sites-available/$domain_name.conf" ]; then
                echo -e "${RED}Apache configuration for $domain_name not found.${NC}"
                echo -e "${YELLOW}Please run full installation instead.${NC}"
                exit 1
            fi
            
            # Fix Apache config for WebSockets
            echo -e "${BLUE}Updating Apache configuration for WebSockets...${NC}"
            
            # Enable required modules
            echo -e "${BLUE}Enabling required Apache modules...${NC}"
            a2enmod proxy proxy_http proxy_wstunnel headers rewrite ssl
            
            # Update n8n service WebSocket settings
            echo -e "${BLUE}Updating n8n service for WebSockets...${NC}"
            if grep -q "N8N_PUSH_BACKEND" /etc/systemd/system/n8n.service; then
                echo -e "${GREEN}WebSocket backend already configured in n8n service.${NC}"
            else
                echo -e "${BLUE}Adding WebSocket configuration to n8n service...${NC}"
                sed -i '/Environment=NODE_ENV=production/a Environment=N8N_PUSH_BACKEND=websocket\nEnvironment=N8N_PUSH=1\nEnvironment=N8N_WEBSOCKET_URL=wss://'"$domain_name"'/' /etc/systemd/system/n8n.service
                systemctl daemon-reload
            fi
            
            # Run WebSocket test
            echo -e "${BLUE}Testing and fixing WebSocket connections...${NC}"
            systemctl restart n8n apache2
            sleep 5
            test_websockets "$domain_name"
            
            echo -e "${GREEN}WebSocket repair completed!${NC}"
            echo -e "${YELLOW}Please restart your browser and test n8n again.${NC}"
            exit 0
            ;;
            
        3)
            # Service Unavailable repair mode
            echo -e "${YELLOW}Starting 'Service Unavailable' repair mode...${NC}"
            
            # Check if n8n is installed
            if ! command_exists n8n; then
                echo -e "${RED}n8n is not installed. Cannot repair service.${NC}"
                exit 1
            fi
            
            # Get hostname for default suggestion (with fallback)
            local hostname=$(hostname -s 2>/dev/null || echo "server")
            if [ -z "$hostname" ] || [ "$hostname" == "localhost" ]; then
                hostname="n8n-server"
            fi
            local default_domain="${hostname}-n8n.local"
            
            # Ask for domain with default suggestion
            read -p "Enter your existing n8n domain name [default: $default_domain]: " domain_name
            
            # Use default if empty
            if [ -z "$domain_name" ]; then
                domain_name="$default_domain"
                echo -e "${GREEN}Using default domain: $domain_name${NC}"
                
                # Ensure domain is in hosts file for .local domains
                if [[ "$domain_name" == *".local" ]] && ! grep -q "$domain_name" /etc/hosts; then
                    echo -e "${BLUE}Adding $domain_name to /etc/hosts file...${NC}"
                    echo "127.0.0.1 $domain_name" >> /etc/hosts
                    echo -e "${GREEN}✓ Added to hosts file. You'll be able to access n8n using this hostname.${NC}"
                fi
            fi
            
            # Perform comprehensive service repair
            echo -e "${BLUE}Performing comprehensive service repair...${NC}"
            
            # 1. Verify the system has enough resources
            echo -e "${BLUE}Checking system resources...${NC}"
            free_memory=$(free -m | awk '/^Mem:/{print $4}')
            if [ "$free_memory" -lt 500 ]; then
                echo -e "${YELLOW}System has low memory ($free_memory MB). This may cause performance issues.${NC}"
                echo -e "${BLUE}Clearing system caches...${NC}"
                sync; echo 3 > /proc/sys/vm/drop_caches
            fi
            
            # 2. Check for and kill zombie processes
            echo -e "${BLUE}Checking for zombie node processes...${NC}"
            zombie_pids=$(ps aux | grep -i "node.*n8n" | grep -v grep | awk '{print $2}')
            if [ ! -z "$zombie_pids" ]; then
                echo -e "${YELLOW}Found potentially conflicting n8n processes. Stopping them...${NC}"
                for pid in $zombie_pids; do
                    kill -9 $pid 2>/dev/null || true
                done
            fi
            
            # 3. Check for port conflicts
            echo -e "${BLUE}Checking for port conflicts...${NC}"
            if netstat -tulpn | grep -q ":5678"; then
                echo -e "${YELLOW}Port 5678 is in use. Releasing it...${NC}"
                fuser -k 5678/tcp || true
                sleep 2
            fi
            
            # 4. Rebuild n8n service file
            echo -e "${BLUE}Rebuilding n8n service file...${NC}"
            current_user=$(logname 2>/dev/null || echo "root")
            
            cat > /etc/systemd/system/n8n.service << EOF
[Unit]
Description=n8n workflow automation
After=network.target

[Service]
Type=simple
User=$current_user
WorkingDirectory=/var/lib/n8n
Environment=NODE_ENV=production
Environment=N8N_PROTOCOL=http
Environment=N8N_HOST=0.0.0.0
Environment=N8N_PORT=5678
Environment=N8N_EDITOR_BASE_URL=https://$domain_name
Environment=N8N_PUSH_BACKEND=websocket
Environment=N8N_PUSH=1
Environment=N8N_METRICS=true
Environment=N8N_DIAGNOSTICS_ENABLED=true
Environment=NODE_OPTIONS=--max-old-space-size=4096
ExecStart=$(which n8n) start
Restart=always
RestartSec=10
LimitNOFILE=50000

[Install]
WantedBy=multi-user.target
EOF
            
            # 5. Check and fix directory permissions
            echo -e "${BLUE}Setting correct permissions for n8n directory...${NC}"
            mkdir -p /var/lib/n8n
            chown -R $current_user:$current_user /var/lib/n8n
            chmod 755 /var/lib/n8n
            
            # 6. Reload systemd and restart n8n
            echo -e "${BLUE}Restarting n8n service...${NC}"
            systemctl daemon-reload
            systemctl restart n8n
            sleep 10
            
            # 7. Test and fix Apache configuration
            echo -e "${BLUE}Testing and fixing Apache configuration...${NC}"
            
            # Check if Apache config exists
            if [ ! -f "/etc/apache2/sites-available/$domain_name.conf" ]; then
                echo -e "${RED}Apache configuration for $domain_name not found.${NC}"
                echo -e "${YELLOW}Creating minimal Apache configuration...${NC}"
                
                # Generate a self-signed SSL certificate if needed
                if [[ "$domain_name" == *".local" ]] && [ ! -f "/etc/ssl/certs/${domain_name}.crt" ]; then
                    echo -e "${BLUE}Generating self-signed certificate for $domain_name...${NC}"
                    
                    # Ensure openssl is installed
                    if ! command_exists openssl; then
                        apt-get update && apt-get install -y openssl
                    fi
                    
                    # Generate the certificate
                    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                        -keyout "/etc/ssl/private/${domain_name}.key" \
                        -out "/etc/ssl/certs/${domain_name}.crt" \
                        -subj "/CN=${domain_name}/O=n8n Installation/C=US"
                    
                    cert_file="/etc/ssl/certs/${domain_name}.crt"
                    key_file="/etc/ssl/private/${domain_name}.key"
                else
                    cert_file="/etc/ssl/certs/ssl-cert-snakeoil.pem"
                    key_file="/etc/ssl/private/ssl-cert-snakeoil.key"
                fi
                
                # Create a minimal working configuration
                cat > /etc/apache2/sites-available/$domain_name.conf << EOF
<VirtualHost *:80>
    ServerName $domain_name
    RewriteEngine On
    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName $domain_name
    
    SSLEngine on
    SSLCertificateFile $cert_file
    SSLCertificateKeyFile $key_file
    
    # Enhanced SSL security
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder on
    SSLCompression off
    
    ProxyPreserveHost On
    ProxyRequests Off
    
    <Location />
        ProxyPass http://127.0.0.1:5678/
        ProxyPassReverse http://127.0.0.1:5678/
        
        # WebSocket support
        SetEnvIf Upgrade "^WebSocket$" WS=1
        RequestHeader set Connection "upgrade" env=WS
        RequestHeader set Upgrade "websocket" env=WS
        
        RewriteEngine On
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule /(.*) ws://127.0.0.1:5678/$1 [P,L]
    </Location>
    
    # Forward proper headers
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port "443"
    
    # Proxy WebSocket specific endpoints
    ProxyPass /socket.io/ ws://127.0.0.1:5678/socket.io/ nocanon
    ProxyPassReverse /socket.io/ ws://127.0.0.1:5678/socket.io/
    ProxyPass /ws ws://127.0.0.1:5678/ws nocanon
    ProxyPassReverse /ws ws://127.0.0.1:5678/ws
    
    # Prevent timeouts for long-running WebSocket connections
    ProxyTimeout 3600
    Timeout 3600
</VirtualHost>
EOF

                a2ensite "$domain_name.conf"
            else
                # Fix existing Apache configuration
                echo -e "${BLUE}Fixing existing Apache configuration...${NC}"
                
                # Use 127.0.0.1 instead of localhost
                sed -i 's/localhost:5678/127.0.0.1:5678/g' /etc/apache2/sites-available/$domain_name.conf
                
                # Add WebSocket support if missing
                if ! grep -q "socket.io" /etc/apache2/sites-available/$domain_name.conf; then
                    echo -e "${YELLOW}Adding WebSocket support to Apache configuration...${NC}"
                    
                    # Add socket.io support just before the last </VirtualHost>
                    sed -i '/<\/VirtualHost>/i \
    ProxyPass /socket.io/ ws://127.0.0.1:5678/socket.io/ nocanon\
    ProxyPassReverse /socket.io/ ws://127.0.0.1:5678/socket.io/\
    ProxyPass /ws ws://127.0.0.1:5678/ws nocanon\
    ProxyPassReverse /ws ws://127.0.0.1:5678/ws' /etc/apache2/sites-available/$domain_name.conf
                fi
            fi
            
            # 8. Enable required Apache modules
            echo -e "${BLUE}Enabling required Apache modules...${NC}"
            a2enmod proxy proxy_http proxy_wstunnel ssl rewrite headers
            
            # 9. Restart Apache
            systemctl restart apache2
            
            # 10. Run final connectivity tests
            echo -e "${BLUE}Running final connectivity tests...${NC}"
            fix_service_unavailable "$domain_name"
            
            # 11. Check if n8n is now working
            if systemctl is-active --quiet n8n; then
                n8n_status=$(curl -s -o /dev/null -w "%{http_code}" -k -L https://$domain_name/)
                
                if [[ "$n8n_status" == "200" || "$n8n_status" == "401" ]]; then
                    echo -e "${GREEN}SUCCESS! Service Unavailable issue has been fixed.${NC}"
                    echo -e "${GREEN}n8n is now responding properly with status code $n8n_status.${NC}"
                    echo -e "${GREEN}You can now access n8n at: https://$domain_name${NC}"
                else
                    echo -e "${YELLOW}n8n service is running but returning status code $n8n_status.${NC}"
                    echo -e "${YELLOW}This might indicate authentication or other configuration issues.${NC}"
                    echo -e "${YELLOW}Try accessing https://$domain_name/ in your browser.${NC}"
                fi
            else
                echo -e "${RED}n8n service is still not running. Please check logs with:${NC}"
                echo -e "${BLUE}journalctl -u n8n -n 50${NC}"
            fi
            
            exit 0
            ;;
            
        4)
            echo -e "${YELLOW}Installation cancelled. Exiting...${NC}"
            exit 0
            ;;
            
        *)
            echo -e "${BLUE}Proceeding with full installation...${NC}"
            ;;
    esac

    # Check requirements
    check_requirements
    
    # Check if n8n is already installed
    if command_exists n8n; then
        echo -e "${YELLOW}n8n is already installed on this system.${NC}"
        echo -e "Current version: $(n8n --version 2>/dev/null || echo "Version not available")"
        
        read -p "Do you want to reinstall n8n? (y/n): " reinstall_choice
        if [[ "$reinstall_choice" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Proceeding with reinstallation...${NC}"
            
            # Stop existing n8n service if it exists
            if systemctl is-active --quiet n8n; then
                echo -e "${BLUE}Stopping existing n8n service...${NC}"
                systemctl stop n8n
            fi
            
            # Uninstall existing n8n
            echo -e "${BLUE}Uninstalling existing n8n...${NC}"
            npm uninstall -g n8n
            
            # Remove existing service file
            if [ -f /etc/systemd/system/n8n.service ]; then
                echo -e "${BLUE}Removing existing service file...${NC}"
                rm -f /etc/systemd/system/n8n.service
                systemctl daemon-reload
            fi
            
            # Ask if data should be kept
            read -p "Do you want to keep existing n8n data? (y/n): " keep_data
            if [[ ! "$keep_data" =~ ^[Yy]$ ]] && [ -d /var/lib/n8n ]; then
                echo -e "${YELLOW}Backing up existing data to /var/lib/n8n.bak...${NC}"
                mv /var/lib/n8n /var/lib/n8n.bak
            fi
            
            echo -e "${GREEN}Ready to proceed with fresh installation.${NC}"
        else
            echo -e "${YELLOW}Installation cancelled. Exiting...${NC}"
            exit 0
        fi
    fi

    # Get hostname for default suggestion (with fallback)
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
        
        # Check if domain is already in hosts file
        if ! grep -q "$domain_name" /etc/hosts; then
            echo -e "${BLUE}Adding $domain_name to /etc/hosts file...${NC}"
            echo "127.0.0.1 $domain_name" >> /etc/hosts
            echo -e "${GREEN}✓ Added to hosts file. You'll be able to access n8n using this hostname.${NC}"
        else
            echo -e "${GREEN}✓ $domain_name is already in your hosts file.${NC}"
        fi
        
        # Display hostname information
        echo -e "${YELLOW}Note: Since you're using a .local domain, you'll only be able to access n8n${NC}"
        echo -e "${YELLOW}from this machine or from your local network with proper mDNS/Bonjour support.${NC}"
    fi

    # Install n8n
    install_n8n

    # Check for existing Apache config
    if [ -f "/etc/apache2/sites-available/$domain_name.conf" ]; then
        echo -e "${YELLOW}An Apache configuration for $domain_name already exists.${NC}"
        read -p "Do you want to overwrite it? (y/n): " overwrite_apache
        
        if [[ "$overwrite_apache" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Removing existing Apache configuration...${NC}"
            a2dissite "$domain_name.conf" 2>/dev/null
            rm -f "/etc/apache2/sites-available/$domain_name.conf"
            systemctl reload apache2
        else
            echo -e "${YELLOW}Keeping existing Apache configuration.${NC}"
            echo -e "${YELLOW}Note: This may cause issues if the configuration is not compatible with this script.${NC}"
            # Skip Apache config creation
            create_apache_config_skip=true
        fi
    fi
    
    # Create Apache config if not skipped
    if [ "$create_apache_config_skip" != "true" ]; then
        create_apache_config "$domain_name" "$auth_file"
    fi
    
    # Generate self-signed SSL certificate for the domain
    generate_self_signed_ssl "$domain_name"

    # Create password file
    create_password_file "$username" "$auth_file"

    # Restart Apache
    echo -e "${BLUE}Restarting Apache...${NC}"
    systemctl restart apache2

    # Start n8n
    echo -e "${BLUE}Starting n8n service...${NC}"
    systemctl start n8n
    
    # Wait a bit longer for services to fully start
    echo -e "${BLUE}Waiting for services to fully start...${NC}"
    sleep 10

    # Check if service started successfully
    sleep 5
    if ! systemctl is-active --quiet n8n; then
        echo -e "${RED}n8n service failed to start. Checking logs...${NC}"
        journalctl -u n8n -n 20
        echo -e "\n${YELLOW}Attempting to fix common issues...${NC}"

        # Try installing with --unsafe-perm (common fix)
        echo -e "${BLUE}Reinstalling n8n with --unsafe-perm...${NC}"
        npm install -g n8n --unsafe-perm

        # Try starting again
        systemctl restart n8n
        sleep 5

        if systemctl is-active --quiet n8n; then
            echo -e "${GREEN}n8n service started successfully after fix!${NC}"
        else
            echo -e "${RED}n8n service still failing. Please check logs with: journalctl -u n8n${NC}"
        fi
    else
        echo -e "${GREEN}n8n service started successfully!${NC}"
    fi

    # Verify connection to n8n
    echo -e "${BLUE}Verifying connection to n8n...${NC}"
    
    # Test HTTP connection first
    if curl -s http://localhost:5678/ > /dev/null; then
        echo -e "${GREEN}n8n is responding on localhost:5678${NC}"
        
        # Test HTTP to HTTPS redirection
        echo -e "${BLUE}Testing HTTP to HTTPS redirection...${NC}"
        if curl -s -I -L http://$domain_name/ -H "Host: $domain_name" --resolve "$domain_name:80:127.0.0.1" | grep -i "Location: https://"; then
            echo -e "${GREEN}HTTP to HTTPS redirection is working correctly${NC}"
        else
            echo -e "${YELLOW}HTTP to HTTPS redirection may not be working. Check Apache configuration.${NC}"
        fi
        
        # Test HTTPS connection
        echo -e "${BLUE}Testing HTTPS connection...${NC}"
        if curl -s -I -k https://$domain_name/ -H "Host: $domain_name" --resolve "$domain_name:443:127.0.0.1" | grep -i "HTTP/1.1 401"; then
            echo -e "${GREEN}HTTPS connection and Apache proxy are correctly forwarding to n8n (401 response with auth expected)${NC}"
        else
            echo -e "${YELLOW}HTTPS connection is not responding as expected. Check Apache SSL configuration.${NC}"
            echo -e "${BLUE}Checking SSL configuration and restarting Apache...${NC}"
            apache2ctl -t
            systemctl restart apache2
        fi
        
        # Verify WebSocket modules
        echo -e "${BLUE}Verifying WebSocket modules...${NC}"
        if apache2ctl -M | grep -E 'proxy_wstunnel|rewrite'; then
            echo -e "${GREEN}WebSocket modules are properly enabled${NC}"
        else
            echo -e "${YELLOW}WebSocket modules may not be properly enabled. Re-enabling...${NC}"
            a2enmod proxy_wstunnel rewrite
            systemctl restart apache2
        fi
    else
        echo -e "${RED}Could not connect to n8n on localhost:5678${NC}"
        echo -e "${YELLOW}Trying alternative troubleshooting...${NC}"

        # Diagnose potential n8n startup issues
        echo -e "${BLUE}Checking for common n8n issues...${NC}"
        
        # Check if port 5678 is in use by another process
        if netstat -tulpn | grep 5678; then
            echo -e "${YELLOW}Port 5678 is already in use by another process. Stopping conflicting process...${NC}"
            fuser -k 5678/tcp || true
        fi
        
        # Try with different user
        echo -e "${BLUE}Adjusting service to run as current user...${NC}"
        current_user=$(logname || echo "root")
        sed -i "s/User=root/User=$current_user/" /etc/systemd/system/n8n.service
        
        # Fix permissions for n8n directory
        echo -e "${BLUE}Adjusting permissions for n8n directory...${NC}"
        chown -R $current_user:$current_user /var/lib/n8n
        
        # Reload and restart
        systemctl daemon-reload
        systemctl restart n8n
        sleep 8

        if systemctl is-active --quiet n8n; then
            echo -e "${GREEN}n8n service started successfully with user $current_user!${NC}"
        else
            echo -e "${RED}Still having issues with n8n service.${NC}"
            echo -e "${YELLOW}Trying one more fix: reinstalling n8n with npm cache clean...${NC}"
            
            npm cache clean --force
            npm install -g n8n --unsafe-perm
            systemctl restart n8n
            sleep 5
            
            if systemctl is-active --quiet n8n; then
                echo -e "${GREEN}n8n service started successfully after cache clean!${NC}"
            else
                echo -e "${RED}n8n service still failing. Please check the detailed logs.${NC}"
                journalctl -u n8n -n 30
            fi
        fi
    fi
    
    # Test and fix WebSocket connections if the service is running
    if systemctl is-active --quiet n8n; then
        echo -e "${BLUE}Testing and configuring WebSocket connections...${NC}"
        test_websockets "$domain_name"
    fi

    # Summary
    echo -e "\n${GREEN}=== Installation Complete ===${NC}"
    echo -e "n8n is now installed and configured with the following details:"
    echo -e "Domain: ${YELLOW}https://$domain_name${NC}"
    echo -e "Username: ${YELLOW}$username${NC}"
    echo -e "Password: ${YELLOW}(As entered)${NC}"
    echo -e "\nTo access n8n, open ${GREEN}https://$domain_name${NC} in your browser."
    echo -e "Use the username and password you provided during installation."
    
    # Local domain specific notes
    if [[ "$domain_name" == *".local" ]]; then
        echo -e "\n${BLUE}Local Domain Information:${NC}"
        echo -e "- You are using a .local domain which has been added to your /etc/hosts file"
        echo -e "- This domain will only work on this machine or on your local network with mDNS/Bonjour"
        echo -e "- Other devices on your network may need to add this hostname to their hosts file"
        echo -e "- The local IP address of this server is: ${YELLOW}$(hostname -I | awk '{print $1}')${NC}"
    fi
    
    echo -e "\n${YELLOW}Note:${NC} A self-signed SSL certificate has been created for your domain."
    echo -e "Your browser will likely show a security warning. This is normal for self-signed certificates."
    echo -e "You can safely proceed by accepting the certificate exception in your browser."

    # Optional: Add instructions for SSL
    echo -e "\n${YELLOW}Note:${NC} For production use, it's recommended to secure your site with SSL using Let's Encrypt."
    echo -e "You can run: ${GREEN}certbot --apache -d $domain_name${NC}"

    echo -e "\n${BLUE}n8n service management:${NC}"
    echo -e "  Start: ${GREEN}systemctl start n8n${NC}"
    echo -e "  Stop: ${GREEN}systemctl stop n8n${NC}"
    echo -e "  Restart: ${GREEN}systemctl restart n8n${NC}"
    echo -e "  Status: ${GREEN}systemctl status n8n${NC}"
    echo -e "  View logs: ${GREEN}journalctl -u n8n -f${NC}"

    echo -e "\n${BLUE}Troubleshooting:${NC}"
    echo -e "  If you see 'Service Unavailable' or have WebSocket connection issues, try these steps:"
    echo -e "  1. Check n8n status: ${GREEN}systemctl status n8n${NC}"
    echo -e "  2. Check logs: ${GREEN}journalctl -u n8n -f${NC} and ${GREEN}tail -f /var/log/apache2/error.log${NC}"
    echo -e "  3. Make sure port 5678 is not in use: ${GREEN}netstat -tulpn | grep 5678${NC}"
    echo -e "  4. Restart n8n and Apache: ${GREEN}systemctl restart n8n apache2${NC}"
    echo -e "  5. Verify WebSocket modules are enabled: ${GREEN}apache2ctl -M | grep -E 'proxy_wstunnel|rewrite'${NC}"
    echo -e "  6. Test direct WebSocket connections:"
    echo -e "     - HTTP WebSocket: ${GREEN}curl -v -N -H \"Connection: Upgrade\" -H \"Upgrade: websocket\" http://localhost:5678/ws${NC}"
    echo -e "     - HTTPS WebSocket: ${GREEN}curl -v -N -k -H \"Connection: Upgrade\" -H \"Upgrade: websocket\" https://localhost:5678/ws${NC}"
    echo -e "  7. Check for WebSocket errors in browser console (F12) when using the n8n interface"
    echo -e "  8. Verify SSL configuration with: ${GREEN}apache2ctl -t${NC}"
    echo -e "  9. Check SSL certificate with: ${GREEN}openssl x509 -text -noout -in /etc/ssl/certs/${domain_name}.crt${NC}"
    echo -e "  10. Test secure WebSocket (WSS) connection with:"
    echo -e "     ${GREEN}curl -v -N -k -H \"Connection: Upgrade\" -H \"Upgrade: websocket\" https://${domain_name}/ws${NC}"
    echo -e "     ${GREEN}curl -v -N -k -H \"Connection: Upgrade\" -H \"Upgrade: websocket\" https://${domain_name}/socket.io/?EIO=4&transport=websocket${NC}"
    echo -e "  11. Check browser Network tab (F12) for WebSocket connections - look for connections to /socket.io/ and /ws"
    echo -e "  12. Try reinstalling n8n with: ${GREEN}npm install -g n8n --unsafe-perm${NC}"
    echo -e "  13. If you see '502 Bad Gateway' errors, check that n8n is running and listening on localhost:5678"
    echo -e "  14. For editor freezes or slow interface, check: ${GREEN}journalctl -u n8n | grep -i websocket${NC}"

    echo -e "\n${GREEN}Script by Antonin Nvh - https://codequantum.io${NC}"
}

# Run main function
main