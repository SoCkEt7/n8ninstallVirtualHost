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
    a2enmod proxy proxy_http proxy_wstunnel headers rewrite auth_basic authn_file ssl proxy_balancer proxy_connect
}

# Install n8n
install_n8n() {
    echo -e "${BLUE}Installing n8n...${NC}"

    # Check if n8n is already installed
    if command_exists n8n; then
        echo -e "${YELLOW}n8n is already installed. Skipping installation.${NC}"
    else
        echo -e "${BLUE}Installing n8n globally...${NC}"
        npm install -g n8n

        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to install n8n. Please check npm configuration and try again.${NC}"
            exit 1
        fi
    fi

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
Environment=N8N_PROTOCOL=http
Environment=N8N_EDITOR_BASE_URL=
Environment=N8N_METRICS=true
Environment=N8N_DIAGNOSTICS_ENABLED=true
Environment=N8N_HIRING_BANNER_ENABLED=false
Environment=N8N_VERSION_NOTIFICATIONS_ENABLED=false
Environment=N8N_USER_MANAGEMENT_DISABLED=false
Environment=N8N_CLUSTER_ENABLED=false
Environment=N8N_DIAGNOSTICS_CONFIG_STATS_SHARING_ENABLED=true
Environment=WEBHOOK_URL=http://localhost:5678/
Environment=WEBHOOK_TUNNEL_URL=
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

    # Proxy rules with WebSocket support (required for n8n)
    ProxyPass / http://localhost:5678/
    ProxyPassReverse / http://localhost:5678/

    # WebSocket proxy configuration
    ProxyPass /favicon.ico http://localhost:5678/favicon.ico
    ProxyPass /webhook http://localhost:5678/webhook
    ProxyPass /rest http://localhost:5678/rest
    
    # Enhanced WebSocket handling - ensures all WebSocket paths work correctly
    # Main WebSocket endpoints
    ProxyPass /ws ws://localhost:5678/ws
    ProxyPassReverse /ws ws://localhost:5678/ws
    ProxyPass /socket.io/ ws://localhost:5678/socket.io/
    ProxyPassReverse /socket.io/ ws://localhost:5678/socket.io/
    
    # Advanced WebSocket handling with proper upgrade headers
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) ws://localhost:5678/$1 [P,L,NE]
    
    # Ensure headers are correctly set for all proxied requests
    ProxyAddHeaders On
    RequestHeader set X-Forwarded-Proto "http"
    RequestHeader set X-Forwarded-Port "80"
    
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

    # Add domain to /etc/hosts for local development (if needed)
    if ! grep -q "$domain" /etc/hosts; then
        echo -e "${BLUE}Adding $domain to /etc/hosts...${NC}"
        echo "127.0.0.1 $domain" >> /etc/hosts
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

# Main function
main() {
    echo -e "${GREEN}=== N8N Apache Virtual Host Installer ===${NC}"

    # Check requirements
    check_requirements

    # Ask for domain
    read -p "Enter domain name for n8n (e.g., n8n.example.com): " domain_name
    if [ -z "$domain_name" ]; then
        echo -e "${RED}Domain name cannot be empty.${NC}"
        exit 1
    fi

    # Ask for username
    read -p "Enter username for n8n authentication: " username
    if [ -z "$username" ]; then
        echo -e "${RED}Username cannot be empty.${NC}"
        exit 1
    fi

    # Define auth file location
    auth_file="/etc/apache2/.htpasswd-n8n"

    # Install n8n
    install_n8n

    # Create Apache config
    create_apache_config "$domain_name" "$auth_file"

    # Create password file
    create_password_file "$username" "$auth_file"

    # Restart Apache
    echo -e "${BLUE}Restarting Apache...${NC}"
    systemctl restart apache2

    # Start n8n
    echo -e "${BLUE}Starting n8n service...${NC}"
    systemctl start n8n

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
        
        # Test Apache proxy connection
        echo -e "${BLUE}Testing Apache proxy connection...${NC}"
        if curl -s -I http://$domain_name/ -H "Host: $domain_name" --resolve "$domain_name:80:127.0.0.1" | grep -i "HTTP/1.1 401"; then
            echo -e "${GREEN}Apache proxy is correctly forwarding to n8n (401 response with auth expected)${NC}"
        else
            echo -e "${YELLOW}Apache proxy is not responding as expected. Check Apache configuration.${NC}"
            echo -e "${BLUE}Restarting Apache...${NC}"
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

    # Summary
    echo -e "\n${GREEN}=== Installation Complete ===${NC}"
    echo -e "n8n is now installed and configured with the following details:"
    echo -e "Domain: ${YELLOW}http://$domain_name${NC}"
    echo -e "Username: ${YELLOW}$username${NC}"
    echo -e "Password: ${YELLOW}(As entered)${NC}"
    echo -e "\nTo access n8n, open ${GREEN}http://$domain_name${NC} in your browser."
    echo -e "Use the username and password you provided during installation."

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
    echo -e "  6. Test direct WebSocket connection: ${GREEN}curl -v -N -H \"Connection: Upgrade\" -H \"Upgrade: websocket\" http://localhost:5678/ws${NC}"
    echo -e "  7. Check for WebSocket errors in browser console (F12) when using the n8n interface"
    echo -e "  8. Try reinstalling n8n with: ${GREEN}npm install -g n8n --unsafe-perm${NC}"
    echo -e "  9. If you see '502 Bad Gateway' errors, check that n8n is running and listening on localhost:5678"

    echo -e "\n${GREEN}Script by Antonin Nvh - https://codequantum.io${NC}"
}

# Run main function
main