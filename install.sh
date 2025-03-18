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
        echo -e "${YELLOW}Node.js is not installed. Installing...${NC}"
        apt-get update
        apt-get install -y ca-certificates curl gnupg
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
        echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_18.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
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
    a2enmod proxy proxy_http proxy_wstunnel headers rewrite auth_basic authn_file
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
ExecStart=$(which n8n) start
Restart=on-failure
RestartSec=10

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
    ProxyPass /ws ws://localhost:5678/ws

    # Remove Upgrade header for non-websocket connections
    SetEnvIf Upgrade "^WebSocket$" WS=1
    RequestHeader set Connection "upgrade" env=WS
    RequestHeader set Upgrade "websocket" env=WS

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
    if curl -s http://localhost:5678/ > /dev/null; then
        echo -e "${GREEN}n8n is responding on localhost:5678${NC}"
    else
        echo -e "${RED}Could not connect to n8n on localhost:5678${NC}"
        echo -e "${YELLOW}Trying alternative troubleshooting...${NC}"

        # Try with different user
        echo -e "${BLUE}Adjusting service to run as current user...${NC}"
        current_user=$(logname || echo "root")
        sed -i "s/User=root/User=$current_user/" /etc/systemd/system/n8n.service
        systemctl daemon-reload
        systemctl restart n8n
        sleep 5

        if systemctl is-active --quiet n8n; then
            echo -e "${GREEN}n8n service started successfully with user $current_user!${NC}"
        else
            echo -e "${RED}Still having issues. Please check the logs.${NC}"
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
    echo -e "  If you see 'Service Unavailable', try these steps:"
    echo -e "  1. Check n8n status: ${GREEN}systemctl status n8n${NC}"
    echo -e "  2. Check logs: ${GREEN}journalctl -u n8n -f${NC}"
    echo -e "  3. Make sure port 5678 is not in use: ${GREEN}netstat -tulpn | grep 5678${NC}"
    echo -e "  4. Restart n8n and Apache: ${GREEN}systemctl restart n8n apache2${NC}"
    echo -e "  5. Try reinstalling n8n with: ${GREEN}npm install -g n8n --unsafe-perm${NC}"

    echo -e "\n${GREEN}Script by Antonin Nvh - https://codequantum.io${NC}"
}

# Run main function
main