#!/bin/bash

# n8n Docker Installation with Domain Support
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

    # Check for Docker
    if ! command_exists docker; then
        echo -e "${YELLOW}Docker is not installed. Installing...${NC}"
        apt-get update
        apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io
    fi

    # Check for Docker Compose
    if ! command_exists docker-compose; then
        echo -e "${YELLOW}Docker Compose is not installed. Installing...${NC}"
        apt-get update
        apt-get install -y docker-compose-plugin
        # Create symlink for convenience
        ln -sf /usr/libexec/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose
    fi

    # Install additional required packages
    echo -e "${BLUE}Installing additional required packages...${NC}"
    apt-get install -y apache2-utils
}

# Create Docker Compose configuration
create_docker_compose() {
    local domain=$1
    local n8n_data_dir="/opt/n8n/data"
    local n8n_db_dir="/opt/n8n/db"
    
    echo -e "${BLUE}Creating directories for n8n data...${NC}"
    mkdir -p "$n8n_data_dir"
    mkdir -p "$n8n_db_dir"
    
    echo -e "${BLUE}Creating docker-compose configuration...${NC}"
    
    mkdir -p /opt/n8n
    cat > /opt/n8n/docker-compose.yml << EOF
version: '3'

services:
  n8n:
    image: n8nio/n8n:latest
    restart: always
    ports:
      # Main n8n port - removed from expose to outside
      - "127.0.0.1:5678:5678"
    environment:
      - N8N_HOST=0.0.0.0
      - N8N_PORT=5678
      - NODE_ENV=production
      # n8n uses HTTP locally (Nginx or Apache handles HTTPS)
      - N8N_PROTOCOL=http
      # Set public-facing URLs to HTTPS with the domain
      - N8N_EDITOR_BASE_URL=https://${domain}
      - WEBHOOK_URL=https://${domain}/
      - N8N_WEBSOCKET_URL=wss://${domain}/
      # Security settings
      - N8N_SECURE_COOKIES=true
      - N8N_ENCRYPTION_KEY=$(openssl rand -hex 16)
      # WebSocket configuration
      - N8N_PUSH_BACKEND=websocket
      - N8N_PUSH=1
      # Skip self-signed certificate validation for local development
      - NODE_TLS_REJECT_UNAUTHORIZED=0
      # Disable unnecessary notifications
      - N8N_METRICS=true
      - N8N_DIAGNOSTICS_ENABLED=true
      - N8N_HIRING_BANNER_ENABLED=false
      - N8N_VERSION_NOTIFICATIONS_ENABLED=false
      - N8N_USER_MANAGEMENT_DISABLED=false
      - N8N_CLUSTER_ENABLED=false
      - N8N_DIAGNOSTICS_CONFIG_STATS_SHARING_ENABLED=true
      # Performance tuning
      - NODE_OPTIONS=--max-old-space-size=4096
    volumes:
      - ${n8n_data_dir}:/home/node/.n8n
    command: n8n start --tunnel
    networks:
      - n8n-network
    depends_on:
      - n8n-postgres

  n8n-postgres:
    image: postgres:14
    restart: always
    environment:
      - POSTGRES_USER=n8n
      - POSTGRES_PASSWORD=$(openssl rand -hex 32)
      - POSTGRES_DB=n8n
    volumes:
      - ${n8n_db_dir}:/var/lib/postgresql/data
    networks:
      - n8n-network

networks:
  n8n-network:
    driver: bridge
EOF

    # Create .env file to store environment variables
    cat > /opt/n8n/.env << EOF
N8N_DOMAIN=${domain}
N8N_DATA_DIR=${n8n_data_dir}
N8N_DB_DIR=${n8n_db_dir}
EOF

    echo -e "${GREEN}Docker Compose configuration created at /opt/n8n/docker-compose.yml${NC}"
}

# Create Nginx configuration
create_nginx_config() {
    local domain=$1
    local auth_file=$2

    echo -e "${BLUE}Creating Nginx virtual host configuration for ${YELLOW}$domain${NC}"
    
    # Check if Nginx is installed
    if ! command_exists nginx; then
        echo -e "${YELLOW}Nginx is not installed. Installing...${NC}"
        apt-get update
        apt-get install -y nginx
    fi
    
    # Create Nginx config directory if it doesn't exist
    mkdir -p /etc/nginx/sites-available
    mkdir -p /etc/nginx/sites-enabled
    
    # Create the Nginx config file
    cat > /etc/nginx/sites-available/$domain.conf << EOF
server {
    listen 80;
    server_name $domain;
    
    # Redirect all HTTP traffic to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $domain;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    # Comment out the above and uncomment below after you get a real certificate
    # ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # Basic authentication
    auth_basic "Restricted Area";
    auth_basic_user_file $auth_file;
    
    # Set headers for security
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    
    # Proxy settings
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    client_max_body_size 0;
    
    # Regular HTTP endpoints
    location /favicon.ico {
        proxy_pass http://127.0.0.1:5678/favicon.ico;
    }
    
    location /webhook {
        proxy_pass http://127.0.0.1:5678/webhook;
    }
    
    location /rest {
        proxy_pass http://127.0.0.1:5678/rest;
    }
    
    # WebSocket endpoints
    location /ws {
        proxy_pass http://127.0.0.1:5678/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    location /socket.io/ {
        proxy_pass http://127.0.0.1:5678/socket.io/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    location /webhooks/ {
        proxy_pass http://127.0.0.1:5678/webhooks/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Main application proxy with WebSocket support
    location / {
        proxy_pass http://127.0.0.1:5678/;
        
        # Add WebSocket support to main location
        proxy_http_version 1.1;
        
        # Handle upgrade if present
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
    }
    
    # Logs
    access_log /var/log/nginx/$domain-access.log;
    error_log /var/log/nginx/$domain-error.log;
}
EOF

    # Add connection upgrade mapping to nginx.conf http block if not already there
    if ! grep -q "map \$http_upgrade \$connection_upgrade" /etc/nginx/nginx.conf; then
        echo -e "${BLUE}Adding WebSocket connection mapping to Nginx main config...${NC}"
        
        # Create a backup
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
        
        # Add the map directive to the http block
        awk '
        /^http {/ {
          print;
          print "    # WebSocket support";
          print "    map \\$http_upgrade \\$connection_upgrade {";
          print "        default upgrade;";
          print "        \'\' close;";
          print "    }";
          next;
        }
        {print}
        ' /etc/nginx/nginx.conf.bak > /etc/nginx/nginx.conf
    fi

    # Enable the site
    if [ -d /etc/nginx/sites-enabled ]; then
        ln -sf /etc/nginx/sites-available/$domain.conf /etc/nginx/sites-enabled/
    fi
    
    # Check nginx config
    echo -e "${BLUE}Testing Nginx configuration...${NC}"
    nginx -t
    
    # Restart Nginx
    echo -e "${BLUE}Restarting Nginx...${NC}"
    systemctl restart nginx
}

# Create Apache configuration
create_apache_config() {
    local domain=$1
    local auth_file=$2

    echo -e "${BLUE}Creating Apache virtual host configuration for ${YELLOW}$domain${NC}"

    # Check if Apache is installed
    if ! command_exists apache2; then
        echo -e "${YELLOW}Apache2 is not installed. Installing...${NC}"
        apt-get update
        apt-get install -y apache2
    fi

    # Enable required Apache modules
    echo -e "${BLUE}Enabling required Apache modules...${NC}"
    a2enmod proxy proxy_http proxy_wstunnel headers rewrite auth_basic authn_file ssl proxy_balancer proxy_connect http2 socache_shmcb

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
    # These will be automatically updated when you run certbot
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

    # Comprehensive proxy configuration with WebSocket support
    ProxyPass /favicon.ico http://localhost:5678/favicon.ico
    ProxyPassReverse /favicon.ico http://localhost:5678/favicon.ico
    ProxyPass /webhook http://localhost:5678/webhook
    ProxyPassReverse /webhook http://localhost:5678/webhook
    ProxyPass /rest http://localhost:5678/rest
    ProxyPassReverse /rest http://localhost:5678/rest
    
    # Comprehensive WebSocket proxy configuration for all endpoints
    # Direct WebSocket endpoint mappings
    ProxyPass /ws ws://127.0.0.1:5678/ws nocanon
    ProxyPassReverse /ws ws://127.0.0.1:5678/ws
    ProxyPass /socket.io/ ws://127.0.0.1:5678/socket.io/ nocanon
    ProxyPassReverse /socket.io/ ws://127.0.0.1:5678/socket.io/
    ProxyPass /webhooks/ ws://127.0.0.1:5678/webhooks/ nocanon
    ProxyPassReverse /webhooks/ ws://127.0.0.1:5678/webhooks/
    
    # Force HTTP protocol to use WebSockets
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
    
    <Location /webhooks/>
        ProxyPass ws://127.0.0.1:5678/webhooks/
        RewriteEngine On
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule webhooks/(.*) ws://127.0.0.1:5678/webhooks/$1 [P,L]
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
    
    # Set proper headers for WebSocket and proxy
    ProxyPreserveHost On
    ProxyAddHeaders On
    ProxyRequests Off
    
    # Explicitly handle connection upgrade headers
    SetEnvIf Request_URI "^/ws" WSREQUEST=1
    SetEnvIf Request_URI "^/socket.io/" WSREQUEST=1
    SetEnvIf Request_URI "^/webhooks/" WSREQUEST=1
    RequestHeader set Connection upgrade env=WSREQUEST
    RequestHeader set Upgrade websocket env=WSREQUEST
    
    # Forward proper headers to backend
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port "443"
    RequestHeader set X-Forwarded-For "%{REMOTE_ADDR}"
    RequestHeader set Host "%{HTTP_HOST}"
    
    # Specific WebSocket headers
    SetEnvIf Origin "^(https?://.+)$" ORIGIN=$1
    Header set Access-Control-Allow-Origin "*" env=ORIGIN
    Header set Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    Header set Access-Control-Allow-Headers "origin, x-requested-with, content-type, authorization"
    Header set Access-Control-Allow-Credentials "true"
    
    # Ensure WebSocket connection upgrade headers are passed
    RewriteEngine On
    RewriteCond %{HTTP:Connection} Upgrade [NC]
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:5678/$1 [P,L]
    
    # Prevent timeouts for long-running WebSocket connections
    ProxyTimeout 3600
    Timeout 3600

    # Headers
    Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains;"

    # Logs
    ErrorLog ${APACHE_LOG_DIR}/$domain-error.log
    CustomLog ${APACHE_LOG_DIR}/$domain-access.log combined
</VirtualHost>
EOF

    # Enable the site
    a2ensite $domain.conf
    
    # Check if we need to setup SSL with certbot (skip for .local domains)
    if [[ "$domain" != *".local" ]] && [[ "$domain" != "localhost" ]]; then
        echo -e "${BLUE}Setting up Let's Encrypt SSL certificate with certbot...${NC}"
        
        # Ensure certbot is installed
        if ! command_exists certbot; then
            echo -e "${YELLOW}Installing certbot...${NC}"
            apt-get update
            apt-get install -y certbot python3-certbot-apache
        fi
        
        # Get the certificate
        echo -e "${GREEN}Running certbot to obtain SSL certificate for $domain${NC}"
        echo -e "${YELLOW}Note: You will need to ensure that your domain points to this server and port 80 is open${NC}"
        certbot --apache -d $domain --non-interactive --agree-tos --email admin@$domain || {
            echo -e "${YELLOW}Automatic certificate generation failed. You can run it manually later with:${NC}"
            echo -e "${GREEN}sudo certbot --apache -d $domain${NC}"
        }
    fi
    
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
        
        # Ensure domain is in hosts file
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
    
    # Creating .htpasswd file
    if [ ! -f "$auth_file" ]; then
        # Create the parent directory if it doesn't exist
        mkdir -p "$(dirname "$auth_file")"
        
        # Generate password
        echo -e "${YELLOW}Please enter a password for user '$username':${NC}"
        htpasswd -c "$auth_file" "$username"
    else
        # Add/update user in existing file
        echo -e "${YELLOW}Please enter a password for user '$username':${NC}"
        htpasswd "$auth_file" "$username"
    fi
}

# Setup n8n with Docker
setup_n8n_docker() {
    echo -e "${BLUE}Setting up n8n with Docker...${NC}"
    
    # Go to n8n directory
    cd /opt/n8n || {
        echo -e "${RED}Failed to change to /opt/n8n directory.${NC}"
        exit 1
    }
    
    # Start the n8n containers
    echo -e "${BLUE}Starting n8n containers...${NC}"
    docker-compose up -d
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to start n8n containers.${NC}"
        echo -e "${YELLOW}Checking docker-compose logs:${NC}"
        docker-compose logs
        exit 1
    fi
    
    echo -e "${GREEN}n8n container is now running.${NC}"
    
    # Create a convenience script to view logs
    cat > /opt/n8n/view-logs.sh << 'EOF'
#!/bin/bash
cd /opt/n8n && docker-compose logs -f
EOF
    chmod +x /opt/n8n/view-logs.sh
    
    echo -e "${GREEN}Created log viewer script: /opt/n8n/view-logs.sh${NC}"
    
    # Create a convenience script for managing n8n
    cat > /usr/local/bin/n8n-docker << 'EOF'
#!/bin/bash
cd /opt/n8n

case "$1" in
    start)
        echo "Starting n8n..."
        docker-compose up -d
        ;;
    stop)
        echo "Stopping n8n..."
        docker-compose down
        ;;
    restart)
        echo "Restarting n8n..."
        docker-compose restart
        ;;
    logs)
        echo "Showing n8n logs..."
        docker-compose logs -f
        ;;
    update)
        echo "Updating n8n..."
        docker-compose pull
        docker-compose down
        docker-compose up -d
        ;;
    status)
        echo "n8n container status:"
        docker-compose ps
        ;;
    exec)
        shift
        echo "Executing command in n8n container: $@"
        docker-compose exec n8n "$@"
        ;;
    *)
        echo "Usage: n8n-docker {start|stop|restart|logs|update|status|exec [command]}"
        exit 1
        ;;
esac
EOF
    chmod +x /usr/local/bin/n8n-docker
    
    echo -e "${GREEN}Created management script: n8n-docker${NC}"
    echo -e "${YELLOW}Usage: n8n-docker {start|stop|restart|logs|update|status|exec [command]}${NC}"
}

# Main function
main() {
    clear
    echo -e "${GREEN}=========================================================${NC}"
    echo -e "${GREEN}       n8n Docker Installation with Domain Support       ${NC}"
    echo -e "${GREEN}=========================================================${NC}"
    echo -e "${YELLOW}This script will install n8n using Docker and set up a${NC}"
    echo -e "${YELLOW}virtual host configuration with SSL and authentication.${NC}"
    echo
    
    # Check requirements
    check_requirements
    
    # Get domain name
    echo -e "${YELLOW}Please enter the domain name you want to use for n8n:${NC}"
    read -p "(e.g., n8n.example.com, n8n.local): " domain
    
    # Validate domain
    if [ -z "$domain" ]; then
        echo -e "${RED}Error: Domain name cannot be empty.${NC}"
        exit 1
    fi
    
    # Add domain to hosts file if it's a local domain
    if [[ "$domain" == *".local" ]] || [[ "$domain" == "localhost" ]]; then
        # Check if domain is already in hosts file
        if ! grep -q "$domain" /etc/hosts; then
            echo -e "${BLUE}Adding $domain to /etc/hosts...${NC}"
            echo "127.0.0.1 $domain" >> /etc/hosts
        fi
    fi
    
    # Get username for authentication
    echo -e "${YELLOW}Please enter a username for basic authentication:${NC}"
    read -p "(default: admin): " username
    username=${username:-admin}
    
    # Define auth file location
    auth_file="/etc/n8n/.htpasswd"
    
    # Create the password file
    create_password_file "$username" "$auth_file"
    
    # Ask user to choose between Nginx and Apache
    echo -e "${YELLOW}Which web server would you like to use?${NC}"
    echo "1) Nginx (recommended)"
    echo "2) Apache"
    read -p "Enter your choice (1 or 2): " web_server_choice
    
    # Create Docker Compose configuration
    create_docker_compose "$domain"
    
    # Configure the selected web server
    case $web_server_choice in
        1)
            create_nginx_config "$domain" "$auth_file"
            ;;
        2)
            create_apache_config "$domain" "$auth_file"
            ;;
        *)
            echo -e "${RED}Invalid choice. Using Nginx as default.${NC}"
            create_nginx_config "$domain" "$auth_file"
            ;;
    esac
    
    # Setup n8n with Docker
    setup_n8n_docker
    
    echo -e "${GREEN}=========================================================${NC}"
    echo -e "${GREEN}                 Installation Complete!                  ${NC}"
    echo -e "${GREEN}=========================================================${NC}"
    echo -e "${YELLOW}n8n is now accessible at: ${GREEN}https://$domain${NC}"
    echo -e "${YELLOW}Username: ${GREEN}$username${NC}"
    echo
    echo -e "${YELLOW}Management commands:${NC}"
    echo -e "${GREEN}n8n-docker start${NC}    - Start the n8n container"
    echo -e "${GREEN}n8n-docker stop${NC}     - Stop the n8n container"
    echo -e "${GREEN}n8n-docker restart${NC}  - Restart the n8n container"
    echo -e "${GREEN}n8n-docker logs${NC}     - View container logs"
    echo -e "${GREEN}n8n-docker update${NC}   - Update n8n to the latest version"
    echo -e "${GREEN}n8n-docker status${NC}   - Check container status"
    echo
    echo -e "${YELLOW}If you encounter any issues:${NC}"
    echo -e "1. Check n8n container logs: ${GREEN}n8n-docker logs${NC}"
    echo -e "2. Check web server logs: ${GREEN}tail -f /var/log/nginx/$domain-error.log${NC} or ${GREEN}tail -f /var/log/apache2/$domain-error.log${NC}"
    echo -e "3. Restart all services: ${GREEN}n8n-docker restart && systemctl restart nginx${NC} or ${GREEN}n8n-docker restart && systemctl restart apache2${NC}"
    echo
    echo -e "${GREEN}Thank you for using the n8n Docker installer!${NC}"
}

# Run the main function
main