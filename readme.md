# n8n-apache-installer

*[English version below](#english-version)*

## Version Française

Un script bash pour installer et configurer automatiquement l'outil d'automatisation de flux de travail n8n avec un hébergement virtuel Apache.

### Fonctionnalités

- Installation en un clic de n8n et de toutes ses dépendances
- Configuration d'hôte virtuel Apache avec domaine personnalisé
- Authentification HTTP Basic pour un accès sécurisé
- Support proxy WebSocket pour une fonctionnalité n8n complète
- Configuration et vérification automatique du service
- Capacités complètes de dépannage et d'auto-réparation
- Installation de la dernière version de n8n (`n8n@next`)
- Mode tunnel activé par défaut (`n8n start --tunnel`)
- Disponible en version standard et lite (simplifiée)

### Utilisation

1. Téléchargez le script:
   ```bash
   wget https://raw.githubusercontent.com/antoninnvh/n8ninstallVirtualHost/main/install.sh
   ```

2. Rendez-le exécutable:
   ```bash
   chmod +x install.sh
   ```

3. Exécutez-le avec sudo (choisissez une option):
   
   **Installation standard:**
   ```bash
   sudo ./install.sh
   ```
   
   **Version lite (installation simplifiée):**
   ```bash
   sudo ./install-lite.sh
   ```

4. Suivez les invites pour:
    - Entrer le nom de domaine souhaité
    - Créer un nom d'utilisateur
    - Définir un mot de passe pour accéder à n8n

### Dépannage

Si vous rencontrez l'erreur "Service Unavailable", vous pouvez exécuter à nouveau le script et sélectionner l'option 3 "Fix 'Service Unavailable'".

Alternativement, essayez ces commandes:

```bash
# Vérifier l'état du service n8n
systemctl status n8n

# Consulter les logs
journalctl -u n8n -f

# Vérifier les logs Apache
tail -f /var/log/apache2/error.log

# Redémarrer n8n et Apache
systemctl restart n8n apache2
```

#### Problèmes courants

1. **Fichier de service systemd manquant:**
   - Si vous voyez "Unit n8n.service not found", le fichier de service n'a pas été créé correctement.
   - Réexécutez l'installateur ou créez manuellement le fichier de service dans `/etc/systemd/system/n8n.service`.

2. **Erreurs de configuration Apache:**
   - Vérifiez la syntaxe Apache: `apache2ctl -t`
   - Consultez les logs d'erreur: `tail -f /var/log/apache2/error.log`
   
3. **Problèmes de connexion WebSocket:**
   - Exécutez à nouveau le script et sélectionnez l'option 2 "Repair WebSockets"
   - Vérifiez que les modules WebSocket sont activés: `apache2ctl -M | grep -E 'proxy_wstunnel|rewrite'`

4. **Conflits de port:**
   - Vérifiez si un autre processus utilise le port 5678: `netstat -tulpn | grep 5678`
   - Terminez les processus conflictuels si nécessaire: `fuser -k 5678/tcp`

---

## English Version

A bash script to automatically install and configure n8n workflow automation tool with Apache virtual hosting.

### Features

- One-click installation of n8n and all dependencies
- Apache virtual host configuration with custom domain
- HTTP Basic Authentication for secure access
- WebSocket proxy support for full n8n functionality
- Automatic service configuration and verification
- Comprehensive troubleshooting and self-healing capabilities
- Latest n8n version (`n8n@next`) installation
- Tunnel mode enabled by default (`n8n start --tunnel`)
- Available in both standard and lite (simplified) versions

### Usage

1. Download the script:
   ```bash
   wget https://raw.githubusercontent.com/antoninnvh/n8ninstallVirtualHost/main/install.sh
   ```

2. Make it executable:
   ```bash
   chmod +x install.sh
   ```

3. Run it with sudo (choose one option):
   
   **Standard installation:**
   ```bash
   sudo ./install.sh
   ```
   
   **Lite version (simplified installation):**
   ```bash
   sudo ./install-lite.sh
   ```

4. Follow the prompts to:
    - Enter your desired domain name
    - Create a username
    - Set a password for accessing n8n

### Troubleshooting

If you encounter a "Service Unavailable" error, you can run the script again and select option 3 "Fix 'Service Unavailable'".

Alternatively, try these commands:

```bash
# Check n8n service status
systemctl status n8n

# View logs
journalctl -u n8n -f

# Check Apache logs
tail -f /var/log/apache2/error.log

# Restart n8n and Apache
`systemctl restart n8n apache2`
```

#### Common Issues

1. **Missing systemd service file:**
   - If you see "Unit n8n.service not found", the service file wasn't created correctly.
   - Re-run the installer or manually create the service file in `/etc/systemd/system/n8n.service`.

2. **Apache configuration errors:**
   - Check Apache syntax: `apache2ctl -t`
   - Look for error logs: `tail -f /var/log/apache2/error.log`
   
3. **WebSocket connection issues:**
   - Run the script again and select option 2 "Repair WebSockets"
   - Check WebSocket modules are enabled: `apache2ctl -M | grep -E 'proxy_wstunnel|rewrite'`

4. **Port conflicts:**
   - Check if another process is using port 5678: `netstat -tulpn | grep 5678`
   - Kill conflicting processes if needed: `fuser -k 5678/tcp`

---

## Copyright

Copyright © 2025 Antonin Nvh - [https://codequantum.io](https://codequantum.io)

This project is licensed under the MIT License - see the LICENSE file for details.