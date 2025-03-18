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

### Utilisation

1. Téléchargez le script:
   ```bash
   wget https://raw.githubusercontent.com/YOUR_USERNAME/n8n-apache-installer/main/install-n8n.sh
   ```

2. Rendez-le exécutable:
   ```bash
   chmod +x install-n8n.sh
   ```

3. Exécutez-le avec sudo:
   ```bash
   sudo ./install-n8n.sh
   ```

4. Suivez les invites pour:
    - Entrer le nom de domaine souhaité
    - Créer un nom d'utilisateur
    - Définir un mot de passe pour accéder à n8n

### Dépannage

Si vous rencontrez l'erreur "Service Unavailable", consultez la section de dépannage à la fin de l'exécution du script ou essayez les commandes suivantes:

```bash
# Vérifier l'état du service n8n
systemctl status n8n

# Consulter les logs
journalctl -u n8n -f

# Redémarrer n8n et Apache
systemctl restart n8n apache2
```

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

### Usage

1. Download the script:
   ```bash
   wget https://raw.githubusercontent.com/YOUR_USERNAME/n8n-apache-installer/main/install-n8n.sh
   ```

2. Make it executable:
   ```bash
   chmod +x install-n8n.sh
   ```

3. Run it with sudo:
   ```bash
   sudo ./install-n8n.sh
   ```

4. Follow the prompts to:
    - Enter your desired domain name
    - Create a username
    - Set a password for accessing n8n

### Troubleshooting

If you encounter a "Service Unavailable" error, refer to the troubleshooting section at the end of the script execution or try these commands:

```bash
# Check n8n service status
systemctl status n8n

# View logs
journalctl -u n8n -f

# Restart n8n and Apache
systemctl restart n8n apache2
```

---

## Copyright

Copyright © 2025 Antonin Nvh - [https://codequantum.io](https://codequantum.io)

This project is licensed under the MIT License - see the LICENSE file for details.