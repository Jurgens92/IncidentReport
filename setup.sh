#!/bin/bash

# Update system and install required packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv nginx supervisor git iptables-persistent

# Create application directory
sudo mkdir -p /var/www/incidentreport
cd /var/www/incidentreport

# Clone the repository
sudo git clone https://github.com/Jurgens92/IncidentReport .

# Create virtual environment with correct permissions
sudo python3 -m venv venv
sudo chown -R www-data:www-data /var/www/incidentreport

# Install Python dependencies as www-data user
sudo -u www-data /var/www/incidentreport/venv/bin/pip3 install flask flask-sqlalchemy flask-login werkzeug email-validator gunicorn

# Create supervisor configuration
sudo tee /etc/supervisor/conf.d/incidentreport.conf << EOF
[program:incidentreport]
directory=/var/www/incidentreport
command=/var/www/incidentreport/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 run:app
user=www-data
autostart=true
autorestart=true
stderr_logfile=/var/log/incidentreport/incidentreport.err.log
stdout_logfile=/var/log/incidentreport/incidentreport.out.log
EOF

# Create log directory with correct permissions
sudo mkdir -p /var/log/incidentreport
sudo chown -R www-data:www-data /var/log/incidentreport

# Create Nginx configuration
sudo tee /etc/nginx/sites-available/incidentreport << EOF
server {
    listen 80;
    server_name _;  # Accept all hostnames

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

# Enable the Nginx site
sudo ln -s /etc/nginx/sites-available/incidentreport /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Set proper permissions
sudo chown -R www-data:www-data /var/www/incidentreport
sudo chmod -R 755 /var/www/incidentreport

# Configure iptables
sudo iptables -I INPUT 5 -p tcp --dport 80 -j ACCEPT
sudo mkdir -p /etc/iptables
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Initialize the database as www-data user
cd /var/www/incidentreport
sudo -u www-data /var/www/incidentreport/venv/bin/python3 reset_db.py

# Start and enable supervisor
sudo systemctl enable supervisor
sudo systemctl start supervisor

# Restart services
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl restart incidentreport
sudo systemctl restart nginx

echo "Setup complete! Access your application through your server IP."