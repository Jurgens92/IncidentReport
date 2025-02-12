#!/bin/bash

# Change to application directory
cd /var/www/incidentreport

# Pull latest changes as www-data user
sudo -u www-data git pull

# Reset database if needed (commented out by default)
# sudo -u www-data /var/www/incidentreport/venv/bin/python3 reset_db.py

# Restart services
sudo supervisorctl restart incidentreport
sudo systemctl restart nginx

echo "Update complete! Application has been updated and restarted."