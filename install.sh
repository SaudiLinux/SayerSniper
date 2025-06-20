#!/bin/bash

# Sayer Installation Script
# Developed by Saudi Linux (SaudiLinux7@gmail.com)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
RESET='\033[0m'

# Logo
echo -e "${CYAN}"
cat << "EOF"
  _____                      
 / ____|                     
| (___   __ _ _   _  ___ _ __
 \___ \ / _` | | | |/ _ \ '__|
 ____) | (_| | |_| |  __/ |   
|_____/ \__,_|\__, |\___|_|   
               __/ |          
              |___/           
EOF
echo -e "${RESET}"

echo -e "${GREEN}[+] Sayer - Advanced Penetration Testing Tool${RESET}"
echo -e "${GREEN}[+] Developed by Saudi Linux (SaudiLinux7@gmail.com)${RESET}"
echo -e "${GREEN}[+] Starting installation...${RESET}"

# Check if running as root
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}[!] This script must be run as root${RESET}" 1>&2
   exit 1
fi

# Create necessary directories
echo -e "${BLUE}[*] Creating necessary directories...${RESET}"
mkdir -p /opt/sayer
mkdir -p /opt/sayer/modules
mkdir -p /opt/sayer/templates
mkdir -p /opt/sayer/reports
mkdir -p /opt/sayer/logs
mkdir -p /opt/sayer/config
mkdir -p /opt/sayer/assets

# Copy files to installation directory
echo -e "${BLUE}[*] Copying files to installation directory...${RESET}"
cp -R * /opt/sayer/
chmod +x /opt/sayer/sayer.py

# Create symlink
echo -e "${BLUE}[*] Creating symlink...${RESET}"
ln -sf /opt/sayer/sayer.py /usr/local/bin/sayer

# Install dependencies
echo -e "${BLUE}[*] Installing dependencies...${RESET}"

# Update package lists
apt-get update

# Install required packages
apt-get install -y python3 python3-pip nmap nikto whois dnsutils nbtscan sqlmap dirb wpscan hydra metasploit-framework

# Install Python dependencies
pip3 install -r requirements.txt

# Final steps
echo -e "${GREEN}[+] Installation completed!${RESET}"
echo -e "${GREEN}[+] You can now run Sayer using the 'sayer' command${RESET}"
echo -e "${GREEN}[+] Example: sayer -t example.com -m recon${RESET}"
echo -e "${YELLOW}[!] For more information, run: sayer --help${RESET}"