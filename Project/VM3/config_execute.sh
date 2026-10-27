#!/bin/sh

pip install -r ../requirements.txt

## These commands are not permanent so they will be lost after reboot. To make them permanent, you can add them to /etc/rc.local or create a systemd service.
## So when booting the system these commands should be executed.
sudo sysctl net.ipv4.ip_forward=1 

echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf

sudo cp interfaces /etc/network/interfaces

sudo apt update

sudo apt install ufw

sudo ufw enable

sudo ufw default deny forward

sudo ufw allow from any to 192.168.2.0 port 443

sudo ufw allow from any to 192.168.1.254 port 443

sudo ufw route allow from any to 192.168.1.254 port 443


sudo ufw allow from 192.168.1.254 to 192.168.0.100 port 22

sudo ufw route allow from 192.168.1.254 to 192.168.0.100 port 22
