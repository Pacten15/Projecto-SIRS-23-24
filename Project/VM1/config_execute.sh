#!/bin/sh

sudo cp interfaces /etc/network/interfaces

sudo systemctl enable postgresql

sudo systemctl start postgresql

sudo cp postgresql.conf /etc/postgresql/16/main/postgresql.conf

echo "host    all             all             192.168.0.10/24         scram-sha-256" | sudo tee -a /etc/postgresql/16/main/pg_hba.conf

sudo -u postgres psql -c "CREATE USER sirs_dbadmin WITH PASSWORD 'sirs_dbpassword';"

sudo -u postgres psql -c "CREATE DATABASE sirs_bombappetit WITH OWNER sirs_dbadmin ENCODING='UTF8' TEMPLATE=template0;"

sudo systemctl enable ssh

sudo apt update

