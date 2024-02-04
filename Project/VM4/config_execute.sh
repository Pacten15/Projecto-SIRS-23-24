#!/bin/sh

sudo apt update

pip install -r ../requirements.txt

sudo cp interfaces /etc/network/interfaces