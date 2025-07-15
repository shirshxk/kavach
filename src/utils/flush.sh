#!/bin/bash
sudo iptables -D INPUT -j NFQUEUE --queue-num 1

