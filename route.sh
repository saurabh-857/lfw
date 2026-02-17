#!/bin/bash

choice="$1"

if [ -z "$choice" ]; then
	printf "1 add rules\n2 delete rules\n"
	read -p "Enter : " choice

fi

case "$choice" in
    1)
        echo "Adding NFQUEUE rules..."
        # sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
        # sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
        # sudo iptables -I INPUT -j NFQUEUE --queue-num 0
        # sudo iptables -I PREROUTING -t mangle -j NFQUEUE --queue-num 0
        # sudo iptables -I OUTPUT -t mangle -j NFQUEUE --queue-num 0
        sudo iptables -I PREROUTING -t mangle ! -i lo -j NFQUEUE --queue-num 0
        sudo iptables -I OUTPUT -t mangle ! -o lo -j NFQUEUE --queue-num 0
        ;;
    2)
        echo "Removing NFQUEUE rules..."
        # sudo iptables -D FORWARD -j NFQUEUE --queue-num 0
        # sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0
        # sudo iptables -D INPUT -j NFQUEUE --queue-num 0
        # sudo iptables -D PREROUTING -t mangle -j NFQUEUE --queue-num 0
        # sudo iptables -D OUTPUT -t mangle -j NFQUEUE --queue-num 0
        sudo iptables -D PREROUTING -t mangle ! -i lo -j NFQUEUE --queue-num 0
        sudo iptables -D OUTPUT -t mangle ! -o lo -j NFQUEUE --queue-num 0
        ;;
    *)
        echo "[!] Invalid arg"
        exit 1
        ;;
esac
