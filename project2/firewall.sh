sudo iptables -F
sudo iptables -t nat -F


sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t raw -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -p icmp --icmp-type redirect -j DROP

