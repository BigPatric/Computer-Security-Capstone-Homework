all : icmp_redirect pharm_attack
icmp_redirect : icmp_redirect.cpp
	g++ -std=c++17 icmp_redirect.cpp -o icmp_redirect -pthread

pharm_attack : pharm_attack.cpp
	g++ -std=c++17 pharm_attack.cpp -o pharm_attack -pthread -lnetfilter_queue

clean:
	rm -f icmp_redirect pharm_attack
