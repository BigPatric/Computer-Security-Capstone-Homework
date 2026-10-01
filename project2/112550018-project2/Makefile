all : icmp_redirect pharm_attack icmp_task4
icmp_redirect : icmp_redirect.cpp
	g++ -std=c++17 icmp_redirect.cpp -o icmp_redirect -pthread

pharm_attack : pharm_attack.cpp
	g++ -std=c++17 pharm_attack.cpp -o pharm_attack -pthread -lnetfilter_queue
icmp_task4 : icmp_task4.cpp
	g++ -std=c++17 icmp_task4.cpp -o icmp_task4 -pthread

clean:
	rm -f icmp_redirect pharm_attack icmp_task4
