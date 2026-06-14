all: random shop simple_shell ret2flag
random: random.cpp
	g++ -o random random.cpp -pthread
shop: shop.py
	cp shop.py shop
	chmod +x shop
simple_shell: simple_shell.py
	cp simple_shell.py simple_shell
	chmod +x simple_shell.py
ret2flag: ret2flag.py
	cp ret2flag.py ret2flag
	chmod +x ret2flag
clean:
	rm -f random shop simple_shell ret2flag