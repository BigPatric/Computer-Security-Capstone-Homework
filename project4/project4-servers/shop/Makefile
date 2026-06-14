all: shop
.PHONY: homework docker-build docker-rmi docker-run

shop: shop.c
	gcc -static -pie -fpie -fstack-protector-all -w -g -z now -o $@ $<

docker-build:
	docker build -t shop .

docker-rmi:
	docker rmi -f shop

docker-run:
	docker run -d -p 8881:8888 shop

homework: shop
	cp shop shop.c ../homework

clean:
	rm -f shop
