all: agenthacker
.PHONY: homework docker-build docker-rmi docker-run

agenthacker: agenthacker.c
	gcc -static -no-pie -fno-stack-protector -w -g -z now -o $@ $<

docker-build: Dockerfile
	docker build -t agenthacker .

docker-rmi:
	docker rmi -f agenthacker

docker-run:
	docker run -d -p 8887:8888 agenthacker

homework: agenthacker
	cp agenthacker agenthacker.c ../homework

clean:
	rm -f agenthacker
