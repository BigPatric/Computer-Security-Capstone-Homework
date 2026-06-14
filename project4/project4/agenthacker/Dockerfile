FROM ubuntu:latest
ARG DEBIAN_FRONTEND=noninteractive
ENV FLAG=FLAG{HEAP_BUFFER_OVERFLOW_EXP}

RUN	apt-get update
RUN	apt-get upgrade -y
RUN	apt-get install ncat tzdata -y
RUN	useradd agenthacker
RUN	mkdir agenthacker

ADD agenthacker ./agenthacker

RUN chown -R agenthacker ./agenthacker
ENV TZ="Asia/Taipei"

USER agenthacker
CMD	ncat -c ./agenthacker/agenthacker -tkl4 0.0.0.0 8888 2> /dev/null
EXPOSE	8888
