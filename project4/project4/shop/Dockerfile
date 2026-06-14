FROM ubuntu:22.04

RUN	apt-get update
RUN	apt-get upgrade -y
RUN	apt-get install ncat tzdata -y
RUN	useradd shop
RUN	mkdir shop

ADD shop ./shop

RUN chown -R shop ./shop
ENV TZ="Asia/Taipei"

USER shop
CMD	ncat -c ./shop/shop -tkl4 0.0.0.0 8888 2> /dev/null
EXPOSE	8888
