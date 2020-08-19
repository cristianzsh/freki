FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install -y python3 python3-dev python3-pip automake \
						libfuzzy-dev python3-mysqldb libssl-dev libffi-dev \
						python3-setuptools mariadb-client

WORKDIR /freki
COPY . /freki

RUN pip3 install -r /freki/requirements.txt