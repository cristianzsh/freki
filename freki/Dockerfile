FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y python3 python3-dev python3-pip automake \
                                         libfuzzy-dev python3-mysqldb libssl-dev libffi-dev \
                                         python3-setuptools mariadb-client foremost \
            && rm -rf /var/lib/apt/lists/*

WORKDIR /freki
COPY . /freki

RUN printf "#!/bin/sh\nwhile ! mysqladmin ping -h\"db\" -P\"3306\" --silent; do\n\techo \"Waiting for MySQL to be up...\"\n\tsleep 1\ndone\nsleep 3\necho \"Starting Freki...\"\nexit 0" > /freki/wait_for_mysql.sh

RUN chmod +x /freki/wait_for_mysql.sh

RUN pip3 install -r /freki/requirements.txt