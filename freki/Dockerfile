FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y python3 python3-dev python3-pip automake \
                                         libfuzzy-dev python3-mysqldb libssl-dev libffi-dev \
                                         python3-setuptools mariadb-client foremost \
            && rm -rf /var/lib/apt/lists/*

WORKDIR /freki
COPY . /freki

RUN echo "#!/bin/sh\n" \
         "while ! mysqladmin ping -h\"db\" -P\"3306\" --silent; do\n" \
         "    echo \"Waiting for MySQL to be up...\"\n" \
         "    sleep 1\n" \
         "done\n" \
         "sleep 3\n" \
         "echo \"Starting Freki...\"\n" \
         "exit 0\n" > /freki/wait_for_mysql.sh

RUN chmod +x /freki/wait_for_mysql.sh

RUN pip3 install -r /freki/requirements.txt