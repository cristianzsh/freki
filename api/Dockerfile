FROM ubuntu:20.04

RUN apt update && apt install -y python3 python3-dev python3-pip \
			automake libfuzzy-dev

WORKDIR /app
COPY . /app

RUN pip3 install -r /app/requirements.txt

EXPOSE 5000
CMD ["uwsgi", "--ini", "/app/wsgi.ini"]
