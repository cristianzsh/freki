FROM alpine:3.17.0

RUN apk add --no-cache mariadb mariadb-client mariadb-server-utils pwgen

ADD ./startup.sh /scripts/startup.sh
RUN chmod -R 755 /scripts

EXPOSE 3306

VOLUME ["/var/lib/mysql"]

ENTRYPOINT ["/scripts/startup.sh"]
