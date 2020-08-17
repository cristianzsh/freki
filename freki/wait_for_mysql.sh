#!/bin/sh

while ! mysqladmin ping -h"db" -P"3306" --silent; do
    echo "Waiting for MySQL to be up..."
    sleep 1
done

sleep 3
echo "Starting Freki..."
exit 0