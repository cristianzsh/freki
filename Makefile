build:
	docker-compose up --build -d

stop:
	docker-compose stop

remove:
	docker-compose down

clean:
	docker-compose down
	docker system prune -fa
