build:
	docker-compose up --build -d

stop:
	docker-compose down

clean:
	docker-compose down
	docker system prune -fa
