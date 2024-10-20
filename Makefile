build:
	@go build -buildvcs=false -o bin/VUP-SERVER

run: build
	@./bin/VUP-SERVER
test:
	@go test -v ./...

docker-rmi:
	@docker rmi queue:latest

docker:
	@docker run -v .:/app -p 8080:8080 queue:latest

docker-build:
	@docker build -t queue:latest .

