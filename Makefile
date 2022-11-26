build:
	@go build -o bin/gofin

run: build
	@./bin/gofin

test:
	@go test -v ./..