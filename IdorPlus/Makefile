.PHONY: build clean install test docker run

APP_NAME=idorplus
VERSION=2.0.0

build:
	go build -o bin/$(APP_NAME) -ldflags="-s -w -X main.version=$(VERSION)" main.go

install:
	go install ./cmd/idorplus

test:
	go test ./... -v

clean:
	rm -rf bin/

docker:
	docker build -t $(APP_NAME):$(VERSION) .

run:
	go run cmd/idorplus/main.go
