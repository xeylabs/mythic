.PHONY: build test lint run docker sdk

build:
	cd server && go build -trimpath ./...

test:
	cd server && go test ./... -race -count=1
	cd sdk/js && bun install --frozen-lockfile && bun run typecheck && bun test

lint:
	cd server && test -z "$$(gofmt -l .)" && go vet ./...

run:
	cd server && go run ./cmd/mythicd

docker:
	docker build -t xeylabs/mythic .

sdk:
	cd sdk/js && bun run build
