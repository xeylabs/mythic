.PHONY: build test lint run docker sdk

build:
	cd server && go build -trimpath ./...

test:
	cd server && go test ./... -race -count=1
	cd sdk/js && bun install --frozen-lockfile && bun run typecheck && bun test
	cd sdk/python && PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install -q -e . pytest && python3 -m pytest tests/ -q

lint:
	cd server && test -z "$$(gofmt -l .)" && go vet ./...

run:
	cd server && go run ./cmd/mythicd

docker:
	docker build -t xeylabs/mythic .

sdk:
	cd sdk/js && bun run build
