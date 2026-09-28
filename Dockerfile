# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY server/ ./server/
WORKDIR /src/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mythicd ./cmd/mythicd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mythicd /mythicd
EXPOSE 8080
ENTRYPOINT ["/mythicd"]
