FROM golang:1.26-alpine AS builder

RUN apk update && apk upgrade --no-cache

WORKDIR /usr/src/app

COPY . .
RUN go mod download && go mod verify

RUN GOEXPERIMENT=jsonv2 CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-s -w" -installsuffix cgo -o /usr/src/bin/app

FROM scratch

COPY --from=builder /usr/src/bin/app .
USER 1000

ENTRYPOINT ["./app"]
