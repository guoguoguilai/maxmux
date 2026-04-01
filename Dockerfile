FROM golang:alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o maxmux .

FROM alpine
COPY --from=build /app/maxmux /usr/local/bin/maxmux
RUN mkdir -p /data
VOLUME ["/data"]
ENTRYPOINT ["maxmux"]
