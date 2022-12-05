FROM golang:latest

LABEL maintainer="beritani"

WORKDIR /app
RUN mkdir data

COPY . .
RUN go mod download
RUN go build -ldflags="-s -w" -o app

ENTRYPOINT [ "./app" ]