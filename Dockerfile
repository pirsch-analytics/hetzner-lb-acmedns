FROM golang AS build
RUN apt-get update && \
    apt-get upgrade -y
WORKDIR /go/src/hetzner-lb-acmedns
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-s -w" /go/src/hetzner-lb-acmedns/main.go && \
	mkdir -p /app/data && \
	mv /go/src/hetzner-lb-acmedns/main /app/server

FROM alpine
RUN apk update && \
    apk upgrade && \
    apk add --no-cache && \
    apk add ca-certificates && \
    rm -rf /var/cache/apk/*
COPY --from=build /app /app
WORKDIR /app

ENV HLBA_LOG_LEVEL=info
ENV HLBA_CA_URL=https://acme-staging-v02.api.letsencrypt.org/directory

VOLUME ["/app/data"]
ENTRYPOINT ["/app/server"]
