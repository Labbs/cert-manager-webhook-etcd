# Build stage
FROM alpine:3.23.0

RUN apk add --no-cache ca-certificates

COPY bin/webhook /webhook

USER 65534:65534

ENTRYPOINT ["/webhook"]
