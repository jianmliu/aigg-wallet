# Runtime image for a prebuilt static wallet-svc binary. Build the binary first:
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
#     -o wallet-svc ./cmd/wallet-svc
# then: docker build -f cmd/wallet-svc/Dockerfile -t onchainpal-wallet-svc .
FROM alpine:3.20
RUN adduser -D -u 10001 svc
COPY wallet-svc /usr/local/bin/wallet-svc
USER svc
EXPOSE 8091
ENTRYPOINT ["/usr/local/bin/wallet-svc"]
