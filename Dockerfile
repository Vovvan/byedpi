FROM --platform=$BUILDPLATFORM golang:1.24.4-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ciadpi ./cmd/ciadpi

FROM scratch
LABEL org.opencontainers.image.title="byedpi" \
      org.opencontainers.image.description="Local SOCKS5 proxy with DPI bypass methods" \
      org.opencontainers.image.source="https://github.com/Vovvan/byedpi" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/ciadpi /ciadpi
EXPOSE 1080/tcp 1080/udp
USER 65532:65532
ENTRYPOINT ["/ciadpi"]
CMD ["-i", "0.0.0.0", "-p", "1080", "--tlsrec", "1+s", "--disorder", "1+s"]
