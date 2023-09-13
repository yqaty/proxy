from golang as builder
COPY . /cmd
WORKDIR /cmd
ENV GOPATH /
RUN go build -o /build/proxy_server main.go
  
FROM ubuntu as prod
COPY --from=builder /build/proxy_server /usr/bin/proxy_server
COPY --from=builder /cmd/config.json /app/config.json
WORKDIR /app
ENTRYPOINT [ "proxy_server" ]