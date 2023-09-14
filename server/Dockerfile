from golang as builder
COPY . /proxy/server
WORKDIR /proxy/server
ENV GOPATH "/"
ENV GOPROXY "https://goproxy.cn"
RUN go build -o /build/proxy_server main.go
  
FROM ubuntu as prod
COPY --from=builder /build/proxy_server /usr/bin/proxy_server
COPY --from=builder /proxy/server/config.json /app/config.json
WORKDIR /app
ENTRYPOINT [ "proxy_server" ]
