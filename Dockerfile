# build oauth2-proxy binary
FROM golang:alpine AS oauth2-proxy
RUN apk --no-cache add curl
RUN curl --output-dir github.com/oauth2-proxy/oauth2-proxy/v7.4.0/ \
     https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v7.4.0/oauth2-proxy-v7.4.0.linux-amd64.tar.gz
RUN go install github.com/oauth2-proxy/oauth2-proxy/v7@latest

# run auth-proxy-server script to configure Keycloak
FROM python:alpine as auth-proxy-server
WORKDIR /app
COPY auth_proxy_server/ auth_proxy_server/
COPY utils/ auth_proxy_server/src/utils/
RUN pip install -r auth_proxy_server/requirements.txt
RUN python auth_proxy_server/src/main.py

# build final image to run oauth2-proxy
FROM alpine
COPY --from=oauth2-proxy /go/bin/oauth2-proxy oauth2-proxy
COPY --from=auth-proxy-server /app/auth_proxy_server/conf/keycloak.cfg .
EXPOSE 4180
ENTRYPOINT ["./oauth2-proxy", "--config=keycloak.cfg"]
