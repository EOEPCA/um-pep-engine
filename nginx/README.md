# Nginx

```shell
docker build -t nginx .
docker run -v letsencrypt:/etc/letsencrypt --name nginx -ti -p 8080:80 nginx sh
certbot certonly --nginx -d oauth2.proxy.develop.eoepca.org
```
