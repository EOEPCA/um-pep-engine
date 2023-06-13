FROM nginx:alpine
RUN apk add certbot certbot-nginx
RUN mkdir /etc/letsencrypt
COPY default.conf /etc/nginx/conf.d/default.conf
# schedule a cronjob to renew certs on first day of each month at 12 pm
RUN echo "0 12 1 * * /usr/bin/certbot renew --quiet"; >> /var/spool/cron/crontabs/root
