FROM nginx:alpine

RUN apk add --no-cache inotify-tools \
    && cp /etc/nginx/mime.types /mime.types.default

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
