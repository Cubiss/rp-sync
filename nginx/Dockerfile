FROM nginx:alpine

RUN apk add --no-cache inotify-tools

COPY error.html /usr/share/nginx/html/rp-sync-error.html

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
