FROM nginx:1.27-alpine

# Static dashboard + reverse proxy config
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html /usr/share/nginx/html

# Vendored Chart.js (no external CDN at runtime — works offline / air-gapped)
# Downloaded at build time into the image.
RUN apk add --no-cache curl \
    && curl -fsSL https://cdn.jsdelivr.net/npm/chart.js@4.4.6/dist/chart.umd.min.js \
        -o /usr/share/nginx/html/js/chart.min.js \
    && apk del curl

EXPOSE 80
