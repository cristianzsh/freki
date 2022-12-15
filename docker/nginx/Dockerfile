FROM nginx:1.23.3-alpine

RUN rm /etc/nginx/nginx.conf
COPY nginx.conf /etc/nginx/

RUN rm /etc/nginx/conf.d/default.conf
COPY freki.conf /etc/nginx/conf.d/
