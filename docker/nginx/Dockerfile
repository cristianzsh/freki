FROM nginx:1.19.6-alpine

RUN rm /etc/nginx/nginx.conf
COPY nginx.conf /etc/nginx/

RUN rm /etc/nginx/conf.d/default.conf
COPY freki.conf /etc/nginx/conf.d/