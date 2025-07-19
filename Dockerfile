FROM debian:12
RUN apt update
RUN apt install redis ca-certificates curl -y
ENV PYTHONUNBUFFERED=1
RUN mkdir /code
WORKDIR /code
#RUN bash .docker/scripts/setup-sass.sh
EXPOSE 8080
