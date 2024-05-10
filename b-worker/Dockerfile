# syntax=docker/dockerfile:1

FROM python:alpine

RUN apk -U upgrade
RUN apk add --no-cache \
	dumb-init \
        xvfb \
        chromium \
        chromium-chromedriver \
        tor \
	rust \
	cargo

RUN mkdir /harvester
WORKDIR /harvester
COPY container .
RUN chmod +xxx harvester.py
RUN mkdir log rep

RUN pip install --upgrade pip
RUN pip install -r dependencies --no-cache-dir

RUN apk del --no-cache \
	cargo \
	rust

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
