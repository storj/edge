#!/bin/bash
# generate a certificate for the authservice for "localhost"
# and the domains generated by https://github.com/jderusse/docker-dns-gen
openssl req \
    -x509 \
    -newkey rsa:4096 \
    -keyout authservice-key.pem \
    -out authservice-cert.pem \
    -days 3650 \
    -nodes \
    -subj '/CN=localhost' \
    -addext "subjectAltName = DNS:localhost,DNS:authservice.docker-local.docker,DNS:authservice.docker-local.docker,DNS:traefik-authservice.docker-local.docker,DNS:docker-local-traefik-authservice-1.docker,DNS:docker-local-authservice-1.docker"
