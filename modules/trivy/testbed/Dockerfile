# Banc d'essai Scanoria : Dockerfile volontairement fautif (image par étiquette
# « latest », exécution en root, ADD d'une URL). Ne jamais construire.
FROM alpine:latest
ADD https://exemple.test/outil.tar.gz /opt/
RUN apk add curl
CMD ["sh"]
