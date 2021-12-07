ARG BASE_IMAGE=alpine:latest

FROM ${BASE_IMAGE}
LABEL maintainer="Rey"

RUN         apk add --no-cache --upgrade && \            
            apk add --no-cache postfix && \
            apk add --no-cache py3-google-auth-httplib2 && \
            apk add --no-cache ca-certificates tzdata supervisor rsyslog musl musl-utils bash libcurl jsoncpp lmdb

# ============================ BUILD SASL XOAUTH2 ============================

ARG SASL_XOAUTH2_REPO_URL=https://github.com/tarickb/sasl-xoauth2.git
ARG SASL_XOAUTH2_GIT_REF=release-0.10

RUN        true && \
           if [ -f /etc/alpine-release ]; then \
             apk add --no-cache --upgrade --virtual .build-deps git cmake clang make gcc g++ libc-dev pkgconfig curl-dev jsoncpp-dev cyrus-sasl-dev; \
           else \
             export DEBIAN_FRONTEND=noninteractive && \
             echo "America/Chicago" > /etc/timezone && \
             apt-get update -y -qq && \
             apt-get install -y --no-install-recommends git build-essential cmake pkg-config libcurl4-openssl-dev libssl-dev libjsoncpp-dev libsasl2-dev; \
           fi && \
           git clone --depth 1 --branch ${SASL_XOAUTH2_GIT_REF} ${SASL_XOAUTH2_REPO_URL} /sasl-xoauth2 && \
           cd /sasl-xoauth2 && \
           mkdir build && \
           cd build && \
           cmake -DCMAKE_INSTALL_PREFIX=/ .. && \
           make && \
           make install && \
           if [ -f /etc/alpine-release ]; then \
             apk del .build-deps; \
           else \
            apt-get remove --purge -y git build-essential cmake pkg-config libcurl4-openssl-dev libssl-dev libjsoncpp-dev libsasl2-dev; \
            apt-get autoremove --yes; apt-get clean autoclean; \
            rm -rf /var/lib/apt/lists/*; \
           fi && \
           cd / && rm -rf /sasl-xoauth2


# Set up configuration
COPY       /configs/supervisord.conf     /etc/supervisord.conf
COPY       /configs/rsyslog*.conf        /etc/
COPY       /configs/smtp_header_checks   /etc/postfix/smtp_header_checks
COPY       /scripts/*.sh                 /

# Set up volumes
VOLUME     [ "/var/spool/postfix", "/etc/postfix", "/etc/opendkim/keys" ]

# Run supervisord
USER       root
WORKDIR    /tmp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD printf "EHLO healthcheck\n" | nc 127.0.0.1 587 | grep -qE "^220.*ESMTP Postfix"

EXPOSE     587
CMD        [ "/bin/sh", "-c", "/run.sh" ]
