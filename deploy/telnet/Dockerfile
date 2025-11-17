FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends openbsd-inetd telnetd && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m admin && \
    echo "admin:admin" | chpasswd && \
    mkdir -p /var/run && touch /var/run/utmp

COPY inetd.conf /etc/inetd.conf
EXPOSE 23

CMD ["/usr/sbin/inetd", "-d"]
