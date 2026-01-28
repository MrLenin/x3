FROM debian:12

ENV GID=1234
ENV UID=1234

RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update 
RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update && apt-get -y install build-essential libcurl4-openssl-dev libjansson-dev libssl-dev flex byacc gawk git vim procps net-tools libtre5 libtre-dev liblmdb-dev gdb valgrind linux-perf autoconf automake libtool

# Build and install libkc (shared Keycloak/HTTP library)
COPY --from=libkc . /tmp/libkc
WORKDIR /tmp/libkc
RUN autoreconf -fi && ./configure --prefix=/usr && make && make install && ldconfig
WORKDIR /

RUN mkdir -p /x3
RUN mkdir -p /x3/x3src
COPY . /x3/x3src

RUN groupadd -g ${GID} x3
RUN useradd -u ${UID} -g ${GID} x3
# Create data directory for LMDB and logs (volume mount point)
RUN mkdir -p /x3/data/lmdb
RUN chown -R x3:x3 /x3

USER x3

WORKDIR  /x3/x3src

# configure script already regenerated with LMDB support - no autogen.sh needed
# Enable SSL for encrypted uplink connections to IRCd
# Disable glibc C23 features to avoid __isoc23_strtol linker errors on Debian 12
ENV CFLAGS="-D__USE_ISOC23=0 -g -O2 -fno-omit-frame-pointer"
ENV CPPFLAGS="-D__USE_ISOC23=0"
RUN ./configure --prefix=/x3 --enable-modules=snoop,memoserv,helpserv,histserv --with-keycloak --with-lmdb --with-ssl CFLAGS="-D__USE_ISOC23=0 -g -O2 -fno-omit-frame-pointer" CPPFLAGS="-D__USE_ISOC23=0"

RUN make
RUN make install
WORKDIR /x3

USER root
#Clean up build
#RUN apt-get remove -y build-essential && apt-get autoremove -y
#RUN apt-get clean

# Dummy sendmail - tests scrape cookies from logs, no actual email needed
RUN printf '#!/bin/sh\ncat > /dev/null\nexit 0\n' > /usr/sbin/sendmail && chmod +x /usr/sbin/sendmail

COPY docker/x3.conf-dist /x3/x3.conf-dist
COPY docker/dockerentrypoint.sh /dockerentrypoint.sh

USER x3

# Run entrypoint (volume permissions fixed by init container in docker-compose)
ENTRYPOINT ["/dockerentrypoint.sh"]

# Run X3 in foreground with debug logging
CMD ["/x3/x3", "-f", "-d"]

