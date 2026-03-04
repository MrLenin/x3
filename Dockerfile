FROM debian:13 AS base

ENV GID=1234
ENV UID=1234

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install \
      build-essential ccache libcurl4-openssl-dev libjansson-dev libssl-dev \
      flex byacc gawk git vim procps net-tools libtre5 libtre-dev gdb \
      valgrind linux-perf autoconf automake libtool cmake && \
    rm -rf /var/lib/apt/lists/*

# --- Build libraries in parallel using multi-stage ---

FROM base AS build-libkc
COPY --from=libkc . /tmp/libkc
WORKDIR /tmp/libkc
RUN autoreconf -fi && ./configure --prefix=/usr && make -j$(nproc) && make install

FROM base AS build-libmdbx
COPY --from=libmdbx . /tmp/libmdbx
WORKDIR /tmp/libmdbx
RUN cmake -B build -DCMAKE_INSTALL_PREFIX=/usr \
      -DCMAKE_INSTALL_LIBDIR=lib \
      -DMDBX_BUILD_TOOLS=OFF -DMDBX_BUILD_CXX=OFF && \
    cmake --build build -j$(nproc) && cmake --install build

# --- Merge libraries into base ---

FROM base AS libs
COPY --from=build-libkc /usr/lib/libkc* /usr/lib/
COPY --from=build-libkc /usr/include/kc/ /usr/include/kc/
COPY --from=build-libmdbx /usr/lib/libmdbx* /usr/lib/
COPY --from=build-libmdbx /usr/include/mdbx.h /usr/include/
RUN ldconfig

# --- Build stage ---

FROM libs AS build

RUN mkdir -p /x3/x3src
WORKDIR /x3/x3src

# Disable glibc C23 features to avoid __isoc23_strtol linker errors on Debian 12
ENV CFLAGS="-D__USE_ISOC23=0 -g -O2 -fno-omit-frame-pointer"
ENV CPPFLAGS="-D__USE_ISOC23=0"

# Copy full source tree
COPY . /x3/x3src

# Regenerate configure script from configure.in (needed for --with-mdbx support)
RUN autoconf && autoheader

# Enable SSL for encrypted uplink connections to IRCd
RUN ./configure --prefix=/x3 \
      --enable-modules=snoop,memoserv,helpserv,histserv \
      --with-keycloak --with-mdbx --with-ssl \
      CFLAGS="-D__USE_ISOC23=0 -g -O2 -fno-omit-frame-pointer" \
      CPPFLAGS="-D__USE_ISOC23=0"

# ccache via BuildKit cache mount — persists across docker builds
ENV PATH="/usr/lib/ccache:${PATH}"
# Build src/ first with parallelism, then run top-level make which copies
# the binary. Top-level Makefile has a race: `all: x3` and `x3: src/x3`
# compete with `all: all-recursive` under -j, failing because src/x3
# doesn't exist yet when the top-level rule runs.
RUN --mount=type=cache,target=/root/.ccache \
    make -C src -j$(nproc) && make
RUN make install

# --- Runtime stage ---

FROM libs AS runtime

RUN groupadd -g 1234 x3 && \
    useradd -u 1234 -g 1234 x3 && \
    mkdir -p /x3/data/lmdb && \
    chown -R x3:x3 /x3

# Dummy sendmail - tests scrape cookies from logs, no actual email needed
RUN printf '#!/bin/sh\ncat > /dev/null\nexit 0\n' > /usr/sbin/sendmail && \
    chmod +x /usr/sbin/sendmail

# Install runtime deps only (keep gdb for debugging)
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install --no-install-recommends \
      libcurl4 libjansson4 libssl3 libtre5 procps net-tools gdb && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build --chown=x3:x3 /x3/ /x3/

USER x3

COPY docker/x3.conf-dist /x3/x3.conf-dist
COPY docker/dockerentrypoint.sh /dockerentrypoint.sh

# Run entrypoint (volume permissions fixed by init container in docker-compose)
ENTRYPOINT ["/dockerentrypoint.sh"]

# Run X3 in foreground with debug logging
CMD ["/x3/x3", "-f", "-d"]
