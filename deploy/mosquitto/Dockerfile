# ─────────────────────────────────────────────
# Stage 1 – Build Mosquitto with sanitizers
# ─────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    CC=clang \
    CXX=clang++

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang llvm lld cmake git pkg-config \
    libssl-dev libc-ares-dev uuid-dev libjansson-dev \
    python3 ca-certificates curl wget \
    xsltproc docbook-xsl docbook-xml

WORKDIR /build
RUN git clone --depth=1 https://github.com/eclipse/mosquitto.git

WORKDIR /build/mosquitto

ENV CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined,leak \
    -fprofile-instr-generate -fcoverage-mapping"
ENV CXXFLAGS="${CFLAGS}"

RUN mkdir build-san && cd build-san && \
    cmake .. \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DWITH_STATIC_LIBRARIES=OFF \
    -DWITH_BROKER=ON \
    -DWITH_CLIENTS=ON \
    -DWITH_WEBSOCKETS=OFF \
    -DENABLE_TESTING=OFF \
    -DWITH_DOCS=ON && \
    make -j$(nproc) && make install

# ─────────────────────────────────────────────
# Stage 2 – Runtime
# ─────────────────────────────────────────────
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libuuid1 libjansson4 libc-ares2 \
    ca-certificates llvm clang && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local /usr/local
COPY --from=builder /usr/bin/llvm-profdata /usr/bin/llvm-profdata
COPY --from=builder /usr/bin/llvm-cov /usr/bin/llvm-cov

WORKDIR /opt/mosquitto

ENV ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:abort_on_error=1:fast_unwind_on_malloc=0:allocator_may_return_null=1" \
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
    LSAN_OPTIONS="print_suppressions=0:detect_leaks=1" \
    LLVM_PROFILE_FILE="/mosquitto/data/mosq-%p.profraw"

RUN mkdir -p /mosquitto/data /mosquitto/log

COPY mosquitto.conf /opt/mosquitto/mosquitto.conf

COPY run.sh /opt/mosquitto/run.sh
RUN chmod +x /opt/mosquitto/run.sh

EXPOSE 1883/tcp
ENTRYPOINT ["/opt/mosquitto/run.sh"]
