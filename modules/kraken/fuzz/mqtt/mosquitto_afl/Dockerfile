FROM aflpp:latest AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=afl-clang-lto
ENV CXX=afl-clang-lto++

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential cmake git libssl-dev pkg-config ninja-build ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get install -y lld-18 llvm-18 llvm-18-dev clang-18 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# --- Mosquitto source --------------------------------------------------------

RUN git clone --depth 1 https://github.com/eclipse-mosquitto/mosquitto
COPY harness.cc /work/mosquitto/

# --- AFL++ / fuzzing build of libmosquitto + fuzzer -------------------------

RUN cd mosquitto && \
    mkdir -p build && cd build && \
    cmake -G "Ninja" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=${CC} \
    -DCMAKE_CXX_COMPILER=${CXX} \
    -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address,undefined" \
    -DCMAKE_CXX_FLAGS="-O1 -g -fsanitize=address,undefined" \
    -DWITH_STATIC_LIBRARIES=ON \
    -DWITH_SHARED_LIBRARIES=OFF \
    -DWITH_BROKER=ON \
    -DWITH_CLIENTS=OFF \
    -DWITH_PLUGINS=OFF \
    -DWITH_TLS=ON \
    -DDOCUMENTATION=OFF .. && \
    ninja libmosquitto_static

RUN cd /work/mosquitto && \
    ${CXX} \
    -O1 -g \
    -fsanitize=fuzzer,address,undefined \
    -I/work/mosquitto/build \
    -I/work/mosquitto \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    /work/mosquitto/harness.cc \
    /work/mosquitto/build/lib/libmosquitto_static.a \
    -lssl -lcrypto -lpthread \
    -o /work/fuzz_mosquitto

# ============================================================================ #
#                  TRIAGE BUILD (non-AFL, pure ASan/UBSan)                     #
# ============================================================================ #

COPY repro.c /work/mosquitto/

RUN cd mosquitto && \
    mkdir -p build_asan && cd build_asan && \
    CC=clang-18 CXX=clang++-18 \
    cmake -G "Ninja" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address,undefined" \
    -DCMAKE_CXX_FLAGS="-O1 -g -fsanitize=address,undefined" \
    -DWITH_STATIC_LIBRARIES=ON \
    -DWITH_SHARED_LIBRARIES=OFF \
    -DWITH_BROKER=ON \
    -DWITH_CLIENTS=OFF \
    -DWITH_PLUGINS=OFF \
    -DWITH_TLS=ON \
    -DDOCUMENTATION=OFF .. && \
    ninja libmosquitto_static

RUN cd /work/mosquitto && \
    clang++-18 \
    -O1 -g -fsanitize=address,undefined \
    -I/work/mosquitto/build_asan \
    -I/work/mosquitto \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    /work/mosquitto/repro.c \
    /work/mosquitto/harness.cc \
    /work/mosquitto/build_asan/lib/libmosquitto_static.a \
    -lssl -lcrypto -lpthread \
    -o /work/repro_mosq


# --- Runtime image -----------------------------------------------------------

FROM aflpp:latest

WORKDIR /work

RUN mkdir seeds output

COPY --from=builder /work/fuzz_mosquitto .
COPY --from=builder /work/repro_mosq .

CMD ["afl-fuzz", "-i", "/work/seeds", "-o", "/work/output", "--", "./fuzz_mosquitto"]
