FROM aflpp:latest AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=afl-clang-fast
ENV CXX=afl-clang-fast++

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential cmake git libssl-dev pkg-config ninja-build ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y lld-18 llvm-18 llvm-18-dev clang-18

WORKDIR /work

RUN git clone --depth 1 https://github.com/eclipse-mosquitto/mosquitto
# RUN cd mosquitto/ && git checkout release/2.0

COPY harness.c /work/mosquitto/

RUN cd mosquitto && \
    mkdir build && cd build && \
    cmake -G "Ninja" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWITH_STATIC_LIBRARIES=ON \
    -DWITH_SHARED_LIBRARIES=OFF \
    -DWITH_BROKER=OFF \
    -DWITH_CLIENTS=OFF \
    -DWITH_PLUGINS=OFF \
    -DWITH_TLS=ON \
    -DDOCUMENTATION=OFF .. && \
    ninja libmosquitto_static

RUN ${CC} \
    -I/work/mosquitto/build \
    -I/work/mosquitto \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    /work/mosquitto/harness.c -o /work/fuzz_mosquitto \
    /work/mosquitto/build/lib/libmosquitto_static.a -lssl -lcrypto -lpthread

FROM aflpp:latest

WORKDIR /work

RUN mkdir seeds output

COPY --from=builder /work/fuzz_mosquitto .

# CMD ["afl-fuzz", "-i", "/work/seeds", "-o", "/work/output", "-x", "/work/dict/mqtt.dict", "--", "./fuzz_mosquitto", "@@"]
CMD ["afl-fuzz", "-i", "/work/seeds", "-o", "/work/output", "--", "./fuzz_mosquitto", "@@"]
