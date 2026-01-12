FROM aflpp:latest AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=afl-clang-fast
ENV CXX=afl-clang-fast++

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake git ninja-build pkg-config && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get install -y clang-18 lld-18 llvm-18 llvm-18-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /work

RUN git clone --depth 1 https://github.com/wolfSSL/wolfMQTT

COPY harness.c /work/wolfMQTT

RUN cd wolfMQTT && \
    cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DWOLFMQTT_EXAMPLES=no \
    -DWOLFMQTT_TLS=no \
    -DWOLFMQTT_V5=yes \
    -DENABLE_WEBSOCKET=OFF \
    -DBUILD_SHARED_LIBS=OFF && \
    cmake --build build

RUN ${CC} -I/work/wolfMQTT -I/work/wolfMQTT/wolfmqtt -I/work/wolfMQTT/src \
    -DWOLFMQTT_V5 \
    /work/wolfMQTT/harness.c \
    /work/wolfMQTT/build/libwolfmqtt.a \
    -o /work/fuzz_wolfmqtt \
    -Wl,--no-as-needed -ldl -lpthread -lm

FROM aflpp:latest

WORKDIR /work

RUN mkdir -p seeds output

COPY --from=builder /work/fuzz_wolfmqtt .

CMD ["afl-fuzz", "-i", "/work/seeds", "-o", "/work/output", "--", "./fuzz_wolfmqtt"]
