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

RUN git clone --depth 1 https://github.com/nanomq/nanomq.git
RUN cd nanomq/ && git checkout tags/0.24.5
RUN cd nanomq/ && git submodule update --init nng

COPY harness.c /work/nanomq/

RUN cd nanomq && \
    mkdir build && cd build && \
    cmake -G "Ninja" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_STATIC_LIB=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_CLIENT=OFF \
    -DNNG_ENABLE_SQLITE=OFF \
    -DNNG_ENABLE_TLS=OFF .. && \
    ninja


RUN ${CC} -I/work/nanomq/include -I/work/nanomq/nng/include \
    /work/nanomq/harness.c -o /work/fuzz_nanomq \
    /work/nanomq/build/nng/libnng.a /work/nanomq/build/nanomq/libnanomq.a \
    -Wl,--no-as-needed -ldl -lpthread

FROM aflpp:latest

WORKDIR /work

RUN mkdir seeds output

COPY --from=builder /work/fuzz_nanomq .

RUN echo "seed" > seeds/seed.txt

CMD ["afl-fuzz", "-i", "seeds", "-o", "output", "--", "./fuzz_nanomq", "@@"]
