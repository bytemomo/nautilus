FROM aflpp:latest AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=afl-clang-lto
ENV CXX=afl-clang-lto++

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential git ca-certificates \
    autoconf automake libtool pkg-config \
    lld-18 llvm-18 llvm-18-dev clang-18 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /work

RUN git clone --depth 1 https://gitlab.com/etherlab.org/ethercat

COPY harness.cc /work/ethercat/
WORKDIR /work/ethercat

RUN ./bootstrap && \
    ./configure \
    --enable-static \
    --disable-shared \
    --disable-kernel \
    --disable-tool \
    --disable-8139too \
    --prefix=/usr/local && \
    make -j$(nproc)

RUN ${CXX} -O2 -g -fno-omit-frame-pointer \
    -fsanitize=address,undefined \
    -I. \
    -Ilib \
    -Iinclude \
    harness.cc \
    -o fuzz_ethercat \
    ./lib/.libs/libethercat.a

FROM aflpp:latest

WORKDIR /work
RUN mkdir -p seeds output

RUN echo -n -e "\x00\x00\x00\x00\xBE\xBA\xFE\xCA\xEF\xBE\xAD\xDE\x00\x10\x01\x55" > seeds/seed1

COPY --from=builder /work/ethercat/fuzz_ethercat .

CMD ["afl-fuzz", "-i", "seeds", "-o", "output", "--", "./fuzz_ethercat"]
