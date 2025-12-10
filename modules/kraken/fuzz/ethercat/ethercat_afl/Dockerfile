FROM aflpp:latest AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=afl-clang-lto
ENV CXX=afl-clang-lto++
ENV CXXFLAGS="-O2 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined"
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential git ca-certificates \
    autoconf automake libtool pkg-config cmake libyaml-dev libyaml-cpp-dev \
    lld-18 llvm-18 llvm-18-dev clang-18 libclang-rt-18-dev linux-headers-generic && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /work

RUN git clone --depth 1 https://gitlab.com/etherlab.org/rtipc.git && \
    cd rtipc && \
    mkdir build && \
    cd build && \
    CXXFLAGS="" cmake .. -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && \
    make install

RUN git clone --depth 1 https://gitlab.com/etherlab.org/ethercat.git
RUN cd ethercat && \
    ./bootstrap && \
    CXXFLAGS="" CC=clang-18 CXX=clang++-18 ./configure \
    --enable-static \
    --enable-fakeuserlib \
    --disable-shared \
    --disable-kernel \
    --disable-tool \
    --disable-8139too \
    --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

COPY harness.cc shim.cc shim.h /work/ethercat/
RUN ${CXX} -O2 -g -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined \
    -I/work/ethercat/ \
    -I/work/ethercat/lib \
    -I/work/ethercat/include \
    -I/work/ethercat/fake_lib \
    /work/ethercat/shim.cc \
    /work/ethercat/harness.cc \
    -o fuzz_ethercat \
    /work/ethercat/fake_lib/.libs/libfakeethercat.a \
    /usr/local/lib/librtipc.so

FROM aflpp:latest

WORKDIR /work
RUN mkdir -p seeds output

COPY --from=builder /usr/lib/x86_64-linux-gnu/libyaml* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/local/lib/ /usr/local/lib/
COPY --from=builder /work/fuzz_ethercat .

ENV LD_LIBRARY_PATH /usr/local/lib/

CMD ["afl-fuzz", "-i", "seeds", "-o", "output", "--", "./fuzz_ethercat"]
