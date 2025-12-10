FROM aflpp:latest AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=afl-clang-lto
ENV CXX=afl-clang-lto++

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential git ca-certificates cmake \
    lld-18 llvm-18 llvm-18-dev clang-18 libclang-rt-18-dev  && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /work

RUN git clone --depth 1 https://github.com/OpenEtherCATsociety/SOEM
RUN cd SOEM && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && \
    make install

COPY harness.cc /work/SOEM/
RUN ${CXX} -O2 -g -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined \
    -I/work/SOEM/include \
    -I/work/SOEM/osal \
    -I/work/SOEM/osal/linux \
    -I/work/SOEM/oshw/linux \
    /work/SOEM/harness.cc \
    -o fuzz_ethercat \
    /usr/local/lib/libsoem.a \
    -pthread

FROM aflpp:latest

WORKDIR /work
RUN mkdir -p seeds output

COPY --from=builder /work/fuzz_ethercat .

CMD ["afl-fuzz", "-i", "seeds", "-o", "output", "--", "./fuzz_ethercat"]
