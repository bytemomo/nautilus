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

RUN git clone --depth 1 <PROJECT>
RUN cd <PROJECT>/ && git checkout tags/<...>
RUN cd <PROJECT>/ && git submodule update --init .

COPY harness.c /work/<PROJECT>

# INSERT BUILD STEP FOR THE PROJECT


FROM aflpp:latest

WORKDIR /work

RUN mkdir seeds output

COPY --from=builder /work/<PROJECT> .

CMD ["afl-fuzz", "-i", "/work/seeds", "-o", "/work/output", "--", "./<PROJECT>"]


# PLEASE REMOVE THIS MESSAGE
#
# This is only a skeleton for an image that builds a project
# to instrument and fuzz it via AFL++.
#
# Use it as a base to create new fuzzing target!
