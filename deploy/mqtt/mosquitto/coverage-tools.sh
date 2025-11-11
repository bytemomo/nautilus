#!/usr/bin/env bash
set -e

OUT=/mosquitto/data
cd $OUT

echo "Merging coverage data..."
llvm-profdata merge -sparse $OUT/*.profraw -o $OUT/mosquitto.profdata

echo "Generating coverage report..."
llvm-cov show /usr/local/sbin/mosquitto \
  -instr-profile=$OUT/mosquitto.profdata \
  -format=html -output-dir=$OUT/coverage-html

echo "Coverage HTML generated at $OUT/coverage-html/index.html"
