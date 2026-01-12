#!/usr/bin/env bash
set -euo pipefail

podman run --rm -it \
    -v "../../seeds/ethercat/:/work/seeds" \
    -v "./my_output/:/work/output" \
    aflpp-soem:latest
