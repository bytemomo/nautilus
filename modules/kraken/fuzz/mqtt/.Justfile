project_dir := source_dir()

default:
    @just --list

build_afl name:
    podman build -t aflpp-{{name}}:latest {{project_dir}}/{{name}}_afl

run_afl name:
    #!/bin/bash
    pushd {{name}}_afl
    ./run.sh
    popd

setup_aflpp_fuzzing:
    echo core | sudo tee /proc/sys/kernel/core_pattern
    cd /sys/devices/system/cpu && (echo performance | sudo tee cpu*/cpufreq/scaling_governor)
