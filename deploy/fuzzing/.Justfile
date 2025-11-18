project_dir := source_dir()

default:
    @just --list

build_afl name:
    podman build -t {{project_dir}}/aflpp/aflpp-{{name}}:latest ./{{project_dir}}/aflpp/{{name}}

run_afl name:
    podman run --rm -it \
        -v "{{project_dir}}/aflpp/{{name}}/my_seeds:/work/seeds" \
        -v "{{project_dir}}/aflpp/{{name}}/my_output:/work/output" \
        aflpp-{{name}}:latest


setup_aflpp_fuzzing:
    echo core | sudo tee /proc/sys/kernel/core_pattern
    cd /sys/devices/system/cpu && (echo performance | sudo tee cpu*/cpufreq/scaling_governor)

build_afl_base_image:
    podman build -t aflpp:latest -f Dockerfile.aflpp
