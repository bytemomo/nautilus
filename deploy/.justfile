
CONTAINER_RUNTIME := "podman"
MOSQ_IMAGE_NAME := "mosquitto-fuzz:asan"
MOSQ_FUME_IMAGE_NAME := "mosq-fume-fuzz:latest"

project_dir := source_dir()

default:
    @just --list

build_mosquitto:
    {{CONTAINER_RUNTIME}} build -f Dockerfile -t {{MOSQ_IMAGE_NAME}} {{project_dir}}/mosquitto

run_mosquitto:
    {{CONTAINER_RUNTIME}} run --rm -it \
        -p 1883:1883 -p 9001:9001 \
        {{MOSQ_IMAGE_NAME}}

coverage_mosquitto container_id:
    {{CONTAINER_RUNTIME}} exec -it {{container_id}} /opt/mosquitto/coverage-tools.sh


build_mosq_fume:
    {{CONTAINER_RUNTIME}} build -f Dockerfile.FUME -t {{MOSQ_FUME_IMAGE_NAME}}  {{project_dir}}/mosquitto

run_mosq_fume:
    {{CONTAINER_RUNTIME}} run --rm -it \
        -v {{project_dir}}/mosquitto/fuzz-out:/mosquitto/data \
        -v {{project_dir}}/mosquitto/fuzz-out:/mosquitto/log \
        {{MOSQ_FUME_IMAGE_NAME}} \
        -t 127.0.0.1:1883 \
        --broker-command "/usr/local/sbin/mosquitto -c /opt/mosquitto/mosquitto.conf -v" \
        fuzz
