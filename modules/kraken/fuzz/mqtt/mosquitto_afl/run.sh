podman run --rm -it \
    -v "../../seeds/mqtt/:/work/seeds" \
    -v "./my_output/:/work/output" \
    aflpp-mosquitto:latest
