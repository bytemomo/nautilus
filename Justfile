set shell := ["bash", "-c"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

CONFIG := "Release"
GEN := "Ninja"
TOOLCHAIN_WIN := "D:\\.scoop\\apps\\vcpkg\\current\\scripts\\buildsystems\\vcpkg.cmake"

FUZZ_DIR := "modules/kraken/fuzz"
ABI_DIR := "modules/kraken/abi"

_default:
    @just --list

# ==============================================================================
# == Main Applications
# ==============================================================================

[doc('Builds the complete Kraken application.
This is a convenience recipe that first builds the main Go binary and then
compiles all the necessary ABI modules.')]
kraken-build-all: kraken-build abi-clean-all abi-build-all

[doc('Builds the main Kraken Go application binary.
It first generates the required protobuf files before compiling the application.')]
kraken-build:
    cd kraken/pkg/modulepb && go generate
    cd kraken && go build -o ../dist/kraken main.go

[doc('Runs the tests for the nautilus suite.')]
test:
    go test ./kraken/... -v -timeout 10s
    go test ./trident/... -v -timeout 10s

    @read -p "Continue? Sudo required (y/N) " RESP; \
        if [ "$RESP" != "y" ] && [ "$RESP" != "Y" ]; then \
            exit 0; \
        fi

    @go test -c ./trident/conduit/datalink/... -o ./dist/sudo_tests/
    @go test -c ./trident/conduit/network/... -o ./dist/sudo_tests/

    @for test in ./dist/sudo_tests/*.test; do \
        sudo $test -test.v -test.timeout 10s; \
    done




# ==============================================================================
# == Scenarios
# ==============================================================================

[doc("Macro to run scenario a in a simple way, need `tmux`. sec_level= ^(hardened|insecure|partial)$ ")]
scenario_a_run sec_level:
    #!/bin/bash
    set -euo pipefail
    SCENARIO_NAME="scenario-a"
    SESSION_NAME="scenario_lab"

    if [[ ! "{{sec_level}}" =~ ^(hardened|insecure|partial)$ ]]; then
        echo "Error: Invalid security level '{{sec_level}}'"
        exit 1
    fi
    [[ -d "resources/$SCENARIO_NAME" ]] || { echo "Directory not found"; exit 1; }
    [[ `command -v tmux` ]] || { echo "This recipe requires the tmux command."; exit 1; }

    echo "Pre-flight: Cleaning..."
    tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
    if ! just scenario_a_clean > /dev/null 2>&1; then
        echo "Warning: scenario_a_clean failed, attempting manual cleanup..."
        podman rm -f scenario-a-broker scenario-a-certs scenario-a-plc scenario-a-rtu scenario-a-scada scenario-a-seeder scenario-a-kraken scenario-a-capture 2>/dev/null || true
    fi

    WORK_DIR="$(pwd)/resources/$SCENARIO_NAME"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$WORK_DIR/results/{{sec_level}}"

    # Create Session (Pane 0 - Left Side)
    tmux new-session -d -s "$SESSION_NAME" -c "$WORK_DIR"
    tmux rename-window -t "$SESSION_NAME:0" "Lab_Dashboard"

    # >>> PANE 0 (Left): Main ICS Environment
    tmux send-keys -t "$SESSION_NAME:0" "export SECURITY_PROFILE={{sec_level}}" C-m
    tmux send-keys -t "$SESSION_NAME:0" "echo 'Starting Main ICS ({{sec_level}})...'" C-m
    tmux send-keys -t "$SESSION_NAME:0" "podman compose up --build 2>&1 | tee results/{{sec_level}}/main_${TIMESTAMP}.log" C-m

    sleep 2

    # Split the window horizontally (-h) to create the right side
    tmux split-window -h -t "$SESSION_NAME:0" -c "$WORK_DIR"
    tmux send-keys -t "$SESSION_NAME:0.1" "export SECURITY_PROFILE={{sec_level}}" C-m
    tmux send-keys -t "$SESSION_NAME:0.1" "echo 'Starting Tools...'" C-m
    tmux send-keys -t "$SESSION_NAME:0.1" "podman compose --profile tools run --no-deps --build -it --rm kraken 2>&1 | tee results/{{sec_level}}/tools_${TIMESTAMP}.log" C-m

    # tmux split-window -v -t "$SESSION_NAME:0.1" -c "$WORK_DIR"
    # tmux send-keys -t "$SESSION_NAME:0.2" "clear; echo 'INTERACTIVE SHELL'" C-m

    tmux attach-session -t "$SESSION_NAME"

    echo "Session ended. Cleaning up..."
    pushd "$WORK_DIR" > /dev/null
    just scenario_a_clean || true
    popd > /dev/null

scenario_a_clean:
    #!/bin/bash
    set -euo pipefail
    pushd resources/scenario-a

    echo "Cleaning up all profiles..."
    for profile in insecure partial hardened; do
        SECURITY_PROFILE=$profile podman compose --profile tools --profile bridge down -v --remove-orphans || true
    done

    echo "Environment nuked:"
    podman ps -a
    popd

# ==============================================================================
# == Fuzzing
# ==============================================================================

[doc('Builds a containerized AFL++ fuzzing environment for a specific target.
The `name` parameter should correspond to a directory in `modules/kraken/fuzz`.')]
fuzz-build-afl name:
    @echo "==> Building AFL fuzzer for {{name}}"
    podman build -t aflpp-{{name}}:latest {{FUZZ_DIR}}/{{name}}/{{name}}_afl

[doc('Runs a specific AFL++ fuzzer using a pre-built container.
This will start the fuzzing process, mounting the necessary directories.')]
fuzz-run-afl name:
    #!/bin/bash
    echo "==> Running AFL fuzzer for {{name}}"
    pushd {{FUZZ_DIR}}/{{name}}/{{name}}_afl > /dev/null
    ./run.sh
    popd > /dev/null

[doc('Configures the host system for optimal fuzzing performance.
This sets the core dump pattern to `core` and changes the CPU frequency scaling
governor to `performance` (need sudo)')]
fuzz-setup:
    @echo "==> Setting up AFL++ fuzzing environment"
    echo core | sudo tee /proc/sys/kernel/core_pattern
    cd /sys/devices/system/cpu && (echo performance | sudo tee cpu*/cpufreq/scaling_governor)

# ==============================================================================
# == ABI Modules
# ==============================================================================

[doc('Builds all ABI modules (Rust/C++).')]
abi-build-all:
		@just {{ if os() == "windows" { "_abi-build-all-windows" } else { "_abi-build-all-unix" } }}

[doc('Cleans all build artifacts and then recompiles all ABI modules from scratch.
Useful for ensuring a clean and consistent build state.')]
abi-rebuild-all:
		@just {{ if os() == "windows" { "_abi-clean-all-windows && just _abi-build-all-windows" } else { "_abi-clean-all-unix && just _abi-build-all-unix" } }}

[doc('Builds a single, specific ABI module by its directory name.')]
abi-build-one name:
		@just {{ if os() == "windows" { "_abi-build-one-windows " + name } else { "_abi-build-one-unix " + name } }}

[doc('Removes all build artifacts from all ABI modules.')]
abi-clean-all:
		@just {{ if os() == "windows" { "_abi-clean-all-windows" } else { "_abi-clean-all-unix" } }}


# ==============================================================================
# == Private Recipes
# ==============================================================================

_abi-build-all-unix:
	#!/usr/bin/env bash
	set -euo pipefail
	for d in {{ABI_DIR}}/*; do
		[[ -d "$d" ]] || continue
		if [[ -f "$d/CMakeLists.txt" ]]; then
			echo "==> Configuring $d"
			cmake -S "$d" -B "$d/build" -G {{GEN}} -DCMAKE_BUILD_TYPE={{CONFIG}}
			echo "==> Building $d"
			cmake --build "$d/build" --config {{CONFIG}}
		elif [[ -f "$d/Cargo.toml" ]]; then
			echo "==> Building $d"
			(cd "$d" && cargo build --release)
		fi
	done

_abi-build-one-unix name:
	#!/usr/bin/env bash
	set -euo pipefail
	dir="{{ABI_DIR}}/{{name}}"
	if [[ -f "$dir/CMakeLists.txt" ]]; then
		echo "==> Configuring $dir"
		cmake -S "$dir" -B "$dir/build" -G {{GEN}} -DCMAKE_BUILD_TYPE={{CONFIG}}
		echo "==> Building $dir"
		cmake --build "$dir/build" --config {{CONFIG}}
	elif [[ -f "$dir/Cargo.toml" ]]; then
		echo "==> Building $dir"
		(cd "$dir" && cargo build --release)
	else
		echo "No build method found for '$dir' (cargo / cmake) !" >&2
		exit 1
	fi

_abi-clean-all-unix:
	#!/usr/bin/env bash
	set -euo pipefail
	for d in {{ABI_DIR}}/*; do
		if [[ -d "$d/build" ]]; then
			echo "==> Removing $d/build"
			rm -rf "$d/build"
		elif [[ -d "$d/target" ]]; then
			echo "==> Removing $d/target"
			rm -rf "$d/target"
		fi
	done

_abi-build-all-windows:
	#! pwsh
	$ErrorActionPreference = "Stop"
	Get-ChildItem -Directory {{ABI_DIR}} | ForEach-Object {
		$dir = $_.FullName
		if (Test-Path (Join-Path $dir 'CMakeLists.txt')) {
			Write-Host "==> Configuring $dir"
			cmake -S $dir -B (Join-Path $dir 'build') -G {{GEN}} -DCMAKE_TOOLCHAIN_FILE="{{TOOLCHAIN_WIN}}" -DCMAKE_BUILD_TYPE={{CONFIG}}
			Write-Host "==> Building $dir"
			cmake --build (Join-Path $dir 'build') --config {{CONFIG}}
		}
	}

_abi-build-one-windows name:
	#! pwsh
	$ErrorActionPreference = "Stop"
	$dir = Join-Path "{{ABI_DIR}}" "{{name}}"
	if (!(Test-Path (Join-Path $dir 'CMakeLists.txt'))) {
		Write-Error "No CMakeLists.txt in $dir"
		exit 1
	}
	Write-Host "==> Configuring $dir"
	cmake -S $dir -B (Join-Path $dir 'build') -G {{GEN}} -DCMAKE_TOOLCHAIN_FILE="{{TOOLCHAIN_WIN}}" -DCMAKE_BUILD_TYPE={{CONFIG}}
	Write-Host "==> Building $dir"
	cmake --build (Join-Path $dir 'build') --config {{CONFIG}}

_abi-clean-all-windows:
	#! pwsh
	$ErrorActionPreference = "Stop"
	Get-ChildItem -Directory {{ABI_DIR}} | ForEach-Object {
		$b = Join-Path $_.FullName 'build'
		if (Test-Path $b) {
			Write-Host "==> Removing $b"
			Remove-Item -Recurse -Force $b
		}
	}
