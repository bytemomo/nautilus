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


kraken-build-all: kraken-build abi-clean-all abi-build-all

kraken-build:
    cd kraken/pkg/modulepb && go generate
    cd kraken && go build -o ../dist/kraken main.go

siren-build:
    rm -f ./siren/ebpf/program/xdp_proxy.bpf.o
    go generate ./siren/ebpf
    go build -o dist/siren ./siren/cmd/siren

# ==============================================================================
# == Fuzzing
# ==============================================================================

fuzz-build-afl name:
    @echo "==> Building AFL fuzzer for {{name}}"
    podman build -t aflpp-{{name}}:latest {{FUZZ_DIR}}/{{name}}/{{name}}_afl

fuzz-run-afl name:
    #!/bin/bash
    echo "==> Running AFL fuzzer for {{name}}"
    pushd {{FUZZ_DIR}}/{{name}}/{{name}}_afl > /dev/null
    ./run.sh
    popd > /dev/null

fuzz-setup:
    @echo "==> Setting up AFL++ fuzzing environment"
    echo core | sudo tee /proc/sys/kernel/core_pattern
    cd /sys/devices/system/cpu && (echo performance | sudo tee cpu*/cpufreq/scaling_governor)

# ==============================================================================
# == ABI Modules
# ==============================================================================

abi-build-all:
	@just {{ if os() == "windows" { "_abi-build-all-windows" } else { "_abi-build-all-unix" } }}

abi-rebuild-all:
	@just {{ if os() == "windows" { "_abi-clean-all-windows && just _abi-build-all-windows" } else { "_abi-clean-all-unix && just _abi-build-all-unix" } }}

abi-build-one name:
	@just {{ if os() == "windows" { "_abi-build-one-windows " + name } else { "_abi-build-one-unix " + name } }}

abi-clean-all:
	@just {{ if os() == "windows" { "_abi-clean-all-windows" } else { "_abi-clean-all-unix" } }}

# ---------- Unix implementations ----------
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

# ---------- Windows implementations ----------
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
