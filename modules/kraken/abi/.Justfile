set shell := ["bash", "-c"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

CONFIG := "Release"
GEN := "Ninja"
TOOLCHAIN_WIN := "D:\\.scoop\\apps\\vcpkg\\current\\scripts\\buildsystems\\vcpkg.cmake"

# ---------- Top-level Platform Dispatch (shell-agnostic) ----------
build-all:
	@just {{ if os() == "windows" { "build-all-windows" } else { "build-all-unix" } }}

rebuild-all:
	@just {{ if os() == "windows" { "clean-all-windows && just build-all-windows" } else { "clean-all-unix && just build-all-unix" } }}

build-one name:
	@just {{ if os() == "windows" { "build-one-windows " + name } else { "build-one-unix " + name } }}

clean-all:
	@just {{ if os() == "windows" { "clean-all-windows" } else { "clean-all-unix" } }}

# ---------- Unix implementations (Bash) ----------
build-all-unix:
	#!/usr/bin/env bash
	set -euo pipefail
	root="moduless"
	[[ -d "$root" ]] || root="."
	for d in "$root"/*; do
		[[ -d "$d" ]] || continue
		if [[ -f "$d/CMakeLists.txt" ]]; then
			echo "==> Configuring $d"
			cmake -S "$d" -B "$d/build" -G {{GEN}} -DCMAKE_BUILD_TYPE={{CONFIG}}
			echo "==> Building $d"
			cmake --build "$d/build" --config {{CONFIG}}
		elif [[ -f "$d/Cargo.toml" ]]; then
			echo "==> Building $d"
			pushd $d
			cargo build --release
			popd
		else
			continue
		fi
	done

build-one-unix name:
	#!/usr/bin/env bash
	set -euo pipefail
	dir="modules/{{name}}"
	[[ -d "$dir" ]] || dir="./{{name}}"

	if [[ -f "$d/CMakeLists.txt" ]]; then
		echo "==> Configuring $d"
		cmake -S "$d" -B "$d/build" -G {{GEN}} -DCMAKE_BUILD_TYPE={{CONFIG}}
		echo "==> Building $d"
		cmake --build "$d/build" --config {{CONFIG}}
	elif [[ -f "$d/Cargo.toml" ]]; then
		echo "==> Building $d"
		cargo build --release
	else
		echo "No build method found (cargo / cmake) !"
		exit 1
	fi

clean-all-unix:
	#!/usr/bin/env bash
	set -euo pipefail
	root="moduless"
	[[ -d "$root" ]] || root="."
	for d in "$root"/*; do
		if [[ -d "$d/build" ]]; then
			echo "==> Removing $d/build"
			rm -rf "$d/build"
		elif [[ -d "$d/target" ]]; then
			echo "==> Removing $d/target"
			rm -rf "$d/target"
		fi
	done

# ---------- Windows implementations (PowerShell) ----------
build-all-windows:
	#! pwsh
	$ErrorActionPreference = "Stop"
	Get-ChildItem -Directory . | ForEach-Object {
		$dir = $_.FullName
		if (Test-Path (Join-Path $dir 'CMakeLists.txt')) {
			Write-Host "==> Configuring $dir"
			cmake -S $dir -B (Join-Path $dir 'build') -G {{GEN}} -DCMAKE_TOOLCHAIN_FILE="{{TOOLCHAIN_WIN}}" -DCMAKE_BUILD_TYPE={{CONFIG}}
			Write-Host "==> Building $dir"
			cmake --build (Join-Path $dir 'build') --config {{CONFIG}}
		}
	}

build-one-windows name:
	#! pwsh
	$ErrorActionPreference = "Stop"
	$dir = Join-Path "modules" "{{name}}"
	if (!(Test-Path (Join-Path $dir 'CMakeLists.txt'))) {
		Write-Error "No CMakeLists.txt in $dir"
		exit 1
	}
	Write-Host "==> Configuring $dir"
	cmake -S $dir -B (Join-Path $dir 'build') -G {{GEN}} -DCMAKE_TOOLCHAIN_FILE="{{TOOLCHAIN_WIN}}" -DCMAKE_BUILD_TYPE={{CONFIG}}
	Write-Host "==> Building $dir"
	cmake --build (Join-Path $dir 'build') --config {{CONFIG}}

clean-all-windows:
	#! pwsh
	$ErrorActionPreference = "Stop"
	Get-ChildItem -Directory . | ForEach-Object {
		$b = Join-Path $_.FullName 'build'
		if (Test-Path $b) {
			Write-Host "==> Removing $b"
			Remove-Item -Recurse -Force $b
		}
	}
