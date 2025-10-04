CONFIG := "Release"
GEN := "Ninja"
TOOLCHAIN_WIN := r#"D:\.scoop\apps\vcpkg\current\scripts\buildsystems\vcpkg.cmake"#

build-all:
	if [[ "{{os()}}" == "windows" ]]; then
		just build-all-windows
	else
		just build-all-unix
	fi


rebuild-all:
	if [[ "{{os()}}" == "windows" ]]; then
		just clean-all-windows
		just build-all-windows
	else
		just clean-all-unix
		just build-all-unix
	fi


build-one name:
	if [[ "{{os()}}" == "windows" ]]; then
		just build-one-windows {{name}}
	else
		just build-one-unix {{name}}
	fi


clean-all:
	if [[ "{{os()}}" == "windows" ]]; then
		just clean-all-windows
	else
		just clean-all-unix
	fi


# -----------------------------
# Unix implementations
# -----------------------------
build-all-unix:
	set -euo pipefail
	for d in plugins/*; do
		if [ -d "$d" ] && [ -f "$d/CMakeLists.txt" ]; then
			echo "==> Configuring $d"
			cmake -S "$d" -B "$d/build" -G {{GEN}} -DCMAKE_BUILD_TYPE={{CONFIG}}
			echo "==> Building $d"
			cmake --build "$d/build" --config {{CONFIG}}
		fi
	done


build-one-unix name:
	set -euo pipefail
	d="plugins/{{name}}"
	if [ ! -f "$d/CMakeLists.txt" ]; then
		echo "No CMakeLists.txt in $d" >&2
		exit 1
	fi
	cmake -S "$d" -B "$d/build" -G {{GEN}} -DCMAKE_BUILD_TYPE={{CONFIG}}
	cmake --build "$d/build" --config {{CONFIG}}


clean-all-unix:
	set -euo pipefail
	for d in plugins/*; do
		if [ -d "$d/build" ]; then
			echo "==> Removing $d/build"
			rm -rf "$d/build"
		fi
	done

# -----------------------------
# Windows implementations (PowerShell)
# -----------------------------
build-all-windows:
	$ErrorActionPreference = "Stop"
	Get-ChildItem -Directory .\plugins | ForEach-Object {
		$dir = $_.FullName
		if (Test-Path (Join-Path $dir 'CMakeLists.txt')) {
			Write-Host "==> Configuring $dir"
			cmake -S $dir -B (Join-Path $dir 'build') -G {{GEN}} -DCMAKE_TOOLCHAIN_FILE="{{TOOLCHAIN_WIN}}" -DCMAKE_BUILD_TYPE={{CONFIG}}
			Write-Host "==> Building $dir"
			cmake --build (Join-Path $dir 'build') --config {{CONFIG}}
		}
	}


build-one-windows name:
	$ErrorActionPreference = "Stop"
	$dir = Join-Path "plugins" "{{name}}"
	if (!(Test-Path (Join-Path $dir 'CMakeLists.txt'))) {
		Write-Error "No CMakeLists.txt in $dir"
		exit 1
	}
	cmake -S $dir -B (Join-Path $dir 'build') -G {{GEN}} -DCMAKE_TOOLCHAIN_FILE="{{TOOLCHAIN_WIN}}" -DCMAKE_BUILD_TYPE={{CONFIG}}
	cmake --build (Join-Path $dir 'build') --config {{CONFIG}}


clean-all-windows:
	$ErrorActionPreference = "Stop"
	Get-ChildItem -Directory .\plugins | ForEach-Object {
		$b = Join-Path $_.FullName 'build'
		if (Test-Path $b) {
			Write-Host "==> Removing $b"
			Remove-Item -Recurse -Force $b
		}
	}
