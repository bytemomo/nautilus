
build_win:
    cmake -S . -B build -G "Ninja" -DCMAKE_TOOLCHAIN_FILE="D:\.scoop\apps\vcpkg\current\scripts\buildsystems\vcpkg.cmake"
    cmake --build build/ --config Release

build_unix:
    cmake -S . -B build -G "Ninja"
    cmake --build build/ --config Release
