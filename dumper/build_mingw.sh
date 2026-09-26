#!/bin/bash
# build_mingw.sh —— MinGW 交叉构建 (macOS/Linux 上出 Windows DLL)
#
# ⚠️ 关键: 必须加 -static。
#    Homebrew 的 mingw-w64 是 **posix thread model**, setjmp/longjmp 的
#    __imp_ 符号由 libwinpthread-1.dll 提供。若不静态链入, 产物会多出一条
#    libwinpthread-1.dll 依赖, 而游戏目录里没有它 —— Xenos 注入直接
#    0xC0000135 (STATUS_DLL_NOT_FOUND), 而且 LoadLibrary 阶段就失败,
#    连 DllMain 都进不去, 不会有任何日志。
#    判定方法: x86_64-w64-mingw32-objdump -p build/dump.dll | grep -i "DLL Name"
#    期望输出只有 KERNEL32.dll + 一组 api-ms-win-crt-*。
set -e
cd "$(dirname "$0")"
CXX=x86_64-w64-mingw32-g++
OUT=build/dump.dll
mkdir -p build

CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -I dumper"
OBJS=""
for f in dllmain locate string meta output; do
    o="build/$f.o"
    $CXX $CXXFLAGS -c "dumper/$f.cpp" -o "$o"
    OBJS="$OBJS $o"
done

# -static: 把 libwinpthread / libgcc / libstdc++ 全部静态链入, 消除外部依赖
# -s:     剥离符号表, 体积从 3.2MB 降到 ~470KB
$CXX -shared -static -s -o "$OUT" $OBJS -lkernel32 -luser32

echo
echo "built: $OUT  ($(stat -f%z "$OUT" 2>/dev/null || stat -c%s "$OUT") bytes)"
echo
echo "依赖检查(必须只有 KERNEL32 + api-ms-win-crt-*, 出现 libwinpthread 就是坏的):"
x86_64-w64-mingw32-objdump -p "$OUT" | grep -i "DLL Name"
