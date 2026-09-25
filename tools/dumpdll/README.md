# Genshin 7.1 metadata dump 工具

## 原理

DLL 注入后自轮询 `qword_145AD52C8`(startup-metadata 缓冲指针,IDA VA 0x145AD52C8):
该指针 **非空 -> NULL** 的瞬间(0x14053A829,init 收尾释放 startup 缓冲)= 全部
metadata 表已在内存中解密/重建完毕,立即 dump。注入时机与 dump 时机解耦——
只要反作弊放行注入,之后 dump 自动完成,无需抢时间。

## 使用步骤(Xenos)

1. 复制 `gi_dump.dll` 到任意目录(建议游戏目录)
2. 启动 GenshinImpact.exe,窗口刚出来时立刻用 Xenos 注入(手动映射或 LoadLibrary 均可)
3. DLL 自动等待 init 完成(约十几秒),然后在 **游戏目录** 下生成 `gi_dump\`:
   - `module.bin` + `module.bin.map` — 主模块映像(il2cpp 节 + 运行期 .data 指针)
   - `pool_metadata.bin` / `pool_genericclass.bin` / `pool_genericmethod.bin` — 解密后的元数据池(0x50000000000)
   - `raw_global.bin` — global-metadata 加载缓冲的最终状态
   - `il2cpp_section.bin` — il2cpp 节
   - `globals.bin` + `info.json` — 全部关键全局变量运行期值
   - `gi_dump.log` — 过程日志
   - `DONE.txt` — 完成标志
4. 手动兜底:任何时候在 `gi_dump\` 里创建空文件 `trigger.txt` → 立即 dump
5. dump 完成后游戏可继续运行或直接关闭;把整个 `gi_dump\` 拷回 Mac

## 注意

- 若游戏在 init 完成前检测注入崩溃,改用 Xenos 的手动映射模式 + 更早注入
- 若注入太晚(init 已完成),DLL 会检测到并延迟 3 秒自动 dump
- 全程 ~900MB 磁盘写入,需要几秒到几十秒;看 `DONE.txt` 或日志确认

## 编译(如需改动)

```
x86_64-w64-mingw32-gcc -O2 -shared -o gi_dump.dll gi_dump.c -static -lkernel32 -luser32
```
