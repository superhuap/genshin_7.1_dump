# genshin-dump v6 (Genshin Impact 7.1)

以 **7.0 dumper 的代码为基线**，移植适配 7.1。**纯内存模式：不读任何磁盘元数据文件。**

产物 `build/dump.dll`，注入式，输出 Il2CppDumper 风格 `dump.cs` / `dump.json`。

> **完整公式、判据、7.2 迁移方法见 [`docs.md`](docs.md)。**
> 本文件只讲怎么用、怎么构建、怎么验证。

## 与 7.0 的关系

| 项 | 说明 |
|---|---|
| 代码结构 / 交互流程 / 控制台输出 | 照搬 7.0 |
| 数据获取层 | 照搬 7.0 —— `InitCtx` 只读运行期全局 |
| 数值 / 公式 / 混淆常数 | 全部换成 7.1（IDA 确认 + 离线全量回归） |

7.0 本来就是纯内存 dumper，所以"不读磁盘"这条是**继承**来的，不是新加的限制。

## 用法

1. 用 Xenos（或任意注入器）在游戏进程里 `LoadLibrary("build\dump.dll")`。
2. DLL 轮询等待 metadata 全局就绪（每 250ms 试一次，上限 `timeout` 秒），
   自动弹控制台并打印就绪信息与各特性开关状态。
3. 解算全部类型（约 2~3 秒），完成后打印输出路径。
4. 输出**固定**在 `%TEMP%\genshin_dump\`：
   `dump.cs` / `dump.json` / `report.txt` / `summary.txt` / `diag.txt` / `dump.done` / `progress.log`；
   失败写 `dump.fail` 并附原因，崩溃写 `crash.txt`（含故障地址相对模块的偏移与当时正在解算什么）。

`config.txt`（首次运行自动生成，**放在 DLL 同目录**）：

```
console=1            ; 弹控制台看实时日志
hold=0               ; 结束后等按键再关窗口
timeout=600          ; 等 metadata 全局就绪的上限(秒)
```

> 7.0 的 `out=` 配置项已移除 —— 输出目录固定，避免配置错误导致产物散落。

## 纯内存是怎么做到的

`InitCtxMemory` 只做三件事，与 7.0 同构：

```c
base = GetModuleHandleW(L"GenshinImpact.exe");
hdr  = *(u64*)(base + 0x5AD52B8);          // 528B 混淆 header
blob = *(u64*)(base + 0x5AD52C0) - 528;   // metadata 内容起点
```

之后所有表都是 `blob + 528 + (h32(field) OP CONST)` —— 每表一次 XOR/减法，只算一次。
blob 是游戏**已经映射好的内存**，所以 82MB 的读盘成本为零。

### 7.1 与 7.0 的结构差异（已实测）

- 7.0 的 `hdr`/`blob`/`pool` 是三个独立全局；7.1 合并成 `g_52B8`/`g_52C0` 一对，
  且 `g_52C0` 指向 header **之后**，故内容起点要 `-528`。
- 7.1 把程序集/镜像表搬到了**运行期堆**，**88 字节/条**（不是 7.0 的 40/44）。
  它在 CRT 堆上，startup 释放后依然存活 ⇒ 晚注入也能读，不需要抢 startup 窗口。
- 7.1 的 16B `Il2CppType` 数组在 exe 映像里（RVA `0x2E1EA20`），不在堆上。

### ⚠️ 方法代码地址：exe 里有**两张**同形态的表，别拿错

| RVA | 判定 |
|---|---|
| `0x2870B90` | ✅ **真方法指针表（MPT）**。711,021 条界内地址**零重复**，100% 16B 对齐 |
| `0x27D4DE0` | ❌ **泛型/共享派发桩表**。3,754 个地址被最多 **2,141** 个方法共用 |

两表只有 0.1% 相同 —— **用错表不是少量偏差，是 99.9% 的方法指向错误代码**，
而所有计数类自检照样全 PASS（代码地址空间太稠密，随机落点也大多是真函数）。

正确性判据见 `../../docs.md` §12，其中最可靠的一条是**语义字节**：
`System.String::get_Length` 必须是 `8b 41 10 c3`（`mov eax,[rcx+0x10]; ret`）。
formulaCheck 的 `mpt-unique-body` 项是常驻守卫。

## 构建

```
build_mingw.sh                              # MinGW（推荐）
build.bat                                   # MSVC, 需 x64 Native Tools Command Prompt
```

**必须静态链接**（`-static -s`）：默认链接会引入 `libwinpthread-1.dll`，
游戏进程里没有，注入直接 `0xC0000135` 起不来。最终依赖只有 `KERNEL32.dll` + 系统 `api-ms-win-crt-*`。

## 公式自检

`report.txt` 的 `formulaCheck` 段自动执行，当前 **58 项 = 53 PASS / 0 FAIL / 5 SKIP**。
每条都用 metadata 的内在性质做判据（计数、升序、区间相接、已知锚点），
任何一条不成立就明确标 FAIL —— **宁可报错也不能悄悄输出错值**。

5 项 SKIP 是 7.0 有、7.1 元数据里确实没有的表（字段默认值 / 泛型实参 / 接口 slot / 数组元素等），
详见 `report.txt` 与 `../../docs/FORMULAS_gsdump5.md`。

> 改任何公式后必须重跑，且必须 0 FAIL。

## 目录

| 文件 | 内容 |
|---|---|
| `dumper/dumper.h` | **全部常量**、混淆原语、记录结构、GameCtx |
| `dumper/dllmain.cpp` | 注入入口：轮询等待 → 控制台 → dump（SEH 保护） |
| `dumper/locate.cpp` | `InitCtxMemory`：基址/全局/表基址解析（纯内存）+ 88B 表解码 |
| `dumper/meta.cpp` | typeDef(70B)/成员(26B)/字段/属性/事件/参数/枚举解码 |
| `dumper/string.cpp` | 字符串 blob 解码（7.1 的 SSE 状态机） |
| `dumper/seh.h` | 工作线程异常保护、crash.txt |
| `dumper/output.cpp` | dump.cs/dump.json/report/summary 输出 + 58 项 formulaCheck |
| `tools/ida_verify.py` | **免 bin 离线验证**：6 项结构不变式（见下） |
| `tools/ida_apply_symbols.py` | 用 dump.json 恢复 IDA 符号**与注释**（见下） |
| `tools/reloc_ida.py` | 换版本重定位（IDAPython，四层自动发现） |
| `tools/verify_formulas.py` | 免 IDA 公式判定器（读 exe + .dat + dumper.h） |
| `tools/found.txt` | 上面两个脚本之间的中间文件（自动产出 / 自动读入） |
| `docs.md` | **完整交接文档**（公式 / 判据 / 迁移手册 / 事故录） |

## 离线验证

不需要 Windows / 游戏，**也不需要任何 `.bin`** —— 只依赖 `GenshinImpact.exe` +
`global-metadata.dat`（都是归档必带项）。

```bash
python3 tools/ida_verify.py <global-metadata.dat> [GenshinImpact.exe]
```

6 项静态检查，约 0.5 秒：

| # | 检查 | 拦截什么 |
|---|---|---|
| 1 | 528B header magic | 基址/版本错 |
| 2 | **真 MPT 界内地址零重复** | **拿错表**（见上） |
| 3 | 桩表有大量重复 | 两表变得不可区分 |
| 4 | 88B 指针全局是密文 | 误以为能从 exe 抓堆表 |
| 5 | **成员索引空间连续性** | **索引错位** |
| 6 | 15 张表基址复算 | `hdr+X OP K` 常数失效 |

**结构不变式**（空洞/重叠、MPT 重复地址）不成立直接 FAIL；
**统计量**（Σ methodCount 等）只与 7.1 基线比对并标 DRIFT。

也可在 IDA 内跑：`File > Script File...` 选本脚本，提示框选 `.dat`。

**检查 5 不可替代**：索引错位不改变方法总数，所以 58 项 formulaCheck 照样全 PASS，
症状只是「方法指向了别的函数」。详见 `docs.md` §20.2。

## 换版本工具链（7.2 等）

`ida_verify.py` 回答「当前常数对不对」；下面这套回答「换版本后新常数是多少、对不对」。
**都需要 IDA 9.x，且都不需要任何 `.bin`**。

```
      IDA 里                              终端
┌──────────────────┐                ┌────────────────────┐
│ reloc_ida.py     │  写 found.txt  │ verify_formulas.py │
│ (发现新值)        │ ────────────> │ (判定对错 + 对齐)    │
└──────────────────┘                └────────────────────┘
```

### 1. 在 IDA 里发现（`File > Script File...` → `reloc_ida.py`）

四层发现，只依赖跨版本稳定的结构特征，不含任何硬编码 RVA 或符号名：

| 层 | 找什么 | 7.1 实测 |
|---|---|---|
| 1 | header（魔数 `MHY\0` 扫描） | `0x27D4BD0` ✅ |
| 2 | metadata 全局槽（顺 header 唯一引用找初始化函数） | 5 个槽全对 ✅ |
| 3 | 代码指针表（滑窗 + 重复率分带 + 起点精修） | MPT `0x2870B90` / 733,442 项 ✅ |
| 4 | 表常数（寄存器数据流跟踪 + 按共用函数数排序） | 12 条，命中 6/15 张表 |

第 4 层结束时自动写 `tools/found.txt`，格式：

```
hdr+0x<disp>  <op> 0x<K>   <共用该常数的函数数>
```

```
hdr+0x204   + 0xE5240D45   1396   等价于 '-' 0x1ADBF2BB
```

- `disp` 是 header 内的**字节偏移**（不是 u32 下标）
- **频次是判断真伪的主要信号**：3 次的多半巧合，1400 次的铁证
- **`+` 和 `-` 是同一张表的两种写法**（互补数之和 = `0x100000000`），`dumper.h` 统一用 `'-'`：

```cpp
static constexpr TableSpec kT_iface = { 0x204, '-', 0x1ADBF2BBu };
```

### 2. 回终端判定

```bash
python3 tools/verify_formulas.py          # 自动读 found.txt
python3 tools/verify_formulas.py --json   # 机器可读
```

逐条解公式并判定：**FAIL** 越界 / 结构错；**WARN** 指进 header 区、stride 未对齐等。
退出码 `0` = 无 FAIL。

7.1 自校验基线 `PASS 21 / WARN 13 / FAIL 0`，其中算出的**界内 711,021、零重复**
与本文上面那张 MPT 表人工记载的基线一字不差。

### 3. 已知短板（别当成「表不存在」）

- 15 张表只自动认出 **6 张**。`mptr`/`thunk` 本就是**直接 RVA 常量**，没有 header 公式。
- 其余缺的靠 §18 人工补：`imul` 找记录大小 → 差分 header 偏移 → 两函数交叉确认。
- 88B 堆表静态校验不了（只在运行期 CRT 堆上），必须真机确认。
- 7.1 上三条待确认的告警：`kT_tokentype -> 0x0`、`kT_field`/`kT_param` 未按 8B 对齐。

完整流程与判读方法见 `docs.md` §20.3。

## 恢复 IDA 符号与注释

在 IDA 里 `File > Script File...` 选 `tools/ida_apply_symbols.py`，再选 `dump.json`：

```
python3 tools/ida_apply_symbols.py <dump.json>            # 在 IDA 内跑
python3 tools/ida_apply_symbols.py <dump.json> --ns       # 符号带命名空间
python3 tools/ida_apply_symbols.py <dump.json> --no-comments   # 只改名, 最快
```

不只是改名 —— dump.json 里闲置的信息全部灌回 IDA：

| 记什么 | 写进 IDA 的形式 | 7.1 实测 |
|---|---|---|
| 方法名 | 符号 `Cls__method` | 711,021 |
| 方法签名 | 函数可重复注释 + `flags` | 711,021 |
| 类型信息 | 多行类型块（image/parent/字段偏移/属性/事件/接口） | 74,616 |
| 属性访问器 | 写进 **getter/setter 地址**的注释 | 127,709 |
| 事件访问器 | 写进 **add/remove/raise 地址**的注释 | 1,180 |

属性/事件的访问器在 JSON 里是**全局方法下标**，脚本先按 type 顺序拼接所有
`methods[]` 建「下标 → rva」表（拼接长度 733,442 与 `meta.methodCount` 精确吻合）。
映射经两条不变式验证：98.93% 的访问器落在所属类型自己的方法区间内，
解出的 rva **非法数为 0**。

三个刻意取舍：

- 注释走**可重复注释**而非函数注释 —— 后者会让 IDA 对 71 万个函数做重量级
  原型/SP 分析，实测卡死整库
- 批量应用时关自动分析，结束再开
- **不自动设函数原型** —— 71 万次 `SetType` 会拖垮 IDA；签名以注释保留

幂等：只重命名自动名（`sub_`/`nullsub_`/`unk_`/`locret_`/`def_`/`jpt_`/`loc_`），
不覆盖手工命名，注释内容相同则跳过。实测第二次运行 0 命名 0 注释。

> **优先用 `dump.json`。** 本游戏有 1,783 个混淆方法名解码后内嵌控制字符（含 `\n`），
> 写进 `dump.cs` 会劈乱行结构：JSON 路径解出 711,021 个，`.cs` 路径只有 710,773 个。

### 基线

```
typeCount 88902 / fields 440172 (327,555 实例 + 112,617 static-const)
methods   733442 / props 115596 / events 628 / interfaces 25981
枚举         8,123 个, 成员 71,358
方法地址     711,021 (96.9%), 唯一, 零重复
产物         dump.cs 115MB / dump.json 137MB
formulaCheck 58 项 = 53 PASS / 0 FAIL / 5 SKIP
```
