# docs.md —— Genshin Impact 7.1 纯内存 dumper 交接文档

> 对象：本目录（`tools/v6/`），产物 `build/dump.dll`，注入型 IL2CPP metadata dumper
> 基线：`/Users/superhuap/Desktop/7.0-dumper`（7.0 版，公式不同，**不可直接复用常量**）
> 状态：**58 项检查 = 53 PASS / 0 FAIL / 5 SKIP**，真机验证通过
> 最后更新：2026-09-26

**这是唯一的交接文档。** 历史上有两份 `FORMULAS.md`（v4 699 行 / v5 769 行，
记录公式的推导过程与失败教训），已按「只保留一份」原则**合并进本文档**：

| 原 FORMULAS 章节 | 现在在哪 |
|---|---|
| §0 三条最易踩的规则 | [§0](#0-三条最易踩的规则迁移前必读)（前置） |
| §1–§11 公式表 | [§3](#3-常量表运行期全局) – [§11](#11-枚举与常量值链重点) |
| §12 字段偏移链 | [§12](#10-字段偏移链重点) |
| §13 字段默认值的真相 | [§13](#13-字段默认值元数据里没有) |
| §14 其他已定位未接入的表 | [§14](#14-已定位但未接入的表留档) |
| §15 枚举 | [§11](#11-枚举与常量值链重点) |
| §16 GENERICINST | [§15](#15-泛型实参为什么纯静态做不到重点) |
| §17 14B 元素表 | [§16](#16-14b-元素表结构齐了但终点在堆) |
| §18 静态/运行期分界线 | [§17](#17-静态--运行期的确切分界线重点) |
| §19 八项特性归属 + 失败教训 | [§19](#19-八项-70-特性的最终归属) / [§25](#25-事故录) |
| v4 §10 派生规则 | [§10](#21-派生规则不是混淆) |
| v4 §11 运行期结构（`Il2CppClass` 等） | [§21](#26-运行期结构留档不参与纯内存路径) |
| v4 §13 启动自检清单 | 已被 [§20](#20-自检体系) 的 58 项 formulaCheck 取代 |

## 目录

**必读**：[§0 三条最易踩的规则](#0-三条最易踩的规则迁移前必读) · [§25 事故录](#25-事故录)

| 节 | 内容 |
|---|---|
| [§0](#0-三条最易踩的规则迁移前必读) | 三条最易踩的规则（迁移前必读） |
| [§1](#1-工具做什么--怎么用) | 工具做什么 / 怎么用 |
| [§2](#2-架构与数据来源) | 架构与数据来源 |
| [§3](#3-常量表运行期全局) | 运行期全局（4 个关键 RVA） |
| [§4](#4-常量表metadata-blob-内的表) | metadata blob 内的 15 张表 |
| [§5](#5-记录结构typedef-70b) | 记录结构：typeDef 70B |
| [§6](#6-记录结构成员-26b--字段-8b--属性-10b--事件-14b--参数-8b) | 记录结构：26B / 8B / 10B / 14B / 8B |
| [§7](#7-混淆原语) | 混淆原语 + **三点锚点表** |
| [§8](#8-字符串-blob-解码) | 字符串 blob 解码 |
| [§9](#9-类型名解析16b-il2cpptype) | 类型名解析（16B Il2CppType） |
| [§10](#10-字段偏移链重点) | **字段偏移链**（重点） |
| [§11](#11-枚举与常量值链重点) | **枚举与常量值链**（重点） |
| [§12](#12-方法代码地址两张表的陷阱重点) | **方法代码地址：两张表的陷阱**（重点） |
| [§13](#13-字段默认值元数据里没有) | 字段默认值：元数据里没有 |
| [§14](#14-已定位但未接入的表留档) | 已定位但未接入的表（留档） |
| [§15](#15-泛型实参为什么纯静态做不到重点) | **泛型实参：为什么纯静态做不到**（重点） |
| [§16](#16-14b-元素表结构齐了但终点在堆) | 14B 元素表：结构齐了但终点在堆 |
| [§17](#17-静态--运行期的确切分界线重点) | **静态 / 运行期的确切分界线**（重点） |
| [§18](#18-公式的寻找方法双验证方法论) | 公式的寻找方法（双验证方法论） |
| [§19](#19-八项-70-特性的最终归属) | 八项 7.0 特性的最终归属 |
| [§20](#20-自检体系) | 自检体系（formulaCheck + ida_verify + 换版本工具链） |
| [§21](#21-派生规则不是混淆) | 派生规则（不是混淆） |
| [§22](#22-当前功能开关状态) | 当前功能开关状态 |
| [§23](#23-已知缺口) | 已知缺口 |
| [§24](#24-72-迁移手册) | **7.2 迁移手册** |
| [§25](#25-事故录) | 事故录（6 个坑） |
| [§26](#26-运行期结构留档不参与纯内存路径) | 运行期结构留档（`Il2CppClass` 等） |
| [附:归档清单](#附归档清单) | 归档清单 |
| [附:文件清单](#附文件清单) | 文件清单 |

## 0. 三条最易踩的规则（迁移前必读）

这三条都在 7.0→7.1 迁移时**实际踩过**，且都造成了长时间误判。

1. **RVA（虚拟地址偏移）不是文件偏移（原始偏移）。** 必须过 section 表换算。
   section header 步长 **40** 字节，起点 = `pe + 4 + 20 + SizeOfOptionalHeader`
   （`SizeOfOptionalHeader` 在 `pe+0x14`，**极易多算 0x20** —— 我犯过，
   错到以为「section 表被加密」）。7.1 的 section 表是**正常的 13 段**：
   `.text .rdata .data .pdata .00cfg .retplne .tls .voltbl _RDATA il2cpp .upx0 .reloc .rsrc`。
   `SizeOfImage` 实测 `0x1AFF7000`（452,947,968 ≈ 432 MB）。
   例：真 MPT `RVA 0x2870B90` 在 `.rdata`，文件偏移 = `0x021A9000 + (0x2870B90 − 0x021AA000)` = `0x286FB90`。

2. **`field_key` 的 64 位乘法不能截断。** `34782*i` 在 `i ≥ 123483` 时超过 2^32，
   截断会让 **316,689 个字段全部解错**。症状极隐蔽：字段总数不变，只有名字变乱码。

3. **值类型判定不能只看 16B 记录的 kind 反引用。** 反查 `VALUETYPE.data` 指向本
   typedef 对 struct 有效，但**原始类型没有这种反引用**
   （实测 `data==System.Int32 && kind∈(VT,CL,EN)` 的记录数 = **0**）。
   必须并上 `byvalType`（`td+4 ^ 0x0DA4711B`）那条记录。只看反引用会把
   `System.Int32` 误判成 class。

> 补充第 4 条（本轮新增）：**不要拿 stock Il2CppDumper 的约定当铁律**去套这份元数据。
> 本作偏移域含 16 字节 `Il2CppObject` 头，**值类型也从 0x10 起**（见 §12.4）。
> 先前两次（"attrBase 必须按 fieldCount 连续"、"值类型首字段必须是 0x0"）都因此得到假阴性。

---

## 1. 工具做什么 / 怎么用

**做什么**：注入游戏进程，读取运行期内存里的 IL2CPP metadata，输出 Il2CppDumper 风格的 `dump.cs`（供人工阅读/参考）和结构化 `dump.json`（供 `ida_apply_symbols.py` 批量恢复 IDA 函数符号）。

**关键特性：纯内存**。不读 `global-metadata.dat`、不读 `startup-metadata.dat`、不搜任何磁盘路径。metadata blob 是游戏自己已经映射好的 82MB 内存，读盘成本为零，因此**注入即 dump，无需抢启动窗口**。

**用法**

```
1. 用 Xenos / 任意注入器在 GenshinImpact.exe 里 LoadLibrary("dump.dll")
2. DLL 轮询等待 metadata 全局就绪（默认上限 600s，见 config.txt 的 timeout）
3. 自动 dump，输出到 %TEMP%\genshin_dump\
```

**输出**

| 文件 | 内容 |
|---|---|
| `dump.cs` | Il2CppDumper 风格，115MB，UTF-8 **带 BOM**（否则中文版 Windows 编辑器按 GBK 猜编码会乱码） |
| `dump.json` | 136MB，无 BOM（RFC 8259 不允许）。顶层 `{meta, types[]}` |
| `report.txt` | formulaCheck 58 项自检结果（53 PASS / 0 FAIL / 5 SKIP）+ 统计 |
| `summary.txt` | 紧凑键值摘要 + 特性开关 + 完整 diag |
| `diag.txt` | 初始化诊断（所有全局解析结果、锚点验证） |
| `progress.log` | 带时间戳的进度 |
| `dump.done` | `ok` |
| `crash.txt` | 仅崩溃时：异常码、故障地址、相对模块偏移、当时正在解算什么 |

**构建**

```
tools/v6/build_mingw.sh          # MinGW, 产出 build/dump.dll
tools/v6/build.bat               # MSVC
```

必须 `-static -s`：默认链接会引入 `libwinpthread-1.dll`，游戏进程里没有，注入直接 `0xC0000135` 起不来。最终依赖只有 `KERNEL32.dll` + 系统 `api-ms-win-crt-*`。

**离线快查**（不需要 Windows / 游戏，**不需要任何 .bin**）

```bash
python3 tools/ida_verify.py <global-metadata.dat> [GenshinImpact.exe]   # 6 项结构不变式
python3 tools/verify_formulas.py                                        # 逐条解公式并判定
```

约 0.5 秒。详见 [§20.2](#202-ida_verifypy--免-bin-的离线快查替代原-nativetestidxprobe)
和 [§20.3](#203-换版本工具链reloc_idapy--foundtxt--verify_formulaspy)。

**换版本时**（7.2 等）另有三件套，先在 IDA 里跑 `reloc_ida.py` 发现新值，
再回终端跑 `verify_formulas.py` 判定 —— 流程见 [§20.3.5](#2035-完整-72-迁移流程)。

---

## 2. 架构与数据来源

```
                    ┌─────────────────── 进程内存 ───────────────────┐
  base = GetModuleHandleW("GenshinImpact.exe")
                    │
   ┌────────────────┼─────────────────────────────────────────────┐
   │ exe 映像 (0x1AFF7000 = 452MB, RVA == 偏移)                    │
   │   RVA 0x27D4BD0 : 528B 混淆 header (magic "MHY\0")            │
   │   RVA 0x2870A88 : 静态结构, +72 存 16B 类型数组 RVA           │
   │   RVA 0x2E1EA20 : 16B Il2CppType 记录数组 (2M 条容量)         │
   │   RVA 0x2870B90 : **真方法指针表 MPT**  ← 唯一方法地址来源     │
   │   RVA 0x27D4DE0 : 泛型/共享派发桩表  ← 不要用!               │
   │   RVA 0x39085D0 : 字符串 SSE 常量 (48B)                      │
   │   RVA 0x5AD4xxx : 运行期指针全局 (见 §3)                     │
   └────────────────┼─────────────────────────────────────────────┘
                    │  *(u64*)(base + RVA)
   ┌────────────────▼─────────────────────────────────────────────┐
   │ CRT 堆 (startup 释放后仍存活)                                 │
   │   RVA 0x5AD52B8 -> 528B header 指针                          │
   │   RVA 0x5AD52C0 -> blob 基址 (**指向 header 之后, 故要 -528**)│
   │   RVA 0x5AD52F0 -> 75 × 88B 程序集表指针                    │
   │   RVA 0x5AD5300 -> 75 × 88B 镜像表指针                      │
   │   blob = 82,724,152 B, 内部 20+ 张表 (§4)                     │
   └──────────────────────────────────────────────────────────────┘
```

**blob 指针的 −528 是 7.1 特有的坑**。7.0 的 `g_xxxx` 直接指内容起点；7.1 的 `g_52C0` 指 header 之后。忘了减 528 会整体错位 528 字节，表现为「所有字符串解出来是乱码」。

**表基址统一形态**：

```
table = blob + 528 + (h32(field) OP CONST)
```

`h32(field)` = 读 528B header 的第 `field` 字节起 4 字节。`OP ∈ {'-', '^', '+'}`。每张表算一次，缓存进 `GameCtx`。代码见 `locate.cpp: ResolveTable()`。

---

## 3. 常量表：运行期全局

全部经 IDA 确认 + 运行期值交叉验证。**换版本时这批最先失效。**

| 常量 | 值 | 含义 | 验证判据 |
|---|---|---|---|
| `kRvaHeaderPtr` | `0x5AD52B8` | → 528B header | header 魔数 = `0x0059484D` ("MHY\0") |
| `kRvaMappedMeta` | `0x5AD52C0` | → blob（已含 header 偏移） | 减 528 后长度 0x4EE4538 |
| `kHeaderBytes` | `528` | blob 指针 − 内容起点 | |
| `kHeaderMagic` | `0x0059484D` | "MHY\0" 小端 | 唯一性：错值立刻报错 |
| `kRvaTypeStruct` | `0x2870A88` | 静态结构，其 +72 存类型数组 RVA | 解析出的 RVA 必须落在映像内 |
| `kTypeArrayOff` | `72` | 上面的字段偏移 | |
| `kRvaAsmCount` | `0x5AD52F0` | dword = 75 | 必须 == `kAsmImgCount` |
| `kRvaAsmTable` | `0x5AD52F8` | 75 × 88B 程序集表 | stride 88 链式校验（见 §17.3） |
| `kRvaImgCount` | `0x5AD5300` | dword = 75 | |
| `kRvaImgTable` | `0x5AD5308` | 75 × 88B 镜像表 | |
| `kAsmImgStride` | `88` | **不是 7.0 的 40/44** | |
| `kAsmImgCount` | `75` | 75 个程序集 / 镜像 | |
| `kRvaGenericDesc` | `0x5AD4E98` | 泛型描述符（仅诊断，特性强制关） | |
| `kRvaSse` | `0x39085D0` | 字符串 SSE 常量 48B | 解出的名字必须是合法标识符 |
| `kImageBase` | `0x140000000` | PE 首选基址 | **仅用于打印 VA**，真机 base 是 ASLR 后的值 |

> `SizeOfImage = 0x1AFF7000`（452,947,968）**不是硬编码常量** —— 每次运行都从 PE 头
> （`NT+0x50`）现场读取。所以它只出现在文档里，`dumper.h` 中没有。
> 离线验证时由 `ida_verify.py` 从 exe 的 PE 头解析（见 §20.2）。

### 3.1 88B 程序集表字段（`kAsm*`）

| 偏移 | 常量 | 公式 | 结果 |
|---|---|---|---|
| `+0x24` | `kAsmTypeCountK = 0x6A3E22EA` | `u32 ^ K` | 该程序集的类型数 |
| `+0x28` | `kAsmDllNameK = 0x2432F7B06693D92B` | `u64 − K` | dll 名指针（"mscorlib.dll"） |
| `+0x30` | `kAsmImgPtrK = 0x5AEB1E2239920311` | `u64 ^ K` | → `img88[i]`，反推 imageIndex |
| `+0x38` | `kAsmTypeStartK = 0x4B1CB1C1` | `u32 ^ K` | 该程序集的类型起始下标 |

**不变式**：`ts[0] == 0`，`ts[i] + tc[i] == ts[i+1]`，每条 `tc[i] > 0`，`Σ tc[i] == 88902`。
这条链是纯内存路径的权威来源，也是 formulaCheck 的 `asm88-chain` 项。**必须严格校验**——全 0 的退化表能骗过朴素的「首尾相接」检查（tc 全 0 时链条退化成「所有 ts 相等」，恒真），2026-09-26 真机就因此产出过 21 项 FAIL 的空 dump。

### 3.2 88B 镜像表字段（`kImg*`）

| 偏移 | 常量 | 公式 | 结果 |
|---|---|---|---|
| `+0x40` | `kImgNameK = 0x783FCBBE2E713C7F` | `u64 − K` | simpleName（"mscorlib"） |
| `+0x48` | `kImgCultureK = 0x3351BD851F7B567F` | `u64 − K` | culture |

---

## 4. 常量表：metadata blob 内的表

`h32(f)` = 528B header 偏移 `f` 处的 u32。`table = blob + 528 + (h32(f) OP K)`。

| 常量 | f | OP | K | 条大小 | 用途 | 状态 |
|---|---|---|---|---|---|---|
| `kT_typedef` | 180 | `-` | `330781793` | **70B** | 类型定义（核心） | ✅ |
| `kT_method` | 364 | `-` | `483030612` | **26B** | 成员（字段+方法共用区间） | ✅ |
| `kT_mptr` | 148 | `^` | `0x4A4C0A71` | 4B | 方法 → vtable 槽位 | ✅ |
| `kT_field` | 396 | `-` | `336578260` | 8B | 字段名/类型（枚举走这条） | ✅ |
| `kT_prop` | 336 | `-` | `473781129` | 10B | 属性 | ✅ |
| `kT_event` | 488 | `^` | `0x100547B1` | 14B | 事件 | ✅ |
| `kT_param` | 276 | `^` | `0x3E5D33E6` | 8B | `{typeIdx, nameIdx}` | ✅ |
| `kT_iface` | 516 | `-` | `450622139` | 4B | 接口 | ✅ |
| `kT_fieldoff` | 296 | `^` | `0x0F92DC85` | 4B | **真实字段偏移**+标志位 | ✅ |
| `kT_fdesc12` | 144 | `+` | `0x0B7255040` | 12B | 每类型字段描述符 | ✅（仅取偏移用） |
| `kT_fhidx4` | 376 | `+` | `0x0ADEC9E28` | 4B | typeIndex → 描述符下标 | ✅ |
| `kT_enumval` | 316 | `^` | `0x593DE464` | 12B | 枚举常量索引表 | ✅ |
| `kT_enumvalblob` | 160 | `^` | `0x3F525210` | — | 枚举值字节区 | ✅ |
| `kT_strblob` | 388 | `+` | `0xBF9D4735` | — | 字符串 blob 源 | ✅ |
| `kT_tokentype` | 412 | `^` | `0x30F4D28E` | 8B | token → 类型（bsearch） | ✅ |
| `kT_paramReg` | 260 | `^` | `0x094C42AB` | 12B | 参数类型注册表 | ⚠️ 定义了但未消费 |
| `kT_fldoff8` | 332 | `^` | `0x37855E78` | 8B | 字段偏移位图 | ⚠️ 定义了但未消费 |
| `kT_geninst12` | 472 | `^` | `0x1F85ABE5` | 12B | 泛型实例缓存 | ❌ 强制关闭 |

**枚举值条数**：`count = (h32(84) ^ 0x23E67A90) / 12`，实测 75,548。

> `kT_paramReg` / `kT_fldoff8` 是已定位但未启用的表。保留常量是为了将来启用时不必重新定位；它们**不参与**任何输出，删了也不影响功能。

---

## 5. 记录结构：typeDef 70B

`typedefTab + 70 * typeIndex`，基址 = `blob + 528 + (h32(180) − 330781793)`。

**完整字段表**（`u32` 除非注明；`i16` = 有符号）：

| 偏移 | 含义 | 公式 |
|---|---|---|
| `+0` | 命名空间 token | `− 1145778368` |
| `+4` | **byval 类型**（值类型判定主依据） | `^ 0x0DA4711B` |
| `+8` | 属性起始下标 | `− 1995389561` |
| `+12` | **成员（方法）起始全局索引** | `^ 0x4D8127F2` |
| `+16` | baseType（**不是基类**，见 §10.2） | `− 1950851500` |
| `+24` | elementType | `− 1031049247` |
| `+28` | 字段起始下标 | `^ 0x29010897` |
| `+36` | 类型名 token | `− 72511848` |
| `+48` | 方法数 | `u16 + 4806` |
| `+52` | 事件起始下标 | `i16 + 3330` |
| `+54` | 接口起始下标 | `i16 + 6631` |
| `+56` | 字段数 | `u16 ^ 0x51A8` |
| `+58` | flags | `u16`（原值） |
| `+67` | 属性数 | `u8 ^ 0x16` |
| `+68` | 事件数 | `u8 + 113` |
| `+69` | 接口数 | `u8 ^ 0xBA` |

> 另有 `+32` = 接口实现列表起始（`^ 0x2E8C0EB8`）与 `+60` = 泛型参数起始（`u16 ^ 0x43DA`），
> 二者已由 class builder 反编译确认（见 §10.4），但 v6 未使用。

**成员索引空间不变式**（`ida_verify.py` 检查 5 每次必查）：

```
忽略 methodCount==0 的类型（11,177 个：接口/枚举，start 是哨兵 0xFFFFFFFF）后：
  索引区间 = 0 .. 733442      空洞 = 0      重叠 = 0
  Σ methodCount == 733442
```

**这是全套自检里最容易被绕过的一环**：索引一旦错位，方法**总数**不变，
所以 58 项 formulaCheck 照样全 PASS，症状只是「方法指向了别的函数」。

## 6. 记录结构：成员 26B / 字段 8B / 属性 10B / 事件 14B / 参数 8B

### 6.1 成员 26B（`methodTab + 26 * 全局成员号`）

字段与方法**共用同一索引区间**。判据：返回类型字段解出 `0xFFFFFFFF` → 这是字段；否则是方法。

| 偏移 | 含义 | 公式（`i` = 全局成员号，`method_key = method_key(i)`） |
|---|---|---|
| `+0` | 名字 token | `method_key ^ (u32 − 1524016681)` |
| `+4` | 参数起始下标 | `method_key ^ (u32 − 257927898)` |
| `+8` | 返回类型（16B 记录下标） | `u32 ^ method_key ^ 0x3F7BDF39` |
| `+12` | 声明 typedef | `u32 ^ method_key ^ 0x59244785` |
| `+16` | vtable slot | `(u16 − 25344) ^ method_key16(i)` |
| `+22` | MethodAttributes | `u16 ^ method_key16(i) ^ 0x8F60` |
| `+24` | 参数个数 | `u8 ^ (method_key − 31)` |

> `+16` 的 slot 走**另一张表** `kT_mptr`（4B/条，vtable 槽位），不是这条 26B 记录。

### 6.2 MethodAttributes 位域（**3 bit 字段，不是单 bit**）

```
MemberAccessMask = 0x0007    PrivateScope=0  Private=1  FamANDAssem=2
                               Assembly=3     Family=4   FamORAssem=5  Public=6
Static  = 0x0010             Final   = 0x0020
Virtual = 0x0040             HideBySig = 0x0080
```

访问性判据：`(flags & 0x7) == 0x1` → private，否则 public。

> **踩过的坑**：曾用 `flags & 0x0040` 判 private，但 `0x0040` 是 **Virtual**。
> 导致全部方法的可见性都是错的。访问性是 `& 0x7` 的 3 bit 值，不是单个 bit。

### 6.3 字段 8B（`fieldTab + 8 * 全局字段号`）

`k = field_key(全局字段号)`：

```
name    = DecodeString( ((u32(rec+4) - 1475293452) ^ k) ^ 0x2D027B84 )
typeRec = k ^ u32(rec) ^ 0x2D27D873
```

枚举成员走这条（枚举无方法，26B 区间为空）。

> **const 字段的坑**：8B 表对 `isConst` 字段存的是**常量槽号**而不是类型索引，
> 所以 `System.String.TrimHead` 这类 const 字段的「类型」解出来是错的
> （真实类型 `char*`，解出 `System.Int32`）。
> **给 IDA 建结构体时必须跳过 `isStatic && isConst` 的字段** —— 偏移和类型都不可靠。
> `dump.json` 里这两个字段分别是 `isStatic` / `isConst`，好过滤。

### 6.4 属性 10B（`k = prop_key(i)`，`kl = k & 0xFFFF`）

```
name   = DecodeString( k ^ (u32(o) - 1953953095) )
getter = (u16(o+6) ^ kl) ^ 0xE5A2
setter = (u16(o+8) - 23324) ^ kl            (0xFFFF = 无)
```

属性类型 = getter 的返回类型；**只有 setter 时退回 setter**（否则 set-only 属性类型留成 `?`）。

> **propStart 纠偏的判据必须与 stock 完全一致** + `getter ∈ {0xFFFF, <4096}`。
> 否则 ±16 范围内挑中的候选点会错，闭包/状态机类的属性会整段错位。

### 6.5 事件 14B（`k = event_key(i)`，`kl = k & 0xFFFF`）

```
name   = DecodeString( k ^ (u32(o+4) - 1037298109) )
type   = k ^ (u32(o) - 452544412)
remove = u16(o+8)  ^ kl ^ 0xEE66
raise  = (u16(o+10) - 30703) ^ kl
add    = u16(o+12) ^ kl ^ 0xBEA7
```

### 6.6 参数 8B（`pk = param_key_of(idx)`）

```
name    = DecodeString( pk ^ (u32(p+4) - 1764493660) ^ 0x4CDBD093 )
typeRec = u32(p) ^ pk ^ 0x31BF59F3
```

属性的 getter/setter、事件的 add/remove/raise 都是**方法序号**，输出时换算成
`methodStart + getter`；`0xFFFF` = 无。

## 7. 混淆原语

`dumper.h` 里有实现，这里只记**致命细节**和**验证锚点**。

```c
field_key(i)    : v = ((u64)34782*(u64)i) ^ 0x59B1DB19
                  ((u64)1824013172 * v) >> 16) + 1410079245
method_key(i)   : (((u32)((u64)860405619*i) ^ 0x73758947) + 1547935323)
method_key16(i) : ((((u32)((0u-16525u)*i) ^ 0x8947u) - 24997u) & 0xFFFF
prop_key(i)     : v = (0x17A5419F8A28 * i) >> 9
                  ((((u64)976451930 * v) >> 12) & M32) ^ 0x70BE4B04
event_key(i)    : (((u32)((0u-1599256506u)*i + 1725894951u) ^ 0x1B23E40Fu)
param_key_of(i) : v = ((41617*i + 1219887025) & M64) ^ 0x19E1D47A
                  (((1457992407*v & M64) >> 21) + 2068375556) & M32
```

> ⚠️ **`field_key` 的 `34782 * i` 必须保持 64 位。** `34782 * 123483 ≈ 2^32`，
> 截断后索引 ≥ 123,483 的 **316,689 个字段全部解错**。症状极隐蔽：
> 字段总数不变，只有名字变乱码。见 §0 规则 2。

### 7.1 三点锚点表（换版本后**立刻**验证原语是否还对）

7.1 的 formulaCheck 用 `i = 0 / 1 / 12345` 三点把 6 个原语钉死。**7.2 重新差分出
常数后，先用这三点验一遍**，比跑全量快几个数量级：

| 原语 | i=0 | i=1 | i=12345 |
|---|---|---|---|
| `field_key` | `0xE924C21B` | `0xB37F41D4` | `0x9F82EC9C` |
| `method_key` | `0xCFB927A2` | `0x9C80D48F` | `0xD8B15837` |
| `method_key16` | `0x000027A2` | `0x0000D48F` | `0x00005837` |
| `prop_key` | `0x70BE4B04` | `0x8D9F04C6` | `0xD9AF9360` |
| `event_key` | `0x7DFCF528` | `0x1CAFBD62` | `0xB022ACB2` |
| `param_key_of` | `0x59176BA7` | `0x62073714` | `0x94627BE1` |

7.2 的值会变 —— 要做的是**把新常数代入这三个 i，看结果是否自洽**：
`field_key` 应满足 `field_key(i)` 在整个字段空间**双射**（440,172 个输入 → 440,172 个
不同输出）。若出现碰撞，说明乘法截断或常数抄错了。

## 8. 字符串 blob 解码

实现见 `string.cpp`。

**token 结构**：`[31:24]` = 长度，`[23:0]` = blob 内偏移。`0x8` 与 `0xFFFFFFFF` 表示空串。

```
源位置  = strBlob + off
k0      = 0x5C2B4E660E2D0544 * ((0x694418957C890198 * off) ^ 0x55A357D81EF0E48B)
stride  = [SSE+8]                              线性步进
常量    = [SSE+0], [SSE+16], [SSE+24], [SSE+32], [SSE+40]  → c0, c1, c3, c2, c4

blocks < 8  : 纯线性 (c ^= k, k += stride)
blocks >= 8 : 前 (blocks & ~1) 块走 SSE 状态机, 剩余块回线性
```

SSE 常量从 `RVA 0x39085D0` 运行期读，读不到时用 IDA 确认的兜底常数 `stride = 0x6B0B40C349AE61E5`。

**判据**：解出的必须是合法 UTF-8 标识符。当前有约 **0.04% 的名字本身在 metadata 里就是 mojibake**（游戏侧就坏了），BOM 只能解决编码识别，修不了错误字符串 —— 这是数据问题不是公式问题。

---

## 9. 类型名解析（16B Il2CppType）

数组在 **exe 映像内** `RVA 0x2E1EA20`（7.1 特有；7.0 在堆上）。

### 9.1 值类型判定：`byvalType` 是主要依据

```
byvalType(ti) = u32( typedefTab[70*ti] + 4 ) ^ 0x0DA4711B     // 16B 记录下标
isValueType   = kind(byvalType) ∈ { VALUETYPE, ENUM, BOOLEAN, CHAR, I1..R8, I, U }
```

**不能只看 16B 记录的 kind 反引用。** 反查 `VALUETYPE.data` 指向本 typedef 这条路
对 struct 有效，但**原始类型（int/float/…）在 16B 数组里没有这种反引用**
（实测 `data==System.Int32 && kind∈(VT,CL,EN)` 的记录数 = 0）。
只看反引用会把 `System.Int32` 误判成 class。必须并上 `byvalType` 那条记录。

formulaCheck 的 `Int32-isValueType` 项就是守这条的。

### 9.2 kind 枚举

（`dumper.h: TypeEnum`）：
`0x00 END / 0x01 VOID / 0x02 BOOLEAN / 0x03 CHAR / 0x04 I1 / 0x05 U1 / 0x06 I2 / 0x07 U2 / 0x08 I4 / 0x09 U4 / 0x0A I8 / 0x0B U8 / 0x0C R4 / 0x0D R8 / 0x0E STRING / 0x0F PTR / 0x10 BYREF / 0x11 VALUETYPE / 0x12 CLASS / 0x13 VAR / 0x14 ARRAY / 0x15 GENERICINST / 0x16 TYPEDBYREF / 0x18 I / 0x19 U / 0x1C OBJECT / 0x1D SZARRAY / 0x1E MVAR / 0x55 ENUM`

**边界防护（关键）**：`typeRecEnd` 必须夹紧到 `min(RegionEnd(ptr), imageEnd)`，上限 `0x200000` 条。
> 7.1 的 `.rdata` 是一个超大 region，直接用 `VirtualQuery` 的 region 末端会把越界索引也判成「可读」，于是读到垃圾类型记录 → 各种离谱 kind/计数 → 卡死或崩。再叠一层「不要额外要求 16 字节对齐」的要求：对齐会把复合类型（指向的元素记录在文件里不保证 16B 对齐）的字段类型从 `array<...>` 退化成 `?`，实测字段语义一致率从 99.741% 掉下来。

`GENERICINST` 特性**强制关闭**（见 §15）。递归护栏 `g_genDepth` 仍保留在产品代码里，
但原先由 `nativetest` 覆盖它的合成自引用表回归测试**已随该工具删除** ——
若将来重开泛型特性，需重新造这个测试。

---

## 10. 字段偏移链（重点）

来源：`sub_140512870 SetupFields`，2026-09-26 IDA 确认 + 全量实测。

```
attrBase(ti) = i32( desc12[ i32( hidx4[ti] ) ] + 8 )
e(ti, j)     = fattr4[ attrBase(ti) + j ]
```

- `desc12` = `kT_fdesc12`（每类型 12B 描述符）
- `hidx4`  = `kT_fhidx4`（typeIndex → 描述符下标）
- `fattr4` = `kT_fieldoff`（4B/条）

**hidx4 的索引变换是恒等**：`(35*ti) * 0x8AF8AF8B`，而 `35 * 0x8AF8AF8B ≡ 1 (mod 2^32)` —— `0x8AF8AF8B` 就是 35 的模逆元。一段伪装成哈希的恒等变换，不要误当成需要复杂 key 的东西。

**e 的位域**：

```
0 < e < 0x1000000   → 实例字段, 低 24 位就是真实实例偏移
e == 0              → static / const(不占实例空间)
e >> 24 != 0        → static / const, 高字节是 FieldAttributes 位
                       其中 bit24 (0x1000000) 另有「有常量」含义(仅 74 个字段)
```

**static 判据换过两版，两次都栽在「只取一部分标志位」上**：

| 版本 | 判据 | 实例升序率 |
|---|---|---|
| v1 | `static = (e==0 \|\| hi==0x01)` | 83.8% ❌ |
| v2 | `static = (e==0 \|\| hi!=0)` | **99.92%** ✅ |

差别在于 `hi` 的 `0x02` / `0x04` 也都是 static 标记，不止 `0x01`。

**坐标系：偏移域含 16 字节 Il2CppObject 头**。引用类型和值类型的首字段都在 `0x10`，比 stock Il2CppDumper 的约定（值类型从 0 起）多一个常数 `0x10`。**给 IDA 建结构体时必须加这个偏移**，否则整个结构体错 16 字节。

**实测判据（全部来自数据内在性质，不依赖外部知识）**：

| 判据 | 实测 |
|---|---|
| 实例偏移按字段序严格升序无重复 | 47,789 / 47,828 = **99.92%** |
| 含 static 的类型里 static 全在前 | 14,747 / 14,747 = **100.00%** |
| 引用类型最小实例偏移 ≥ 0x10 | 56,341 / 56,341 = **100.00%** |
| 值类型最小实例偏移 == 0x10 | 12,433 / 12,434 = **99.99%** |
| 总量 | 327,555 实例 + 112,617 static/const = 440,172 |

`FEAT_FIELD_OFFSET` 的开关就是靠「锚点全部命中」自动判定的（`locate.cpp`）。

---

## 11. 枚举与常量值链（重点）

来源：`sub_14051A510`，2026-09-26 IDA 确认。

**枚举判据**：有一个名为 `value__` 的实例字段（全库 **8,123** 个）。
> 不要用 16B 记录的 kind 判枚举 —— 枚举在 16B 记录里是 `VALUETYPE(0x11)`，和普通结构体无法区分。底层类型 = `value__` 字段的类型，决定常量值的字节宽度。

```
enumTab[i]   = { u32 全局字段号(fieldStart+j), i32 值字节偏移, i32 未知(≈70) }   // 12B/条
key 严格升序(75,548 条)  → 可直接二分
值字节 = valBlob + slot, 按底层类型宽度读
slot 步长 = 值宽度(4 字节枚举步长 4, 8 字节枚举步长 8) → 槽位互不重叠
```

**当前输出**：8,123 个枚举 / 71,358 个成员，值全部从常量表直读（不是从偏移表推的）。

---

## 12. 方法代码地址：两张表的陷阱（重点）

> **本项目最贵的一个 bug**：99.9% 的方法指向了错误代码，而所有计数类自检全 PASS。代价是 2026-09-26 整整一轮返工。

exe 里有**两张** 8B/条、下标都是全局成员号的表：

| RVA | 统计特征 | 判定 |
|---|---|---|
| **`0x2870B90`** | 711,021 条界内地址**两两不同（零重复）**，100% 16B 对齐，散布全图 `0x6C04000..0x19DA4520` | ✅ **真方法指针表（MPT）** |
| `0x27D4DE0` | 649,615 个不同值，3,754 个地址被**最多 2,141** 个方法共用，7.5% 挤在 `0x43xxxx..0x47xxxx` 一条窄带 | ❌ **泛型/共享派发桩表** |

**两表只有 0.1% 相同** —— 用错表不是「少量偏差」，是全盘错误。

### 12.1 正确性判据（两条独立证据都必须成立）

**判据 1（统计）**：真 MPT 每个方法一个唯一代码体 → 重复地址必须为 **0**。
> 这就是 formulaCheck 的 `mpt-unique-body` 项。用错表时它会 FAIL（3,754 个重复地址，最大重数 2,141）。

**判据 2（语义字节）** —— 找语义**不可能搞错**的方法，然后看它的字节：

| 方法 | mi | 真 MPT 的字节 | 含义 |
|---|---|---|---|
| `System.String::get_Length` | 3042 | `8b 41 10 c3` | `mov eax,[rcx+0x10]; ret`，正好读 `m_stringLength`（偏移 0x10） |
| `System.String::get_Chars(int)` | 2917 | `85 d2 / 78 12 / 39 51 10 / 7e 0d / 0f b7 44 41 14` | `test edx` / `js` / `cmp [rcx+0x10],edx` 边界检查 / `movzx eax, word [rcx+rcx*2+0x14]` 读 `m_firstChar`（char 按 2 字节缩放） |

用错表时 `get_Length` 给的是 `56 48 83 ec 40 48 89 c8 ...`（0x40 栈帧的大函数）—— 一眼就能看出不对。

> **方法选择建议**：`get_Length` 这种「函数体只有一条指令、且必然读某个已知偏移的字段」的方法是最好的判据。带 `if`/循环/异常处理的方法不行 —— 桩函数（`*a5 = a1()`，从参数取真实方法指针再调）反编译出来也很大。

### 12.2 覆盖率

`711,021 / 733,442 = 96.9%`。剩下 22,421 条是 **0**（抽象/纯虚/未生成）。这是正常上限。

### 12.3 离线验证只需 exe + `.dat`，**根本不需要内存 dump**

7.1 的 exe **磁盘上就带全部离线验证所需的结构**（实测 2026-09-26）：

| 结构 | exe 上的状态 |
|---|---|
| 真 MPT（733,442 条） | ✅ 在 `.rdata` `0x2870B90`，与运行期映像**逐条 100% 相同**（归一化基址后） |
| 528B header | ✅ `0x27D4BD0`，magic `0x0059484D` |
| 16B 类型数组 | ✅ `0x2E1EA20`，抽 4096 条仅 20/65536 字节不同（运行期改写），kind 分布一致 |
| SSE 常量 | ✅ `0x39085D0`，`stride = 0x6B0B40C349AE61E5` |

**但 88B 程序集/镜像表不可替代** —— 它只在**运行期 CRT 堆**上，而指向它们的全局
在磁盘上是**加密的**：

```
g_52F8 asmTab  RVA 0x5AD52F8  ->  0xC8C166264AAF08AF   ← 密文，不是指针
g_5308 imgTab  RVA 0x5AD5308  ->  0x14C23807B71699FD   ← 密文
```

`ida_verify.py` 检查 4 就是断言这个 —— 它证明**堆表必须运行期抓**，
而**公式验证不需要它**（索引连续性只要 header + `.dat`，见 §20.2）。

**这条分界线的完整版见 [§17](#17-静态--运行期的确切分界线重点)。**

> 曾有两个错误结论：「exe 的 section 表是加密的」「exe 磁盘上是 0xFF」——
> 都源于 PE section 表起点多加了 `0x20` 的解析 bug，与地址换算笔误，**均不成立**。
> 见 §25 事故录 ⑥。

### 12.4 输出约定

```csharp
// RVA: 0x446360 Offset: 0x446360 VA: 0x140446360
public UnityEngine.Camera get_mainCamera() { }
```

- `RVA` **必须在行首** —— `tools/ida_apply_symbols.py` 的解析器是
  `RVA_RE = ^\s*//\s*RVA:\s*0x([0-9A-Fa-f]+)`，挪到行尾会让它失配、套符号应用 **0 个**。
- `Offset` 与 `RVA` 同值：纯内存模式没有文件偏移（与 7.0 及 Il2CppDumper 处理 runtime dump 的方式一致）。
- `VA` = `kImageBase + RVA`，**必须用 `%llX`**。`(unsigned)(kImageBase + rva)` 配 `%X` 只取低 32 位，会把 `0x140000000` 截成 `0x40000000`，在 IDA 里跳不动。
- `kImageBase` 是 PE 首选基址，与 IDA 装载基址无关；IDA 地址 = `idaapi.get_imagebase() + rva`，rebase 到任何值都不受影响。

---

## 13. 字段默认值：元数据里**没有**

`sub_140512DB0` 的 `bsearch`（0x140513D0D）给出三张表，基址对，但**用途判断是错的**。

| 用途 | hdr | 运算 | 常量 | 说明 |
|---|---|---|---|---|
| 索引表 | 428 | `−` | 103054637 | 8B/条 `{u32 key, u32 packed}`，按 key bsearch |
| 索引表长度 | 28 | `−` | 2131072890 | 元素数 = `(h32(28) − 2131072890) >> 3` = **2,165** |
| 值字节表 | 216 | `−` | 1927885444 | `+ 0x8D16CD7C`，`+4*dataIndex` 取值 |

```c
tabA = blob + h32(428) - 103054637;  n = (h32(28) - 2131072890) >> 3;
r = bsearch(&key, tabA, n, 8, sub_140525160);
if (r && (packed = r[1]) >= 0x1000000) {
    p = alloc16(8 * (packed>>24) + 23);              // 16B 对齐
    *(u32*)p    = packed >> 24;                      // size, 4B 字数
    p[1]         = tabB + 4 * (packed & 0xFFFFFF);   // 值指针（不解混淆）
}
```

**实测：值不是常量，是 RVA 列表。** 表 A 共 2,165 项，key 从 769 起**严格升序**
（0 违例），100% 满足 `packed >= 0x1000000`。把表 B 按 `4*dataIndex` 读出来，
字节明显是 **exe 内的 RVA**（如 `be 57 0a 08` → `0x080A57BE`），且都在
`GenshinImpact.exe` 有效范围内，相邻 key 的差值（6、1）正是「一串极短 stub 函数」。

**结论**：这张表是**默认接口方法实现（default interface member）的编译后方法体指针表**，
key = 接口的 16B 类型记录索引。**不是**字段默认值表。

真正的「有默认值」标志是 `FieldInfo.attrs` 的 bit24（74 个字段，见 §12.3），
而那 74 个字段的默认值来源**仍未找到**。

⇒ `FEAT_FIELD_DEFVAL` 保持关闭 —— 名字对应的功能一个都没实现，**宁可缺着**。

---

## 14. 已定位但未接入的表（留档）

| 用途 | hdr | 运算 | 常量 | 条目 | 状态 |
|---|---|---|---|---|---|
| 泛型实例缓存 | 472 | `^` | 0x1F85ABE5 | 12B | 语义未验证 → 见 §15 |
| 接口实现列表 | 516 | `−` | 450622139 | 4B | ✅ 已确认（§10.4） |
| 泛型参数 | 452 | `−` | 1518027399 | 6B | ✅ 索引确认（§10.4） |
| token→类型 | 320 | `−` | 1832561230 | 6B | 手写二分 |
| 泛型上下文 | 464 | — | — | 16B | `*(_WORD*)(v4+192)` 给条数 |
| 默认接口方法体 | 428 | `−` | 103054637 | 8B | ✅ 已确认，语义见 §13 |
| 14B 元素/置换表 | 368 | `^` | 0x7B3B96A2 | 14B | 结构齐但终点在堆 → §16 |
| 参数类型注册表 | 156 | `−` | 259975212 | 12B | 条数 = `(h32(156)−259975212)/12` |

**泛型实例缓存**（`sub_140512DB0` 两处 0x14051311F / 0x140513FB1）：
```c
gi   = blob + (h32(472) ^ 0x1F85ABE5);
a    = gi + 12 * typeRecIdx;
cls  = sub_1405238F0(*(u32*)a, a[+4]==-1?0:typeArr+16*a[+4],
                               a[+8]==-1?0:typeArr+16*a[+8]);
```
12B 记录 = `{u32 token, i32 typeIdxA, i32 typeIdxB}`，`-1` = 空槽。
key 是 16B 记录索引（`& 0x1FFFFFFF`）。**只覆盖两个类型参数**，语义未验证。

---

## 15. 泛型实参：为什么纯静态做不到（重点）

来源：`sub_1404E3CC0`（类型规范化）的 `switch case 0x15`（GENERICINST），
**逐条指令**（0x1404E3DC7 起）：

```asm
mov  rax, cs:qword_145AD4E98
mov  rax, [rax+8]                     ; base = *(u64*)(g_145AD4E98 + 8)
movsxd rcx, dword ptr [r15]           ; ⚠️ 有符号扩展 —— data 是 int32
shl  rcx, 5                           ; ×32
mov  rsi, [rax+rcx+8]                 ; p = *(u64*)(base + data*32 + 8)
cmp  r14d, [rsi]                      ; argCount = *(u32*)p
mov  rax, [rsi+8]                     ; args = *(u64*)(p+8)  -> Il2CppType*[]
...  逐个 sub_1404E3CC0(args[i]) ...
mov  ecx, [rax+rcx]                   ; 泛型类型定义索引
call sub_14051CD50                    ; -> Il2CppClass
```

32B/条记录：`+0x00` 泛型类型定义索引 / `+0x04` ? / `+0x08` 指向 `{u32 argCount; u64 argsArray; }` / `+0x10` ?

### 15.1 三条实测事实

| 事实 | 证据 |
|---|---|
| 16B 记录的 `data` 是**有符号 int32 下标**，不是 VA | 439,914 条 GENERICINST 里 438,463 条高 32 位 = 0；剩 1,451 条高位非 0 = **负数**（`movsxd` 证实），从 base 往回索引 |
| 16B 数组内部的 `data` 链**不是**实参列表 | `AttrListImpl.attrValues` 走 **18 跳**才到 `object`；`TimeZoneInfo.systemTimeZones` 走 **22 跳** |
| 表基址经过 `g_145AD4E98` 这个全局 | 该全局在磁盘 exe 上是**密文** |

### 15.2 全局块在磁盘上是加密的（已严格证实）

逐字节对比 exe 文件 vs 运行期映像（同一 RVA）：

| 区域 | 相同字节 |
|---|---|
| `[对照]` 528B header @0x27D4BD0 | **32/32** |
| `[对照]` 16B 类型数组 @0x2E1EA20 | **32/32** |
| 全局块 @0x5AD4E90 | 0/32 |
| 全局块 @0x5AD4EA0 / 0x5AD4F00 / 0x5AD5100 / 0x5AD52C0 / 0x5AD5400 | 0/32 |

对照组说明 PE 映射和读取路径都没错 —— **只加密了全局描述符块**。

### 15.3 该全局的**唯一写点** —— 结论：堆分配，静态不可达

`qword_145AD4E98` 在 `sub_140534B80`（巨型 init）里有 3 处引用，逐一解码后
**只有 1 处是写**（0x140535146），另 2 处都是读。写点上游：

```asm
b9 30 00 00 00                mov  ecx, 0x30          ; 48 字节
e8 …                          call <alloc>            ; ★ 分配
48 8d dd …                    lea  rcx, [rip+…]       ; 初始值
48 89 85 d0 02 00 00          mov  [rbp+0x2D0], rax   ; 存的是分配返回值
…
48 89 05 4b fd 59 05         mov  [qword_145AD4E98], rax
```

⇒ **`g_145AD4E98` 是一个 48 字节的堆描述符**，它指向的 32B/条数组同样在堆上。

### 15.4 结论（不再是猜测）

```
global-metadata.dat            ✗ 表不在这里   (82MB 全扫, 1 个假阳性)
GenshinImpact.exe 映像          ✗ 表不在这里   (按 32B 步长 + 7 重抽样扫, 唯一候选 argCount 恒 0)
g_145AD4E98 磁盘值              ✗ 是密文       (0/32 字节与运行期一致, 对照组 32/32)
g_145AD4E98 运行期值 = 堆地址    ✗ 纯静态拿不到
```

**所以 GENERICINST 类型实参对纯静态 dumper 是不可达的** —— 不是「缺公式」，
也不是「还没找到」，而是**数据只存在于运行期堆上**。

对照：`h32(368) ^ 0x7B3B96A2` 那张 14B 表走的是 `qword_145AD52B8`(header) +
`qword_145AD52C0`(blob)，**两者磁盘明文**，所以那条路才是纯静态可做的 ——
GENERICINST 与它是两类东西，**别混**。

> v6 走的是「纯内存」路线（注入后从 `base + 0x5AD4E98` 读，此时已解密且指向堆），
> 但实参下标换算仍未验证，故 `FEAT_GENERIC_INST` **强制关闭**，输出 `genericinst@N`。

---

## 16. 14B 元素表：结构齐了但终点在堆

同一个 `sub_1404E3CC0`，`case 0x13`(VAR) / `case 0x30`(MVAR) 走**另一条路**，
**不经过任何加密全局**，所以纯静态可解：

```c
tab = blob + 528 + (h32(368) ^ 0x7B3B96A2);      // 14B/条
e   = (data * 0x2F5C + 0x15DA179) & M32;
e  ^= 0x23B2C8D;
e   = ((e * 0x20091C5) >> 10) & M32;               // ⚠️ 32 位截断
idx = ((((e + 0x5AB3) & M32) ^ 0x570B)
        + (u16)tab[data*14 + 12] - 14487) & 0xFFFF;
arg = *(u64*)(arr + idx*8);
```

> 这正是 7.0 记在 `FEAT_ELEM_14` 的那张表 —— **7.1 的偏移是 `hdr+368`，
> 常数 `0x7B3B96A2`**，7.0 的 `hdr+72` 是错的。

### 16.1 为什么还不能用（两步都堵住）

1. **内容是高熵的**，前 10 条 `u32` = 1862612838 / 1079446023 / …，`u16@12` = 83 / 51032 / …
   没有可辨识结构。
2. **索引公式实测几乎是常数**：data = 0/1/2/35/104/231/359 全都算出 `idx=0`，
   765/1000 → 1，12345 → 52186。说明 `tab[data*14+12]` 那个 u16 是**关键扰动项**，
   去掉它索引就塌成常数 —— 这是一张**带键的置换/打散表**。

3. **即便解开置换表，取值终点仍在运行期**：
```asm
mov  rcx, [rdi]          ; rcx = *(u64*)a2       ; a2 来自 Class+56
mov  rcx, [rcx+8]        ; rcx = *(u64*)(rcx+8)  ; ★ 运行期对象
mov  rsi, [rcx+rdx*8]    ; rsi = arr[idx]        ;   在运行期数组里取值
```
⇒ 结构、基址、索引公式三样都齐了，**但终点是运行期对象**。`FEAT_ELEM_14` 保持关闭。

---

## 17. 静态 / 运行期的确切分界线（重点）

追完 GENERICINST 与 14B 表两条路之后，能力边界可以划清。判据很简单：**表基址的来源**。

| 来源 | 例子 | 静态可读？ |
|---|---|---|
| `g_52C0` = `blob + 528`，`blob` = 磁盘上的 `global-metadata.dat` | typedef / method / field / prop / event / param / iface / **枚举常量表** / **14B 置换表** | ✅ v6 全靠这一类 |
| `g_52B8` = exe 里 528B header（磁盘明文） | 全部 `h32(off) OP CONST` 公式 | ✅ |
| exe 里的静态数组（RVA 已知、文件里有数据） | 16B `Il2CppType` 数组 @0x2E1EA20、**真方法指针表 @0x2870B90** | ✅ |
| **exe 映像但落在加密全局块** | `g_5AD4E90` / `g_5AD4E98` 一族（磁盘 0/32 与运行期一致，对照组 32/32） | ❌ 磁盘上就是密文 |
| **运行期堆** | 泛型实例 32B 表、14B 表索引到的 `arr[]`、Class 池、字符串堆、**88B 程序集/镜像表** | ❌ 不在磁盘任何位置 |

⇒ **凡是终点落在后两类的特性，纯静态都做不了**。这不是「公式没找到」：

- GENERICINST 类型实参（82,662 行 `genericinst@N`）—— §15
- 14B 元素表的最终取值 —— §16
- 接口方法 slot —— §19.1（元数据里根本没有）
- 真正需要 Class 池 / 字段类型 / 泛型展开的运行期特性

⇒ 继续投入产出比最高的方向只剩两个：
1. **解密 `0x5AD4Exx` 全局块**（磁盘上就是密文，解开就等于多一个静态数据源），
   切入点 `sub_140534B80` 里对该块的解密循环；
2. **枚举剩余可静态拿下的表** —— 走 `g_52B8`/`g_52C0` 的那些
   （可按「引用了 `qword_145AD52B8` 且引用了 `qword_145AD52C0`」这个特征批量筛）。

> 注：v6 本身是**注入式**的，能读运行期堆，所以 88B 表拿得到。
> 但 §15/§16 那两条即使注入也要处理 Class 池二次解引用，成本远高于收益，故保持关闭。

---

## 18. 公式的寻找方法（双验证方法论）

**每个公式都必须过两关，缺一不可。**

### [A] 反编译定位

1. 在 IDA 找**访问函数**（不是初始化函数）。优先找「谁在读这张表」——从访问点反推比从初始化点正推容易得多。
2. 记下访问指令的**寻址形态**，例如
   `mov rax, cs:qword_145897138; mov rax, [rax+48h]; mov rax, [rax+r9*8]`
   → 表 = `*(regBase + 0x48)`，下标 = `r9`。
3. **差分法拿混淆常数**：
   - 在访问函数里找对 header 某个偏移的读（`mov eax, [rbx+118h]` 之类）
   - 记录它与「期望值」的差/异或
   - 换一个函数、同一个 header 偏移再差分一次，两次一致即确认
   - **换版本时这是唯一可靠路径**，不能沿用旧常数
4. 找「差分系数」：访问指令里常有 `imul`/`lea` 之类，记录被乘数（例：`35*ti`、`34782*i`）。乘数要确认 64/32 位。

### [B] 真机交叉验证

`formulaCheck` 自动执行，判据**只能来自数据内在性质**，不能来自「外部知识」。例子：

- 字段偏移：实例偏移按字段序升序、static 全在前、引用类型最小偏移 ≥ 0x10、值类型最小偏移 == 0x10
- 88B 表：类型区间首尾相接无空洞、Σ = 88,902
- 枚举：key 严格升序可二分、已知枚举锚点（`Sign.Negative = -1`/`Zero = 0`/`Positive = 1`、`UriPartial = 0/1/2`、`ConsoleColor.Black = 0`…）
- 字符串：已知类型名 `System.Object` / `System.Int32` / `UnityEngine.Vector2` 必须解出
- 计数一致性：Σ 各表条数 == 头部声明数

**为什么要双验证**：[A] 只能告诉你「这个访问点这样算」，不能保证「这个访问点就是你要的表」。[B] 能保证「算出来的东西自洽且符合 IL2CPP 的结构性事实」。两关都过才算定案。

> 2026-09-26 的 MPT 事故正是只过了 [B] 的弱形式（覆盖率 96% ✓、不同地址 649,615 ≥ 400,000 ✓）而漏掉了「零重复」这个强判据。**自检项要挑能真正区分对错的，不要只挑容易过的。**

---

## 19. 八项 7.0 特性的最终归属

| 7.0 特性 | 7.1 归属 | 依据 |
|---|---|---|
| 真实字段偏移 | ✅ **已交付** | §12，327,555 字段 |
| 字段定义 12B | 🟡 部分 | `hdr+144` 的 `+8` 用来取 attrBase，其余字段未解 |
| 枚举成员 | ✅ **已交付** | §11，8,123 枚举 |
| 字段默认值 | ❌ **元数据里没有** | §13；bit24 那 74 个是运行期缓存 static（§12.3） |
| 枚举字面值 | ✅ **已交付** | §11，同一张常量表 |
| 泛型实例展开 | ❌ **运行期堆** | §15 |
| **接口方法 slot** | ❌ **元数据里没有** | §19.1 |
| 数组/泛型元素 14B | ❌ **运行期** | §16：置换表在磁盘，终点 `arr[]` 是运行期对象 |

### 19.1 接口方法 slot：元数据里根本没有这个字段

`sub_140512DB0` 解析接口实现列表（0x1405130E1 起）：

```c
v34 = blob + h32(516) - 450622139;                       // 接口表, 4B/条
v35 = *(u32*)(v34 + 4*( ifaceStart + j )) & 0x1FFFFFFF;  // 16B 类型记录索引
*(_QWORD*)(v4 + 8*(j + ifaceCount) + 208) = v42;         // ★ 只存 Il2CppClass*
```

实测该表（`blob + 0xFB9040`）就是**一串 16B 记录索引**（`3870, 3872, 3873, 3876, …`），
**没有任何 slot / offset 字段**。slot 是运行期算出来的（`sub_1404E4DA0` 建
(type, method) 缓存，`sub_1404E6B70` 逐个比对签名做映射）。

⇒ `FEAT_IFACE_SLOT` 对 7.1 **不是「未移植」，是元数据里没有**。

---

## 20. 自检体系

两层，各管一段：

| 层 | 工具 | 何时跑 | 覆盖 |
|---|---|---|---|
| **权威** | `report.txt` 的 **58 项 formulaCheck** | 每次真机 dump | 产物级的全部语义 |
| **快查** | `tools/ida_verify.py` | 改常数后，秒级 | 4 项静态可算的结构不变式 |

### 20.1 formulaCheck（58 项 = 53 PASS + 5 SKIP）

跑在**真机**里（DLL 注入后随 dump 一起执行）。**改任何公式后必须 0 FAIL。**

| 组 | 项 |
|---|---|
| **方法地址** | `method-addr-coverage` / `method-addr-distinct` / `mpt-unique-body` / `mpt-coverage` |
| **初始化** | `header-magic` / `typeRec-rva` / `blob-size` / `blob-borrowed` |
| **表结构** | `image-count-75` / `asm-count-75` / `image[0]=mscorlib` / `typeCount-88902` / `asm88-chain` / `enumval-table` / `enumval-coverage` / `enumval-not-overreach` |
| **类型锚点** | `type-System.Object` / `type-System.Int32` / `Int32-isValueType` / `Int32.m_value` / `System.String` / `String.get_Length` / `Vector2.Dot` |
| **字段偏移** | `fieldOff-table` / `fieldOff-ascending` / `fieldOff-static-first` / `fieldOff-ref-no-header-clash` / `fieldOff-vt-min-0x10` / `Assembly-off-from-table` / `fieldOff-vs-layout` |
| **枚举锚点** | `ConsoleColor.Black` / `ConsoleColor.White` / `AttributeTargets.Assembly` / `AttributeTargets.All` / `RegistryHive.ClassesRoot` / `RegistryHive.Users` |
| **其他** | `event-count-628` |

**5 个 SKIP**（7.0 有、7.1 未移植，**不是失败**）：字段定义 12B / 字段默认值 /
泛型实例展开 / 接口方法 slot / 数组-泛型元素。各自原因见 §19。

> **SKIP 的传染性**：被跳过的特性若在某条路径上悄悄生效了（例如 const 字段的
> 「类型」实为常量槽号，输出看起来像正常类型），formulaCheck **不会**报警。
> 所以 SKIP 项对应的输出必须人工核对，见 §6.3 的 const 字段坑。

> 有 FAIL 就别信产物 —— `report.txt` 结尾会直接写
> 「*** 有 N 项 FAIL —— 公式或地址语义不成立, 别信产物 ***」。

### 20.2 `ida_verify.py` —— 免 bin 的离线快查（替代原 nativetest/idxprobe）

原 `nativetest` / `idxprobe` 依赖 gi_dump 产出的 `.bin`，目标版本不保证有。
本脚本**只依赖 `GenshinImpact.exe` + `global-metadata.dat`**，且**不需要 IDA**
（也能在 IDA 内跑）：

```bash
python3 tools/ida_verify.py <global-metadata.dat> [GenshinImpact.exe]
```

6 项检查，约 0.5 秒：

| # | 检查 | 拦截什么 | 不变式? |
|---|---|---|---|
| 1 | 528B header magic | 基址/版本错 | — |
| 2 | **真 MPT 界内地址零重复** | **拿错表** | ✅ 硬 FAIL |
| 3 | 桩表有大量重复 | 两表变得不可区分 | ✅ 硬 FAIL |
| 4 | 88B 指针全局是**密文** | 误以为能从 exe 抓堆表 | ✅ 硬 FAIL |
| 5 | **成员索引空间连续性** | **索引错位** | ✅ 硬 FAIL |
| 6 | 15 张表基址复算落在 blob 内 | `hdr+X OP K` 常数失效 | — |

**判定原则**：
* **结构不变式**（索引空洞/重叠、MPT 重复地址）—— 不成立直接 FAIL。换版本时这类量
  也不该变，变了就是公式错了。
* **统计量**（Σ methodCount、MPT 界内条数、各表偏移）—— 只与 7.1 基线比对并标
  **DRIFT**，不 FAIL。换版本时它们本来就会变。

**为什么检查 5 不可替代**（这是删掉 idxprobe 唯一的实质损失，已用脚本补上）：
索引错位不改变方法**总数**，所以 58 项 formulaCheck 全部照常 PASS，症状只是
「方法指向了别的函数」。2026-09-26 的 MPT 事故正是这一类：覆盖率 96% ✓、
不同地址 649,615 ✓，全绿，但 99.9% 方法地址是错的。

> 注：§15/§16 说明纯静态拿不到的东西（泛型实参、14B 表终点）**也无法离线验证** ——
> 它们只存在于运行期堆。这类缺口靠 §17 的分界线表判断，不靠自检。

### 20.3 换版本工具链：`reloc_ida.py` → `found.txt` → `verify_formulas.py`

§20.2 的 `ida_verify.py` 回答「**当前这套常数对不对**」；
这一节的三件套回答「**换版本后新常数是多少、对不对**」。两者职责不同，都要跑。

```
      IDA 里                              终端
┌──────────────────┐                ┌────────────────────┐
│ reloc_ida.py     │  写 found.txt  │ verify_formulas.py │
│ (发现新值)        │ ────────────> │ (判定对错 + 对齐)    │
│ 四层, 见下表      │                │ 读 exe/.dat/dumper.h│
└──────────────────┘                └────────────────────┘
```

#### 20.3.1 `reloc_ida.py` —— 四层发现

只依赖**跨版本稳定的结构特征**，不含任何硬编码 RVA 或名称。IDA 9.x（`ida_nalt.get_imagebase`）。

| 层 | 找什么 | 判据（全部与版本无关） | 7.1 实测 |
|---|---|---|---|
| 1 | header | 魔数 `MHY\0` 字节串扫描（**不能按 u32 值匹配**，大小端变过） | `0x27D4BD0` ✅ |
| 2 | metadata 全局槽 | 顺着 header 数据的**唯一引用**找到初始化函数，解析 `lea`+`mov cs:全局,reg` 配对 | 5 个槽全对 ✅ |
| 3 | 代码指针表 | 容忍滑窗 → 按重复率分带 → 起点回溯精修；**值必须零或指向可执行段且 16B 对齐** | MPT `0x2870B90` / 733,442 ✅ |
| 4 | 表常数 | 寄存器族级数据流跟踪，解出 `h32(hdr+disp) OP K`；**按共用函数数排序** | 12 条，命中 6/12 |

第 3 层的「可执行段」约束是关键：MPT 全部 733,442 项**零个**指向数据段，靠这条把
候选起点从 `0x2870B78` 精确钉到 `0x2870B90`（前 3 项指向 `.data`）。

第 4 层有两种编译形态，都要认（7.1 真实汇编）：

```
形态 A（先读字段再运算）        形态 B（先装常数再读字段）
  movsxd rsi, [rdx+19Ch]          mov  esi, 0EC48AB9Fh
  xor    rsi, 30F4D28Eh    ⟵      add  esi, [rdx+0B4h]      ⟵
  add    rsi, rax                  movsxd rsi, esi
                                  add  rsi, rax
```

> **`+` 与 `-` 是同一张表的两种写法**，互补数之和 = `0x100000000`。
> `dumper.h` 统一用 `'-'` 风格。脚本在行尾直接给出换算结果。
> 7.1 实测 `iface`/`typedef`/`method` 三张表两种写法并存，互补数精确相加为 `0x100000000`。

**已知短板（7.1 上实测，别指望它全覆盖）**：
* 15 张表只自动认出 **6 张**。`mptr`/`thunk` 本来就是**直接 RVA 常量**（`kRvaMethodCodePtrs`），
  压根没有 header 公式，脚本不去找它们是对的。
* 其余 8 张缺的是**访问形态**不是扫描量 —— `limit` 从 600 提到 1500 只让前两名
  （`0x1D8` 1421 次、`0x204` 1396 次）涨了频次，没带来新表。仍需人工补。

#### 20.3.2 `found.txt` —— 两个脚本之间的中间文件

`reloc_ida.py` 第 4 层结束时自动写到 `tools/found.txt`。**你不需要手动做任何事**，
它是给 `verify_formulas.py` 自动读的，同时也方便人工核对和跨版本 diff。

```
hdr+0x<disp>  <op> 0x<K>   <共用该常数的函数数>
```

```
hdr+0x1D8   ^ 0x1F85ABE5   1421
hdr+0x204   + 0xE5240D45   1396   等价于 '-' 0x1ADBF2BB
hdr+0xB4    + 0xEC48AB9F   18     等价于 '-' 0x13B75461
hdr+0x19C   ^ 0x30F4D28E   7
```

| 列 | 含义 |
|---|---|
| `disp` | header 内的**字节偏移**（不是 u32 下标；15 个真值 144..516 全 < 528） |
| `op` | `^` 异或 / `-` 减去 / `+` 加上 |
| `K` | 混淆常数 |
| 频次 | **判断真伪的主要信号**。3 次的多半是巧合配对，1400 次的是铁证 |

`+` 行按补数换算好再填 `dumper.h`：

```cpp
// found.txt:  hdr+0x204  + 0xE5240D45  ->  等价于 '-' 0x1ADBF2BB
static constexpr TableSpec kT_iface = { 0x204, '-', 0x1ADBF2BBu };
```

**跨版本 diff**（每版留一份）：

```bash
diff 7.1/tools/v6/tools/found.txt 7.2/tools/v6/tools/found.txt
```

| diff 现象 | 含义 |
|---|---|
| 三值全变 | 混淆常数换了，正常照抄 |
| `disp` 变、表还在 | header 字段顺序调整，要复查记录结构有没有跟着变 |
| **多出新条目** | 有新表访问器，通常意味着有表要接 |
| **某条消失** | 该版本访问形态变了（寄存器分配/编译器），需人工补 |

#### 20.3.3 `verify_formulas.py` —— 免 IDA 逐条判定

```bash
python3 tools/verify_formulas.py            # 默认路径自动向上找
python3 tools/verify_formulas.py --json     # 机器可读
```

**只依赖 `GenshinImpact.exe` + `global-metadata.dat` + `dumper.h`，不需要 IDA、不需要 `.bin`。**
直接从 `dumper.h` 里正则抠出全部 `constexpr` 和 `kT_*` 规格（记录大小从注释
`// 70B/条` 里取，表结构改了校验器自动跟上），逐条解公式并判定：

| 判定 | 含义 |
|---|---|
| **FAIL** | 偏移越界 / `field` 不在 528B 内且 4 字节对齐 / 读不出项 |
| **WARN** | 偏移 `< 528`（**指进 header 区，常数很可能写错**）/ 2 的幂 stride 未对齐 / 首条越界 |
| **PASS** | 偏移落在 blob 内且对齐 |

另外还查：header 魔数、Il2CppType 数组 RVA、**真 MPT 全表扫描**（界内地址零重复）、
88B 堆表（静态必然读不到真值，只做提示）、以及 `found.txt` 与 `dumper.h` 的逐条对齐。

退出码：`0` = 无 FAIL，`1` = 有 FAIL，`2` = 环境/用法错误。

**7.1 自校验基线**：`PASS 21 / WARN 13 / FAIL 0`。其中校验器算出的
**界内 711,021、零 22,421、重复 0** 与 §12 人工记载的基线一字不差 —— 说明它本身可信。

7.1 上 `found.txt` 的 12 条命中 **6**：`iface` `typedef` `method`（`+`/`-` 等价）
+ `enumval` `enumvalblob` `tokentype`（写法完全一致）。

#### 20.3.4 三条待你确认的遗留告警

脚本如实报出，但这三条我判断不了对错：

| 告警 | 内容 |
|---|---|
| `kT_tokentype -> 0x0` | 解出的偏移落在 header 区。`reloc_ida.py` 独立发现 `0x19C ^ 0x30F4D28E` 与 `dumper.h` **写法完全一致**，所以**不是提取错误，是公式本身如此**。它在 `sub_1404B1570` 里被当 bsearch 表基址用（8 字节元素） |
| `kT_field` 未按 8B 对齐 | `-> 0x8D07B4` |
| `kT_param` 未按 8B 对齐 | `-> 0x38A5C6C` |

4B/16B 步长的表全部齐整，只有这两个 8B 的不齐。可能是正常的（表前面有别的结构），
也可能是常数有偏差。

#### 20.3.5 完整 7.2 迁移流程

```
1. IDA 载入 7.2 的 GenshinImpact.exe
2. 跑 tools/reloc_ida.py
     [2/5] 抄 5 个全局槽 RVA        -> dumper.h kRvaHeaderPtr / kRvaMappedMeta / kRvaTypeStruct
     [3/5] 抄主 MPT 候选 RVA        -> dumper.h kRvaMethodCodePtrs
                                    ⚠️ 长度必须等于方法数，且界内零重复
     [4/5] 看 found.txt，抄 kT_*     -> 记得 '+' 换算成 '-' 补数
3. python3 tools/verify_formulas.py
     ⚠️ FAIL 必须清零；每条 WARN 逐个确认是「版本正常变化」还是「常数写错」
4. python3 tools/ida_verify.py <dat>      # 6 项结构不变式必须全 OK
5. 真机注入 -> 53 PASS / 0 FAIL / 5 SKIP
6. 核对产物：与上一版 diff，确认只有预期变化
```

第 2 步抄不出来的表（7.1 上是 8/15）按 §18 方法论人工补：
`imul` 找记录大小 → 差分 header 偏移 → 两个函数交叉确认。

### 20.4 `ida_apply_symbols.py` —— 把 dump 的信息灌回 IDA

原版只做一件事: 按 rva 重命名函数。dump.json 里其余信息全部闲置。现版本把能恢复的都恢复:

| 记什么 | 写进 IDA 的形式 | 数据来源 | 7.1 实测条数 |
|---|---|---|---|
| 方法名 | 符号 `Cls__method` | `types[].methods[]` | 711,021 |
| 方法签名 | 函数可重复注释 `System.Void Cls::m(int a)` + `flags` | `return` / `params` / `flags` | 711,021 |
| 类型信息 | 函数可重复注释的多行块 | `types[]` 全部字段 | 74,616 |
| **字段真实偏移** | 类型块里的 `+0x20 name : type` | `fields[].offset` | — |
| **属性访问器** | 写进 **getter/setter 地址**的注释 | `properties[]` | 127,709 |
| **事件访问器** | 写进 **add/remove/raise 地址**的注释 | `events[]` | 1,180 |

**属性/事件的访问器在 JSON 里是全局方法下标, 不是 rva。** 脚本先按 type 顺序把
所有 `methods[]` 拼起来建「下标 → rva」表 —— 实测拼接长度 **733,442** 与
`meta.methodCount` 精确吻合, 证明拼接顺序就是全局下标顺序。

映射正确性用两条**与版本无关的不变式**验证(7.1 实测):

| 不变式 | 结果 |
|---|---|
| 访问器下标落在**所属类型自己的**方法区间内 | 132,189 / 133,621 = **98.93%** |
| 解出的 rva 是合法 MPT 项(映像内且 16B 对齐) | 128,889 合法 / 4,732 解出 0(抽象方法) / **非法 0** |

> 剩下 1.07% 的越界是显式接口实现(访问器归属另一个类型), 属正常。

类型块注释长这样:

```
Class: System.Locale
Image: mscorlib
TypeDefIndex: 5
methods=8 fields=2 properties=2 events=1 interfaces=1
interfaces: System.IDisposable
--- fields (2) ---
  +0x10    m_x : int
  static   S_1 : string  [static,const]
--- properties (2) ---
  Len : int   get=1 set=-
--- events (1) ---
  Ev : EventHandler   add=4 remove=5 raise=-
```

**三个刻意的设计取舍**

1. **注释用「可重复注释」而不是函数注释** —— 函数注释会触发 IDA 对 71 万个函数做
   重量级原型/SP 分析, 实测能卡死整库。可重复注释不触发, 但一样能在函数视图看到。
2. **批量应用时关掉自动分析**(`ida_auto.enable_auto(False)`), 结束再开并 `auto_wait()`。
3. **不自动设函数原型** —— `idc.SetType` 71 万次同样会拖垮 IDA 且容易触发
   栈帧重算。签名以注释形式保留, 需要原型时手工对少量关键函数设。

**幂等**: 只重命名自动名(`sub_`/`nullsub_`/`unk_`/`locret_`/`def_`/`jpt_`/`loc_`),
不覆盖手工命名; 注释内容相同则跳过。可安全重复运行(实测第二次 0 命名 0 注释)。

**必须防「非法 UTF-8」**: 那 1,783 个含控制字符的混淆名, 如果此前被别的工具写进过
注释或符号, IDA 的 Python 绑定在**返回**时就抛
`UnicodeDecodeError: 'utf-8' codec can't decode byte 0xc2 ...`。
所以本脚本把**所有返回字符串的 IDA 调用**都包了一层 `_ida_str()`,
并且每个地址单独 try/except —— 一个坏地址不会中断整批 71 万条。
读取失败时当作无旧内容, 直接用干净文本覆盖那堆垃圾字节。

**`dump.json` 优于 `dump.cs`**: 本游戏有 **1,783 个混淆方法名解码后内嵌控制字符**
(含 `\n`), 写进 `dump.cs` 会把一条逻辑行劈成多条物理行。实测:

| 路径 | 解出的方法数 |
|---|---|
| `dump.json` | **711,021**(控制字符被转义成 `\uXXXX`, 一个不丢) |
| `dump.cs` | 710,773(+248 个签名拼接后仍失配) |

所以**优先用 `dump.json`**。`dump.cs` 路径保留是为了兼容, 脚本会自动打印告警。

## 21. 派生规则（不是混淆）
以下不是混淆原语，是**布局/语义规则**，源自 v4 的穷举验证。

### 21.1 类型级修饰符：元数据里**没有**

对 typedef 70B 全部 69 字节 × 16 个位 × {原值, 取反}，叠加
{字节交换, 每字节位反转, 16 位反转, 取反, 移位} 六种变换，以 15 个已知类型
（String/Math/Type/Exception/Int32/Object/IDisposable/Attribute/Console/Enum/
IEnumerator/IComparable/Delegate/StringBuilder/Array）为真值：

```
abstract 0 处   sealed 0 处   vis0/vis1/vis2 0 处   iface 0 处
```

方法级 flags 完全正常且是标准 `MethodAttributes`。
→ 构建时把**类型级 TypeAttributes 归一化丢弃**了。
`dump.cs` 里类型统一渲染成 `public class X` 是**符合实际的**，不是偷懒。

### 21.2 基类：静态解不出

`typedef+16` **不是基类**：15 个已知类型（含 `System.Object` 自己）的 `+16` 原始值
**全部相同** = `0x7447A1AB`。

- `− 1950851500` → 恒得哨兵值，偶尔（2,901 个）落成有效索引但是噪声
- `− 0x7447A038` → 恒得 371（System.Object），会输出 88,896 行**错误**继承
- 全文件扫 4B 基类表（10 组已知父子对约束，加性/异或 bias 各一遍）→ **0 命中**

⇒ 纯静态拿不到基类。`dump.cs` 的 `: Base` 来自 v6 的 `TypeParentName`（另一条路径），
不可靠时留空。

### 21.3 字段 static 启发式（仅对值类型有效）

元数据无字段 flags。唯一**可证明**的静态判据：

> **值类型不可能包含自身类型的实例字段** → struct 内部「字段类型解析回本类型」必然 static
> （`Vector2.upVector` / `Vector3.forwardVector` / `Quaternion.identity` 都是这类）

**该判据不能用于 class**（`StringBuilder.m_ChunkPrevious` 就是同类型实例字段）。
条件方向写成 `!vt` 会让 `Vector3` 的 9 个 static 字段全被分配实例偏移
`0/12/24/…/108`，把 `x/y/z` 挤到 `120/124/128`。

> v6 走的是 §12 的 `fattr4` 真实偏移表，不需要这个启发式。保留在此是因为它是
> 「无字段 flags」这一事实的独立佐证。

### 21.4 接口 / 泛型：索引语义已确认（class builder 反编译）

**接口**（`sub_140512DB0`）：
```c
v34 = blob + h32(516) - 450622139;                       // 接口表, 4B/条
v35 = *(u32*)(v34 + 4*((*(int*)(typedefRec + 32) ^ 0x2E8C0EB8) + i)) & 0x1FFFFFFF;
if ( *(u32*)(...) & 0xE0000000 == 0xC0000000 ) break;    // 终止符
cls->ifaces[i] = sub_14051D330(v35);
```
起始下标 = `typedef+32 ^ 0x2E8C0EB8`；条目值 `& 0x1FFFFFFF`。

> v3 当初解不出来的原因：用了 `typedef+54` / `+69`（那两个是**别的**语义），
> 不是 `+32`。

**泛型参数**：
```c
gp  = blob + h32(452) - 1518027399;                       // 6B/条 {u32 typeIdx, i16 nameIdx}
idx = (u16)(i + (*(u16*)(typedefRec + 60) ^ 0x43DA));    // 起始 = typedef+60 ^ 0x43DA
```
**参数个数不在 typedef 里**，而是从**声明类的 `Class+0xC0`** 继承
（`v13 = *(_WORD*)(declaringCls + 192)`）—— 静态侧确实找不到「个数字段」。

---

## 22. 当前功能开关状态

```
[on ] 真实字段偏移    7.1 = hdr+296^0x0F92DC85, 经 desc12[hidx4[ti]]+8 索引; 偏移域含 16B 对象头
[off] 字段定义 12B    7.1 = hdr+144+0x0B7255040 (每类型描述符), 已用于取偏移, 其余字段未解
[on ] 枚举成员        7.1 = 字段表本身(按 value__ 判枚举) + 常量表 hdr+316^0x593DE464
[off] 字段默认值      7.1 表已定位(hdr+428/216), 但值语义是 RVA 列表不是常量
[on ] 枚举字面值      同一张常量表: 值字节在 hdr+160^0x3F525210, 按底层类型宽度读
[off] 泛型实例展开    7.1 静态表无实参; 堆表链已定位但实参下标换算未验证 -> 强制关闭
[off] 接口方法 slot   7.1 元数据里没有: 接口表只存 Il2CppClass, slot 运行期算
[off] 数组/泛型元素   未移植
```

**统计基线**（真机 + 离线一致）：

```
typeCount   88,902        fields       440,172   (327,555 有偏移 / 112,617 static)
methods     733,442        props        115,596
events        628         interfaces    25,981
枚举         8,123 / 71,358 成员
方法地址     711,021 (96.9%), 唯一, 零重复
产物         dump.cs 115MB / dump.json 136MB
```

---

## 23. 已知缺口

| 缺口 | 现状 | 备注 |
|---|---|---|
| **泛型实参** | 强制关闭，输出 `genericinst@N` | 堆表链已定位（`kRvaGenericDesc`），但**实参下标换算未验证**。曾误信一个「指针差 = typeArray」的推导，导致 RVA 落到 blob 之外 + 指数递归爆栈。递归护栏已修，但换算仍无可靠判据 |
| **const 字段默认值** | 关闭 | 表已定位（hdr+428/216），但值语义是 **RVA 列表不是常量**。`dump.cs` 里 const 字段的**类型不可信**（存的是常量槽号） |
| **字段定义 12B** | 部分 | 只用了取偏移的部分，其余字段未解 |
| **接口方法 slot** | 关闭 | 7.1 元数据里没有，slot 是运行期算的 |
| **数组/泛型元素 kind 0x14** | 未移植 | 7.0 有，7.1 未做 |
| **mojibake 名字** | 0.04% | metadata 里本身就是坏的。BOM 修不了 |
| **kind 0x16 / 0x4014** | 占位 | |
| **运行期对象信息** | 未做 | GameObject 遍历方案（静态槽方案见旧 `docs_engine.md` §6） |

---

## 24. 7.2 迁移手册

### 24.1 总体流程

```
0. 先跑一遍 7.1 的产物做对照基线（58 项 = 53 PASS / 0 FAIL / 5 SKIP 的 report.txt 存好）
1. IDA 载入 GenshinImpact.exe 7.2
2. 跑 tools/reloc_ida.py  →  发现 header / 全局槽 / MPT / 表常数，自动写 tools/found.txt
3. 抄 dumper.h 常量区：[2] 全局槽 + [3] 主 MPT + [4] found.txt 里的 kT_*
                          （'+' 要换算成 '-' 补数；抄不出来的表按 §18 人工补）
4. python3 tools/verify_formulas.py  →  FAIL 必须清零，每条 WARN 逐个确认
5. python3 tools/ida_verify.py <dat>  →  6 项结构不变式必须全 OK
6. 真机注入 → 53 PASS / 0 FAIL / 5 SKIP + IDA 抽查
7. 核对产物：SHA 与上一版 diff，确认只有预期变化
```

每一步的命令、判读方法、以及 7.1 上已知的误报都在
[§20.3](#203-换版本工具链reloc_idapy--foundtxt--verify_formulaspy)。

> 7.1 实测：`reloc_ida.py` 能自动认出 15 张表里的 6 张、`mptr`/`thunk` 因为本就没有
> header 公式（直接 RVA）不在其列。**别把「脚本没报出」当成「表不存在」**。

### 24.2 必须重新定位的四类东西

`tools/reloc_ida.py` 提供了脚本化入口，7.1 上的实际产出见 §20.3。

| 类别 | 目标 | 7.1 的值（对照用） | 脚本化程度 | 定位手法 |
|---|---|---|---|---|
| **A. 指针全局** | header / blob / 88B 表 / MPT | `0x5AD52B8` / `0x5AD52C0` / `0x5AD52F8` / `0x2870B90` | **全自动**（第 1~3 层） | 魔数扫 header；顺引用找初始化函数拿全局槽；滑窗+重复率分带找 MPT |
| **B. 类型记录数组** | 16B 数组 RVA | `0x2E1EA20` | 手工 | 从「kind 分发函数」`movsx byte [rec+0Ah]` 切入 |
| **C. 表访问器** | 每张表的 `hdr+X OP K` | 见 §4 | **半自动**（第 4 层，7.1 命中 6/15） | 寄存器族级数据流跟踪 + 按共用函数数排序；漏的按 §18 手工补 |
| **D. 混淆原语** | `field_key` / `method_key` / … | 见 §7 | 手工 | 找「读记录后 XOR 一个由 index 推出的值」的指令 |

### 24.3 优先重验的高危项（按踩坑代价排序）

**① 两张 8B 指针表必须重新区分**（§12）

每版都要重跑两条判据：
- 统计：真 MPT 零重复、100% 16B 对齐、散布全图
- 语义：`System.String::get_Length` 的字节必须是 `8b 41 10 c3`（或等价的 4 字节小函数）

**如果新版本找到的表重复地址不为 0，那是桩表，不是 MPT。**

**② blob 指针的 −528**

7.1 的 `g_52C0` 指 header **之后**。7.2 可能变成指内容起点（7.0 就是那样），或者偏移量变了。判据：减 528 后 header 魔数 = `0x0059484D`、blob 长度 = 0x4EE4538 量级、字符串能解出合法标识符。

**③ 88B 表的 stride 和链式不变式**

stride 可能变（7.0 是 40/44，7.1 是 88）。不变式必须严格校验：

```
ts[0] == 0,  ts[i] + tc[i] == ts[i+1],  每条 tc[i] > 0
```

**只查「首尾相接」不够** —— tc 全 0 的退化表能骗过它。`tc[i] > 0` 这条必须有。

**④ 注入时机 / 88B 表可能没填完**

`g_52B8/g_52C0` 就绪 **不等于** 88B 表填完。表现是 `typeCount=0` 的空 dump。dumper 已把这种情况当「未就绪」处理（`return false` → 等待循环继续轮询），看到超时就看 `init-timeout.txt` 的 `last=`：

- 表指针**在变** → 只是还没填完，继续等
- 表指针**一直不动且恒为 75 条** → 全局 RVA 指错了，回 IDA 重定位

**⑤ 成员索引公式**（§5）

`methodStart` 的偏移和常数几乎必变。改完必须跑 `ida_verify.py` 检查 5（空洞 = 0、重叠 = 0）。这条**不能靠 formulaCheck** —— 索引错位时它全 PASS。

**⑥ 混淆原语的位宽**（§7）

`* i` 的乘法**必须确认 64 位**。截断后高位索引全解错，且症状只是「部分名字乱码」，总数不变。

**⑦ 字段偏移坐标系**（§10）

含 16 字节 Il2CppObject 头，首字段 0x10。确认方法：看 `fieldOff-ref-no-header-clash`（引用类型最小偏移 ≥ 0x10）和 `fieldOff-vt-min-0x10`（值类型 == 0x10）两项是否都 100%。

**⑧ static 判据要用全部标志位**（§10）

`hi != 0` 而不是 `hi == 0x01`。用 v1 那个判据实例升序率只有 83.8%，一眼就能看出来。

**⑨ AccessFlags 是 3 bit 字段**

`(flags & 0x7) == 0x1` → private。**`0x0040` 是 Virtual，不是 private。**

### 24.4 可以直接沿用的部分

- 架构：纯内存初始化、流式 `TypeSink` 解码（逐类型解完立刻写盘释放）、`dump.cs` / `dump.json` 格式
- 13B Il2CppType kind 枚举（除 7.0→7.1 已无变化，但**新版本可能加 kind**）
- 工具链：`ida_verify.py` / `ida_apply_symbols.py` / `reloc_ida.py`（三者都不依赖 .bin）
- 自检项清单：58 项全部保留，只调阈值

### 24.5 30 秒快查（改完常数先跑这个）

```bash
python3 tools/ida_verify.py <global-metadata.dat> [GenshinImpact.exe]
```

重点看两行：

* `[2/3] 真MPT 重复=0` —— 拿错表会在这里炸
* `[5] 索引空间无缝连续: 空洞=0 重叠=0 起点=0` —— `methodStart` 公式错会在这里炸

全 OK 再去构建 DLL、注入真机看 58 项 formulaCheck。

---

## 25. 事故录

> 留着是为了避免重犯。这六个里有三个是「所有计数类自检全 PASS 但结果全错」。

### ① 两张指针表搞反（最严重）

- **症状**：99.9% 方法指向错误代码；`get_mainCamera` 指向泛型派发桩；同类型里 `set_isCulled` 和 `Start` 地址相同
- **为什么没被拦住**：`method-addr-coverage`(96%) 和 `method-addr-distinct`(649,615 ≥ 400,000) **都 PASS**。代码地址空间太稠密，随便一个野地址也大概率落在真函数上
- **教训**：自检项要挑**能真正区分对错**的。「零重复」能区分，「地址数量够多」不能。**语义字节判据**（`get_Length` 应为 4 字节函数）比任何统计都可靠
- **预防**：`mpt-unique-body` 常驻 formulaCheck；`dumper.h` 常量区写明两张表的区别

### ② 退化表骗过校验

- **症状**：真机 `typeCount=0`，产物 416 字节，21 项 FAIL
- **原因**：`DecodeAsm88` 只查「首尾相接」。tc 全 0 时链条退化成「所有 ts 相等」，**恒真**
- **预防**：每条 `tc[i] > 0`；`typeCount==0` 视为「未就绪」返回 false 让轮询继续

### ③ `%X` 截断 64 位 VA

- **症状**：`VA: 0x40446360`，正确应为 `0x140446360`。IDA 里 Alt+Q 跳不动
- **原因**：`(unsigned)(kImageBase + m.rva)` 配 `%X`，只取低 32 位，`0x140000000` 被截掉
- **为什么没被拦住**：RVA 本身小于 `SizeOfImage`，所以 RVA 是对的，**只有 VA 错**。肉眼极难发现
- **预防**：所有地址一律 `%llX` + `(unsigned long long)`。`addr-va-selfcheck` 这类自检项值得加

### ④ AccessFlags 用错位

- **症状**：所有方法可见性都是错的
- **原因**：`0x0040` 是 **Virtual**；访问性是 `& 0x7` 的 3 bit 字段
- **预防**：对照 .NET `MethodAttributes` 定义，不要凭直觉取单个 bit

### ⑤ 格式改动破坏下游脚本

- **症状**：`dump.cs` 改成 `// VA: ... RVA: ...` 打头后，套符号应用 **0 个**
- **原因**：`ida_apply_symbols.py` 的 `RVA_RE = ^\s*//\s*RVA:` 要求 `// RVA:` 在行首
- **预防**：改 `dump.cs` 格式前先 grep 下游脚本的解析正则；改完用真实正则跑一遍匹配数

### ⑥ 验证脚本自身的算术错误

- **症状**：连续报「IDA 里没有函数」「exe 磁盘上是 0xFF」
- **原因**：手算十六进制加法时在 `0x140` 后面多插了一个 `0`（`0x140000000 + 0x93720A0` 应为 `0x1493720A0`），连续查了 4 个错误地址
- **预防**：地址换算**一律用工具算，不要手算**。python 里 `f"0x{B+r:X}"` 一行搞定

---

## 26. 运行期结构留档（不参与纯内存路径）

以下来自 v4 的 `sub_14051*` 系列反编译。v6 是注入式，理论上能用；实际未走这条路，
因为 §15/§16 表明要处理 Class 池二次解引用，成本远高于收益。**留档供将来需要时参考。**

### 26.1 `Il2CppClass`（`sub_140512DB0` class builder）

变长对象；接口数组内联在 `+0xD0`。**父类/声明类存的是 Class 池内的字节偏移**
（要加池基址 `*(u64*)(base + 0x5AD4E90)` 才是 `Class*`）。

| 偏移 | 字段 | 确认依据 |
|---|---|---|
| `+0x08` | GC 描述符（哪些字段含引用） | `sub_140557260(cls[0xBA], bitmap, fieldCount)` |
| `+0x20` | `MethodInfo*[]` | `SetupMethods`: `mov [r14+20h],rbx` |
| `+0x28` | `FieldInfo[]`（32B/条） | `SetupFields`: `mov [v3+40],v19`（40=0x28） |
| `+0x38` | `u32*` 类型索引 | `sub_14051CD50(*(u32**)cls[0x38])` |
| `+0x98` | **70B typedef 记录指针** | `mov rcx,[r14+98h]` → `movsxd r10,[rcx+0Ch]` → `xor 0x4D8127F2` |
| `+0xAC` | 声明类（外层类）池内偏移 | 与 0xB0 同模式 |
| `+0xB0` | **基类**池内偏移 | `if (cls[0xB0]) sub_140512DB0(cls[0xB0] + pool)` |
| `+0xBA` | 实例大小（dword） | 判引用类型看低 16 位 |
| `+0xBC` | 字段偏移记录的 u16 下标 | 索引 §12 的表 |
| `+0xBE` | 接口个数 | `cls[8*(i+cnt)+0xD0]` |
| `+0xC0` | 泛型参数个数 | 从**声明类**继承 |
| `+0xC2` | 方法个数 | `movzx ebx, word ptr [rcx+0C2h]` |
| `+0xD0` | 接口数组（内联，`Class*[]`） | `*(QWORD*)(v4 + 8*(v31+cls[0xBE]) + 208)` |

**标志字节**（此前写错过，已按反编译更正）：

| 字节 | 位 | 含义 |
|---|---|---|
| `+0xC8` | bits 4-6 | `log2(实例大小)` |
| | bits 1-3 (`0x0E`) | **泛型实例标记**（`cls[200] & 0xE` → 泛型实例化路径） |
| | bit 7 (`0x80`) | 已构建完成 |
| `+0xC9` | bit 1 (`0x02`) | 泛型参数容器 |
| | bit 4 (`0x10`) | 已初始化（函数入口重入保护） |
| | bit 5 (`0x20`) | 构建中 |
| `+0xCA` | bit 0 | 显式布局 |
| | bit 2/3/4 | 泛型参数已建 / 字段已建 / 跳过字段偏移 |

> ⚠️ **`+0xC8` bits 1-3 不是可见性，是泛型标记。** 类型级
> `public/internal/abstract/sealed` 在这个 Class 结构里**也没找到** —— 与 §21.1 的
> metadata 穷举结论一致：构建时确实把这组语义丢了。
> 所以 `dump.cs` 里类型统一渲染成 `public class X` 是**符合实际的**。

### 26.2 `Il2CppMethod`（56B，`sub_140514630` SetupMethods）

`+0x0` name / `+0x8` declaring / `+0xC` slot / `+0x10` methodIndex /
`+0x18` flags / `+0x28` codePtr / `+0x30` methodPointer / `+0x38` invoker /
`+0x48` returnType / `+0x50` paramStart / `+0x58` genericContainer /
`+0x60` declaringType / `+0x68` parent。

### 26.3 `Il2CppField`（32B，`sub_140512870` SetupFields，指针 XOR 编码）

`+0x0` name / `+0x8` type / `+0x10` declaring / `+0x18` attrs（bit24 = 有默认值）。
**无字段偏移字段** —— 运行时偏移全靠 §12 的 `fattr4` 表。

### 26.4 PE 重定位表

1,658,208 项。指针槽在重定位表里，**运行期读出来已是 `base+RVA`**。
这是「不能把 `kImageBase=0x140000000` 用于 VA 判定」的根因。

### 26.5 Class 池二次解引用

```
desc = *(u64*)(base + 0x5AD4E90)
pool = *(u64*)(desc+0x00)      // = 0x50000000000 ← Class 池基址
end  = *(u64*)(desc+0x10)
```

---

## 目录

**必读**：[§0 三条最易踩的规则](#0-三条最易踩的规则迁移前必读) · [§25 事故录](#25-事故录)

| 节 | 内容 |
|---|---|
| [§0](#0-三条最易踩的规则迁移前必读) | 三条最易踩的规则（迁移前必读） |
| [§1](#1-工具做什么--怎么用) | 工具做什么 / 怎么用 |
| [§2](#2-架构与数据来源) | 架构与数据来源 |
| [§3](#3-常量表运行期全局) | 运行期全局（4 个关键 RVA） |
| [§4](#4-常量表metadata-blob-内的表) | metadata blob 内的 15 张表 |
| [§5](#5-记录结构typedef-70b) | 记录结构：typeDef 70B |
| [§6](#6-记录结构成员-26b--字段-8b--属性-10b--事件-14b--参数-8b) | 记录结构：26B / 8B / 10B / 14B / 8B |
| [§7](#7-混淆原语) | 混淆原语 + **三点锚点表** |
| [§8](#8-字符串-blob-解码) | 字符串 blob 解码 |
| [§9](#9-类型名解析16b-il2cpptype) | 类型名解析（16B Il2CppType） |
| [§10](#10-字段偏移链重点) | **字段偏移链**（重点） |
| [§11](#11-枚举与常量值链重点) | **枚举与常量值链**（重点） |
| [§12](#12-方法代码地址两张表的陷阱重点) | **方法代码地址：两张表的陷阱**（重点） |
| [§13](#13-字段默认值元数据里没有) | 字段默认值：元数据里没有 |
| [§14](#14-已定位但未接入的表留档) | 已定位但未接入的表（留档） |
| [§15](#15-泛型实参为什么纯静态做不到重点) | **泛型实参：为什么纯静态做不到**（重点） |
| [§16](#16-14b-元素表结构齐了但终点在堆) | 14B 元素表：结构齐了但终点在堆 |
| [§17](#17-静态--运行期的确切分界线重点) | **静态 / 运行期的确切分界线**（重点） |
| [§18](#18-公式的寻找方法双验证方法论) | 公式的寻找方法（双验证方法论） |
| [§19](#19-八项-70-特性的最终归属) | 八项 7.0 特性的最终归属 |
| [§20](#20-自检体系) | 自检体系（formulaCheck + ida_verify + 换版本工具链） |
| [§21](#21-派生规则不是混淆) | 派生规则（不是混淆） |
| [§22](#22-当前功能开关状态) | 当前功能开关状态 |
| [§23](#23-已知缺口) | 已知缺口 |
| [§24](#24-72-迁移手册) | **7.2 迁移手册** |
| [§25](#25-事故录) | 事故录（6 个坑） |
| [§26](#26-运行期结构留档不参与纯内存路径) | 运行期结构留档（`Il2CppClass` 等） |
| [附:归档清单](#附归档清单) | 归档清单 |
| [附:文件清单](#附文件清单) | 文件清单 |

## 附:归档清单

**不包含任何 `.bin`。** 7.2 迁移不需要它们 —— 免 bin 的 `ida_verify.py` 已覆盖
离线验证。最小自洽集（合计约 **508 MB**）：

| # | 内容 | 大小 | 缺了会怎样 |
|---|---|---|---|
| 1 | `tools/v6/`（源码 + `build/dump.dll`） | 1 MB | 无法重建 |
| 2 | `tools/v6/docs.md`（本文档）+ `README.md` | 60 KB | 无迁移依据 |
| 3 | `GenshinImpact.exe` | 424 MB | 无法离线验证、无法 IDA 分析 |
| 4 | `global-metadata.dat` | 79 MB | **无法离线验证**（`ida_verify.py` 读它） |
| 5 | `startup-metadata.dat` | 3.9 MB | 留档（7.1 不用，但体积可忽略） |
| 6 | `MANIFEST.md`（各文件 SHA256） | 少量 | 无法校验完整性 |

**必须保留 `.dat` 和 `.exe`** —— 这是归档的硬性要求，也是 `ida_verify.py` 的输入。

**可丢弃**：`gi_dump/`（全部 .bin + .map）、`dump_out*/`（被取代的历史产物）、
`*.o` 中间文件、`.DS_Store`。

**IDA 数据库**：分析成果在 `GenshinImpact.exe.i64`（约 951 MB）。
⚠️ IDA 运行期间 `.i64` 是**陈旧的**，活状态在 `.id0/.id1/.id2/.nam/.til`（约 4.7 GB）。
必须**先正常关闭 IDA**（它会把散装文件打包回 `.i64`）再拷贝，否则拿到的是旧状态。

> 由于本工具链已不需要 `.bin`，归档**不含** FORMULAS 独立文件 —— v4/v5 的推导
> 精华已全部并入本文档（见头部对照表）。删除 `tools/v1`–`v5` 不会丢失任何结论，
> 只会丢掉旧的 python 研究脚本（`gi71.py` / `explore*.py` 等一次性探查工具）。

## 附:文件清单

| 文件 | 行数 | 职责 |
|---|---|---|
| `dumper/dllmain.cpp` | 256 | DLL 入口：轮询等待、控制台、SEH、config |
| `dumper/dumper.h` | 485 | **全部常量**、混淆原语、记录结构、GameCtx |
| `dumper/locate.cpp` | 613 | 纯内存 `InitCtx`、88B 表解码、特性开关、边界检查 |
| `dumper/meta.cpp` | 855 | typeDef/成员/字段/属性/事件/参数/枚举解码、类型名解析 |
| `dumper/output.cpp` | 937 | `dump.cs` / `dump.json` / `report` / `summary`、58 项 formulaCheck |
| `dumper/string.cpp` | 134 | 字符串 blob 解码（SSE 状态机） |
| `dumper/seh.h` | 128 | 工作线程异常保护、crash.txt |
| `tools/ida_verify.py` | ~430 | **免 bin 离线验证**（6 项结构检查，见 §20.2） |
| `tools/ida_apply_symbols.py` | 677 | 用 dump.json 恢复 IDA 符号**与注释**（签名/类型块/属性/事件，见 §20.4） |
| `tools/reloc_ida.py` | 791 | 换版本重定位（IDAPython，四层发现；见 §20.3.1） |
| `tools/verify_formulas.py` | 437 | 免 IDA 公式判定器（读 exe/.dat/dumper.h；见 §20.3.3） |
| `tools/found.txt` | 12 | `reloc_ida.py` 自动产出，`verify_formulas.py` 自动读入（见 §20.3.2） |
| `build_mingw.sh` / `build.bat` | 34 / 20 | 构建（`-static -s` 必须） |
| **代码合计** | **3408** | 不含 tools |
