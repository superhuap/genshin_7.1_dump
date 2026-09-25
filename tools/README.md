# Genshin Impact 7.1 元数据离线解码工具集

从加密的 global-metadata.dat + 运行期 dump 完全离线还原 IL2CPP 元数据。

## 成果

- `dump_out/dump.cs` — 745K 行,68,616 类型 / 553,094 方法(名字/命名空间/flags/RVA)
- `dump_out/dump.json` — 机器可读全量数据

## 已破解的格式(全部从 IDA 静态分析提取)

### 总体架构
- `GenshinImpact.exe` 内嵌 528B 混淆 header(module RVA 0x27D4BD0,`MHY\0` 魔数)
- 磁盘 `global-metadata.dat` 的 528B 头被跳过,section 数据按内嵌 header 偏移寻址(全部 +528)
- `startup-metadata.dat`(明文)承载 image/assembly 数据,init 后释放
- 每表字段有独立混淆:固定常量 XOR/ADD 或**随记录索引变化的密钥流**

### 字符串(sub_14050F280 复刻)
- 索引打包:`[31:24]=长度(≤255)`,`[23:0]=字符串区字节偏移`
- 密钥流 `key_i = key0 + i*0x6B0B40C349AE61E5`(64位)
  `key0 = 0x5C2B4E660E2D0544 * ((0x694418957C890198*idx ^ 0x55A357D81EF0E48B))`
- 长串(≥8块)走 SSE 变体:状态 `{key0, swap32(key0)+STEP}` 起步,每16B块 +C1{D6168186935CC3CA},每32B +C2{AC2D030D26B98794},尾块回线性
- 空串 = 索引 0x8

### 内嵌 header 字段表(偏移→运算→常量)
```
+8   (v-1823609295)>>2   typeCount = 68616
+24  v-1281686557        参数/默认值 8B 记录表
+44  (v-610644003)/0x28  汇编数 = 75
+92  v-381850355         接口 typedef 索引 4B 表
+120 v-432378149         startup 44B image 记录
+144 v-1222291392        12B per-type method-info 表
+148 v^0x4A4C0A71        4B → methodPointer 间接表
+172 v^0x7D85E99F        startup int 表
+180 v-330781793         ★ 70B typedef 表
+184 v-1241239214        startup int 表
+192 v-1630172749        14B 泛型方法表 (232,325条)
+212 (v-585353259)/14    14B 计数
+220 (v-1009555078)>>4   image 数 = 75
+224 v-486952835         size
+236 v-1757766433        u16 表
+280 (v>>2)^0x11BB5358   usage 计数
+288 v-499562099         10B 表
+304 (v-565220529)/14    计数2
+308 v^0x558E11EC        startup {start,count} 8B
+320 v-1832561230        6B 泛型范围表 (计数 @508-127184164 /6)
+364 v-483030612         ★ 26B 方法记录表 (553,094条)
+376 v-1377001944        4B per-type → 12B 表索引
+384 v-898198093         startup int 数组
+388 v-1080211659        ★ 字符串数据区
+392 v^0x1B58E334        usage 计数
+424 v^0x13FD57CF        4B 表
+436 (v-267406932)/3     缓存计数
+440 v-768000888         startup 16B 表
+472 v^0x1F85ABE5        12B 泛型核心表
+500 v-1508895639        u8 种类表(参数)
+504 v-2051052385        startup
+516 v-450622139         4B 编码方法槽表
+524 v-248195061         startup 字符串表
```

### typedef 70B 记录(偏移→语义→公式)
```
+0  namespaceIdx = v - 1145778368
+4  byvalType(16B Il2CppType 表 idx) = v ^ 0xDA4711B
+8  ? = v - ?                    (未解码)
+12 methodStart(26B表) = v ^ 0x4D8127F2
+16 declaring(16B表) = v - 1950851500   (-1哨兵=1950851499)
+20 type2(16B表) = v ^ 0x67A02A49
+24 element(16B表) = v - 1031049247   (-1哨兵=1031049246)
+28 ?
+32 methodStart2(@516表) = v ^ 0x2E8C0EB8
+36 nameIdx = v - 72511848
+40 f40(→class+160) = v - 1096399758
+44 generic(16B表) = v ^ 0x5591B379   (-1哨兵)
+48 methodCount = (u16)v + 4806
+50/+52 ?
+54 interfaceStart = (int16)v + 6631
+56 ?
+58 flags16(位语义与 stock 不同,interface 位不在此)
+60/+62 (哨兵 0x6675)
+64 ?
+65 countA = u8 - 114
+66 countB = u8 - 3
+67 ?
+69 interfaceCount = u8 ^ 0xBA
```

### 方法 26B 记录(@364, i=全局方法索引)
```
k1(i)   = ((860405619*i) ^ 0x73758947) + 1547935323
v25(i)  = (u16)((-16525*i) ^ 0x8947) - 24997
kbits(i)= ((115*i) ^ 0x47) + 91
+0  nameIdx = k1(i) ^ (v - 1524016681)
+4  ? (疑 returnType)
+8  ? (疑 paramStart)
+12 declaringTypeIdx = v ^ k1(i) ^ 0x59244785
+16 slot = ((u16)v - 25344) ^ v25(i)
+18 ? = v ^ v25(i) ^ 0x41FB
+20 ? = v ^ v25(i) ^ 0xD73C  (恒 0xFFFF?)
+22 flags = v ^ v25(i) ^ 0x8F60  (MethodAttributes ✓)
+24 bit46 = kbits(i) ^ (v - 31)
+25 bit47相关 = kbits(i) ^ (v - 124)
methodPointer: idx = u32(@148表 + 4*i) (≠-1) → *(u64*)(5298struct+96数组 + 8*idx)
```

### 池内运行期结构(指针 = stored - bias)
```
assembly(52F8, 88B): +36 typeCount^0x6A3E22EA, +56 typeStart^0x4B1CB1C1,
                     +32 expCnt-1034392383, +64 name+0x2C559A9973CA0315(堆)
image(5308, 88B):    +8 assembly+0x1D2861AD1B868E81,
                     +64 name+0x783FCBBE2E713C7F(池), +48 nameNoExt+0x3351BD851F7B567F
5298 struct:         +96 methodPointers 数组, +136 共享方法缓存, +152 tokens
52A0 struct:         +8 genericClasses(16B), +72 Il2CppType(16B), +88 u16 表
```

## 工具
- `gi71.py` — 核心:header 字段解码 + 字符串密码
- `dump_v1.py` — 生成 dump.cs / dump.json
- `typedefs.py` / `methods.py` — 表调试器
- `pool_tables.py` — 池结构检查
- `dumpdll/` — 运行期 dump DLL(Xenos 注入用,已使用)

## 待办(v2)
- 字段表(位置未定位,需找 SetupFields/字段名解析器)
- 参数表(@24 8B 记录 + @500 种类表,公式部分已知)
- 属性/事件/嵌套类型/默认值/字符串字面量
- interface/enum/valuetype 位(在 16B Il2CppType attrs 或 12B 记录)
- 可选:重建标准格式 metadata 供 Il2CppDumper(工作量大于自产 dump)
