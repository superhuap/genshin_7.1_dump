#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""reloc_ida.py —— 换版本时的公式重定位辅助（IDAPython 3.x / IDA 9.x）

设计原则：**不预设任何具体数值**。
换版本时全局 RVA、header 各字段偏移、混淆常数 K、MPT 地址都会变。
所以本脚本只依赖**跨版本稳定的结构特征**：

  第 1 层  header 的魔数 `MHY\\0`（已确认 .dat 与 exe 共用且稳定）
  第 2 层  代码指针表的统计特征（在映像内 + 16B 对齐 + 重复率）
  第 3 层  **表访问器的指令形态** —— 常数的真正来源
           从「读 header+off → 加减/异或立即数 → 加 blob 基址」这条指令链里
           把 `off` 和 `K` 直接解出来（docs.md §18 方法论 [A] 的自动化）

用法（IDA 载入新版 EXE，File > Script File...）：

    直接运行 -> 跑全流程
    或在 IDA 的 Python 控制台里单独调用：
        find_header()          # 1. 靠魔数定位 header
        find_code_tables()     # 2. 靠统计特征找 MPT / 泛型桩表
        find_table_accessors() # 3. 从访问函数指令里解出 (hdr+off, op, K)
        cross_check()          # 4. 交叉验证（MPT 与桩表应等长）
        report()               # 汇总迁移清单

命令行：
    python3 reloc_ida.py [header|tables|accessors|report]

换版本时可能要调的参数见下方「可调参数」。
"""

import re
import struct
import sys

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_nalt
import ida_segment
import ida_ua
import idautils
import idc

# ============================================================================
#  可调参数
# ============================================================================
MAGIC       = b"MHY\x00"    # header 魔数；注意按**字节串**匹配，不按 u32 值
HDR_BYTES   = 528           # header 长度
SCAN_MIN    = 20000        # 指针表最小长度(项)
TOL_BAD     = 64           # 滑窗容忍的连续坏值数(离群野指针)
BAND_WIN    = 2048         # 重复率分带的窗口大小(项)
MIN_EXACT   = 200000       # 判定「这是一张连续表」所需的最少连续合规项
MIN_FUNCS   = 3            # (hdr+disp) OP K 至少被这么多函数共用才算真表常数
CHUNK       = 1 << 20      # 读块大小(性能)
DUP_SAMPLE  = 200000       # 算重复率时的采样上限(项)

BASE   = ida_nalt.get_imagebase()
RESULT = {}


def _p(*a):
    print(*a)


def image_size():
    m = 0
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s.end_ea > m:
            m = s.end_ea
    return m - BASE


# ============================================================================
#  第 1 层 · header —— 靠魔数扫描
# ============================================================================
def find_header(magic=MAGIC):
    """在 IDB 里扫描 header 魔数，返回候选 EA 列表。

    魔数是唯一跨版本稳定的锚点。实测 7.1 里全 exe 仅一处命中
    (RVA 0x27D4BD0)，且 .dat 文件 offset 0 也是同一个魔数。
    注意：.dat 的前 528B 虽同魔数但内容与 exe 内那份不同（只有 10/528 字节
    相同），**公式必须用 exe 内这份**，不要改成从 .dat 读。
    """
    cands = []
    ea = ida_bytes.find_bytes(magic, 0, flags=ida_bytes.BIN_SEARCH_FORWARD)
    while ea != ida_idaapi.BADADDR:
        cands.append(ea)
        ea = ida_bytes.find_bytes(magic, ea + 1,
                                  flags=ida_bytes.BIN_SEARCH_FORWARD)
    for c in cands:
        seg = ida_segment.getseg(c)
        segname = ida_segment.get_segm_name(seg) if seg else "?"
        _p("  候选 @ 0x%X  段 %s  RVA 0x%X" % (c, segname, c - BASE))
        # 结构自证：header 内应有一批「像被混淆过的 blob 内偏移」的 u32。
        # 仅作提示 —— 实测该分布与随机 .rdata 无区分度，不能当判据。
        n_in = 0
        for i in range(0, HDR_BYTES, 4):
            v = ida_bytes.get_dword(c + i)
            if v != ida_idaapi.BADADDR and v < 0x20000000:
                n_in += 1
        _p("        528B 内 <0x20000000 的 u32: %d / 132" % n_in)
    RESULT["header"] = cands
    if not cands:
        _p("  [!] 没找到魔数 %r。" % (magic,))
        _p("      换版本可能连魔数都变了。备选思路(docs.md §18):")
        _p("      找 metadata 加载器 —— 定位同时写「字符串表首地址」和「blob 基址」")
        _p("      两个全局的那段初始化代码，其赋值右值就是 header 地址。")
    return cands


# ============================================================================
#  第 2 层 · 代码指针表 —— 靠统计特征
# ============================================================================
def _iter_qwords(start, end):
    """分块读出 [start,end) 内的 8B 值，产出 (ea, value)。"""
    ea = start
    while ea < end:
        n = min(CHUNK, end - ea)
        n -= n % 8
        if n <= 0:
            return
        buf = ida_bytes.get_bytes(ea, n)
        if not buf or len(buf) < n:
            # 不可读区域：退化为逐个读
            for k in range(0, n, 8):
                yield ea + k, ida_bytes.get_qword(ea + k)
            ea += n
            continue
        cnt = n // 8
        for k, v in enumerate(struct.unpack_from("<%dQ" % cnt, buf, 0)):
            yield ea + k * 8, v
        ea += n


_EXEC = None


def _exec_ranges():
    """可执行段的范围列表(RVA)，只算一次。"""
    global _EXEC
    if _EXEC is None:
        r = []
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            if s.perm & ida_segment.SEGPERM_EXEC:
                r.append((s.start_ea - BASE, s.end_ea - BASE))
        r.sort()
        _EXEC = r
    return _EXEC


def _ok(v, lo, hi):
    """一个值是否像「方法代码指针表的元素」。

    * 0            —— 抽象/纯虚/未生成，无实现
    * 指向可执行段 —— 函数入口；实测 7.1 真 MPT 的 733442 项**无一例外**
                      都是零或指向可执行段(该判据把候选起点从 0x2870B78
                      精确钉到 0x2870B90 —— 前面 3 项指向 .data)
    * 且 16B 对齐  —— 函数入口对齐
    """
    if v == 0:
        return True
    r = v - BASE
    if not (0 <= r < hi) or (r & 0xF):
        return False
    for a, b in _exec_ranges():
        if a <= r < b:
            return True
    return False


def _bands(s_ea, e_ea, lo, hi):
    """把一个容忍滑窗得到的长段，按**重复率**再切成若干带。

    为什么需要第二步: 容忍滑窗会把真 MPT 和它前面的桩表并成一段
    (中间只有少量离群值, 达不到断段阈值)。两者的决定性差别是**重复率**:
    真 MPT 每个方法一个唯一代码体 -> 零重复; 桩表大量共享 -> 高重复。

    先用 BAND_WIN 项的滑窗给每个位置定 'unique'/'dup'，再把同类的相邻
    窗口合并成带。对 'unique' 带再**回溯精修起点**(从带首向后找第一处
    连续 REFINE 项合规的位置)，把地址误差从 ±BAND_WIN*8 收到 0。
    """
    W = BAND_WIN
    kind = []
    for off in range(0, (e_ea - s_ea) // 8, W):
        seen = set()
        cnt = dup = 0
        ea = s_ea + off * 8
        for _, v in _iter_qwords(ea, min(ea + W * 8, e_ea)):
            if lo <= v < hi:
                cnt += 1
                if v in seen:
                    dup += 1
                else:
                    seen.add(v)
        rate = 100.0 * dup / max(cnt, 1)
        kind.append("u" if rate < 1.0 else ("d" if rate > 15 else "."))
    out = []
    i = 0
    while i < len(kind):
        j = i
        while j < len(kind) and kind[j] == kind[i]:
            j += 1
        if kind[i] in "ud":
            b0 = s_ea + i * W * 8
            b1 = s_ea + (j * W if j < len(kind) else len(kind) * W) * 8
            if kind[i] == "u":
                # 带首可能落在表**内部**(分带粒度 BAND_WIN*8 字节)，所以先往回多看
                # 一个窗口再精修起点，然后从精修后的起点正向量出表的真实长度。
                floor = max(s_ea, b0 - W * 8)
                st = _refine_start(floor, b1, lo, hi)
                if st is not None:
                    n = _run_len(st, b1, lo, hi)
                    if n >= MIN_EXACT:
                        out.append(_stat(st, st + n * 8, lo, hi, exact=True))
            else:
                # 高重复带(桩表)：不做起点精修，按分带原样上报
                out.append(_stat(b0, b1, lo, hi, exact=False))
        i = j
    return out


def _refine_start(scan_lo, b1, lo, hi):
    """从 scan_lo 向后找第一处「连续 MIN_EXACT 项合规」的起点 = 表真实起点。"""
    run = 0
    for ea, v in _iter_qwords(scan_lo, b1):
        if _ok(v, lo, hi):
            run += 1
            if run == MIN_EXACT:
                return ea - (MIN_EXACT - 1) * 8
        else:
            run = 0
    return None


def _run_len(st, limit, lo, hi):
    n = 0
    for _, v in _iter_qwords(st, limit):
        if not _ok(v, lo, hi):
            break
        n += 1
    return n


def _stat(b0, b1, lo, hi, exact=False):
    n = (b1 - b0) // 8
    seen = set()
    cnt = dup = zero = 0
    for _, v in _iter_qwords(b0, b0 + min(n, DUP_SAMPLE) * 8):
        if v == 0:
            zero += 1
        if lo <= v < hi:
            cnt += 1
            if v in seen:
                dup += 1
            else:
                seen.add(v)
    seg = ida_segment.getseg(b0)
    # xref 数是真 MPT 的强判据：它被「方法体分发器」以 index*8 访问，
    # 必然有代码引用；而那些恰好也很稀疏的普通指针表通常没人引用。
    nx = 0
    for probe in (b0, b0 + 8, b0 + 16, b0 + 24, b0 + 32):
        if probe == ida_idaapi.BADADDR:
            break
        try:
            nx = max(nx, sum(1 for _ in idautils.XrefsTo(probe)))
        except Exception:
            pass
    return dict(start=b0, end=b1, seg=ida_segment.get_segm_name(seg) if seg else "?",
                n=n, inimg=cnt, zero=zero, dup=dup, xref=nx,
                rate=100.0 * dup / max(cnt, 1), exact=exact)


def find_code_tables(minlen=SCAN_MIN):
    """扫描数据段，找「像方法代码指针表」的连续段。

    判据（全部来自 IL2CPP 的结构性质，不含版本相关数值）：
      * 连续项多数落在映像内 (基址 .. 基址+SizeOfImage)
      * 且 16 字节对齐 —— 函数入口对齐
      * 允许少量 0 —— 抽象/纯虚/未生成 = 无实现
      * 容忍 <=TOL_BAD 个连续离群值不断段
        （否则桩表会被少数野指针打断成十几段而漏检；这一点踩过坑）

    分类：
      重复率 ≈ 0  -> 疑为 **真 MPT**（每个方法一个唯一代码体）
      重复率高    -> 疑为 **泛型/共享派发桩表**
    """
    lo = BASE
    hi = BASE + image_size()
    segs = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s.perm & ida_segment.SEGPERM_EXEC:
            continue                       # 代码段不参与
        run = bad = 0
        start = s.start_ea
        for ea, v in _iter_qwords(s.start_ea, s.end_ea):
            if _ok(v, lo, hi):
                if run == 0:
                    start = ea
                run += 1
                bad = 0
            else:
                bad += 1
                if bad > TOL_BAD:
                    if run >= minlen:
                        segs.append((start, ea - bad * 8))
                    run = 0
        if run >= minlen:
            segs.append((start, s.end_ea))

    rows = []
    for s_ea, e_ea in segs:
        rows.extend(_bands(s_ea, e_ea, lo, hi))
    rows.sort(key=lambda r: r["n"], reverse=True)
    # 主 MPT 候选 = 最长的零重复表；再用 xref 数做交叉确认
    uniq = [r for r in rows if r["rate"] < 1.0]
    for r in uniq:
        r["primary"] = (r is uniq[0]) if uniq else False
    _p("  %-11s %-9s %-9s %-8s %-6s %s"
       % ("RVA", "长度", "界内*", "重复率", "xref", "判定"))
    for r in rows:
        tag = ""
        if r["rate"] < 1.0:
            tag = "真 MPT (主候选)" if r.get("primary") else "零重复表 (待排除)"
        elif r["rate"] > 15:
            tag = "桩表/高重复表"
        _p("  0x%08X  %-9d %-9d %7.2f%% %-6d %s"
           % (r["start"] - BASE, r["n"], r["inimg"], r["rate"], r["xref"], tag))
    _p("  * 界内 = 前 %d 项采样统计" % DUP_SAMPLE)
    RESULT["code_tables"] = rows
    if not rows:
        _p("  [!] 没扫到候选。若新版换了段布局/对齐，请放宽 _scan_rdata 的过滤条件。")
    return rows


# ============================================================================
#  第 3 层 · 表访问器 —— 从指令里解出 (hdr+off, op, K)
# ============================================================================
_DISPL = (ida_ua.o_displ, ida_ua.o_mem, ida_ua.o_phrase)


def _displ_of(ea, n=1):
    """若该指令的操作数是 ``[base + disp]``，返回带符号的 disp；否则 None。"""
    t = idc.get_operand_type(ea, n)
    if t not in _DISPL:
        return None
    v = idc.get_operand_value(ea, n)
    if v >= 0x8000000000000000:            # 负位移(IDA 返回无符号 64 位)
        v -= 0x10000000000000000
    return v


def find_globals_map(hdr_ea=None):
    """从 header 数据的唯一引用者里，挖出整张 **metadata 全局指针表**。

    7.1 实测：header 数据地址只有 **1 处** 引用，位于一个初始化函数里：

        lea  rax, unk_1427D4BD0
        mov  cs:qword_145AD52B8, rax      <- header 全局槽
        retn

    这个函数把 5 个相邻的 metadata 全局一次性写好（hdr / blob / 通用表…），
    是换版本时**最值钱的一张表** —— 一次就能把全部全局槽的 RVA 收齐。

    同时用「数据段里扫 qword == header 地址」做独立交叉验证。
    """
    if hdr_ea is None:
        h = RESULT.get("header") or []
        hdr_ea = h[0] if h else None
    if hdr_ea is None:
        _p("  [!] 请先跑 find_header()")
        return []
    refs = list(idautils.XrefsTo(hdr_ea))
    _p("  header 数据 @0x%X 有 %d 处引用" % (hdr_ea, len(refs)))
    out = []
    for xr in refs:
        f = ida_funcs.get_func(xr.frm)
        if not f:
            continue
        _p("  初始化函数 %s @ RVA 0x%X" % (idc.get_func_name(f.start_ea), f.start_ea - BASE))
        # 配对 "lea reg, <target>" 与紧随其后的 "mov cs:<global>, reg"
        ea = f.start_ea
        pend = None
        while ea < f.end_ea:
            m = idc.print_insn_mnem(ea)
            t0 = idc.get_operand_type(ea, 0)
            t1 = idc.get_operand_type(ea, 1)
            v1 = idc.get_operand_value(ea, 1) & 0xFFFFFFFFFFFFFFFF
            if m == "lea" and t1 in (ida_ua.o_near, ida_ua.o_mem):
                pend = v1                       # 记住 lea 出来的目标地址
            elif m == "mov" and t0 == ida_ua.o_mem and pend is not None:
                g = idc.get_operand_value(ea, 0)
                if BASE <= g < BASE + image_size() and BASE <= pend < BASE + image_size():
                    mark = " <= header" if pend == hdr_ea else ""
                    _p("      全局 RVA 0x%08X  ->  目标 RVA 0x%08X%s"
                       % (g - BASE, pend - BASE, mark))
                    out.append((g, pend, pend == hdr_ea))
                pend = None
            elif m not in ("mov",):
                pend = None
            ea = idc.next_head(ea, f.end_ea)
    # 独立交叉验证：数据段里扫 qword == header 地址
    hits = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s.perm & ida_segment.SEGPERM_EXEC:
            continue
        for ea, v in _iter_qwords(s.start_ea, s.end_ea):
            if v == hdr_ea:
                hits.append(ea)
    _p("  数据段里等于 header 地址的槽位: %s"
       % ([("RVA 0x%X" % (h - BASE)) for h in hits] or "无"))
    RESULT["globals_map"] = out
    RESULT["header_global"] = [g for g, t, ish in out if ish]
    return out


def find_table_accessors(hdr_global=None, limit=1500, window=14):
    """在引用 header 全局的函数里，解出 `(hdr+disp) OP K`。

    这是**常数真正的来源** —— 不是猜，是从访问器指令里读出来的。
    7.1 真实形态(Hex-Rays 反编译结果)：

        v20 = *(_DWORD *)(qword_145AD52C0                     // blob 全局
                + *(_DWORD *)(qword_145AD52B8 + 516)          // 读 header 字段
                - 450622139                                   // K
                + 4LL * (...));
        v23 = (*(int *)(qword_145AD52B8 + 472) ^ 0x1F85ABE5) // 这里是 '^'
               + qword_145AD52C0;

    编译后 K 的指令形态有三种，全部要认：
        xor   reg, K        ->  '^' K
        sub   reg, K        ->  '-' K
        add   reg, K        ->  '+' K
        lea   reg,[reg-K]   ->  '-' K     (位移为负的 lea)
        lea   reg,[reg+K]   ->  '+' K
    """
    if hdr_global is None:
        g = RESULT.get("header_global") or []
        hdr_global = g[0] if g else None
    if hdr_global is None:
        _p("  [!] 请先跑 find_globals_map()（它会给出 header 全局槽）")
        return []
    xrs = list(idautils.XrefsTo(hdr_global))
    funcs = []
    seen = set()
    for xr in xrs:
        f = ida_funcs.get_func(xr.frm)
        if f and f.start_ea not in seen:
            seen.add(f.start_ea)
            funcs.append(f)
    _p("  header 全局 @RVA 0x%X: %d 处引用, %d 个不同函数 (最多分析 %d 个)"
       % (hdr_global - BASE, len(xrs), len(funcs), limit))

    # key = (disp, op, K) -> 命中它的函数集合
    hits = {}
    scanned = 0
    for f in funcs[:limit]:
        got = _walk_accessor(f, hdr_global)
        if got is None:
            continue
        scanned += 1
        for key in got:
            hits.setdefault(key, set()).add(f.start_ea)
    RESULT["accessors"] = []
    if not hits:
        _p("  [!] 没解出。可能寻址形态更多样，请在 IDA 里手工顺着一个访问器看。")
        return []
    # **按复现次数排序** —— 这是最强的过滤信号。
    # 真表常数会被几十上百个访问器共用；偶然配对上的噪音只出现一两次。
    ranked = sorted(hits.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    multi = [(k, v) for k, v in ranked if len(v) >= MIN_FUNCS]
    _p("  共 %d 个不同组合, 其中 %d 个被 >=%d 个函数共用 (= 真实表常数)"
       % (len(hits), len(multi), MIN_FUNCS))
    if not multi:
        _p("  [!] 没有任何组合达到 %d 函数的复现阈值，可能是 MIN_FUNCS 设太高" % MIN_FUNCS)
        multi = ranked[:40]
    _p("  %-9s %-2s %-10s %-6s %s"
       % ("hdr+disp", "op", "K", "函数数", "示例函数 RVA"))
    for (disp, op, k), fset in multi:
        ex = sorted(fset)[0]
        # 形态 B 报的是 '+'，而 dumper.h 习惯写 '-'。两者是同一张表:
        #   h + K  ==  h - (2^32 - K)
        # 7.1 实测 iface/typedef/method 三张表的两种写法并存, 补码之和恰为 0x100000000。
        alt = ""
        if op == "+":
            alt = "   等价于 '-' 0x%08X" % ((0x100000000 - k) & 0xFFFFFFFF)
        _p("  0x%-7X %-2s 0x%08X %-6d 0x%X%s"
           % (disp, op, k, len(fset), ex - BASE, alt))
        RESULT["accessors"].append((disp, op, k))
    _p("")
    _p("  注: '+' 与 '-' 是同一张表的两种写法, 互补数之和 = 0x100000000。")
    _p("      填 dumper.h 时统一用 '-' 风格:  kT_x = { disp, '-', 2^32 - K }。")
    _p("      若某些表没出现在这里, 把 limit 调大后重跑(默认 %d/%d 个函数)。"
       % (limit, len(funcs)))
    _save_found(multi)
    return RESULT["accessors"]


def _save_found(rows, path=None):
    """把发现结果落盘，供 verify_formulas.py 离线对齐 dumper.h。

    格式就是人能读的 `hdr+0x.. OP 0x..`，方便手工核对，也方便版本间 diff。
    """
    import os
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "found.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("# reloc_ida.py 自动发现 —— %d 条 (>=%d 个函数共用)\n"
                    % (len(rows), MIN_FUNCS))
            f.write("# hdr+disp   op K        函数数\n")
            for (disp, op, k), fset in rows:
                f.write("hdr+0x%-5X %s 0x%08X   %d\n" % (disp, op, k, len(fset)))
        _p("  已写入 %s" % path)
        _p("  下一步: python3 verify_formulas.py   # 读 .dat 逐条判定并与 dumper.h 对齐")
    except Exception as e:                       # 落盘失败不该影响主流程
        _p("  [!] 写 %s 失败: %s" % (path, e))


def _reg(ea, n=0):
    """取第 n 个操作数的寄存器名（小写），不是寄存器返回 None。"""
    t = idc.get_operand_type(ea, n)
    if t not in (ida_ua.o_reg, idc.o_reg):
        return None
    r = idc.print_operand(ea, n)
    return r.strip().lower() if r else None


def _fam(r):
    """把寄存器名归一到「族」，统一 eax/rax/al/ax 这类宽度别名。"""
    if not r:
        return None
    r = r.strip().lower()
    if r.startswith("e"):
        return r[1:]
    return r


def _mem_base_reg(ea, n=1):
    """取 ``[base + disp]`` 里的 base 寄存器族；绝对地址/无基址返回 None。

    必须先剥掉段前缀(cs:)和操作数尺寸前缀(dword ptr)，否则
    "dword ptr [rdx+19Ch]" 会被解析成 "dword ptr [rdx" 而匹配失败。
    o_mem 是无基址的绝对寻址，直接返回 None。
    """
    t = idc.get_operand_type(ea, n)
    if t not in _DISPL or t == ida_ua.o_mem:
        return None
    txt = (idc.print_operand(ea, n) or "").strip()
    txt = re.sub(r"^(cs|ds|ss|es|fs|gs):", "", txt, flags=re.I)
    txt = re.sub(r"^(byte|word|dword|qword|tword|oword|xmmword)\s+(ptr\s+)?",
                 "", txt, flags=re.I)
    txt = txt.strip().lstrip("[").rstrip("]")
    m = re.match(r"^([a-z][a-z0-9]*)", txt, flags=re.I)
    return _fam(m.group(1)) if m else None


_LOADS = ("mov", "movzx", "movsx", "movsxd")
_ALU = {"xor": "^", "add": "+", "sub": "-"}
_NO_SIDE_EFFECT = ("cmp", "test", "push", "nop", "jmp", "call", "retn", "int3")


def _walk_accessor(f, hdr_global):
    """在一个函数里做**寄存器族级数据流跟踪**，解出所有
    ``h32(hdr + disp) OP K``。

    7.1 实测有两种编译形态，都要认：

      形态 A —— 先读字段再运算
          movsxd rsi, dword ptr [rdx+19Ch]   ; rdx 持有 header 指针
          xor    rsi, 30F4D28Eh             ; ^ K
      （7.1: disp=0x19C K=0x30F4D28E 已知为 tokentype 表）

      形态 B —— 先装常数再读字段
          mov  esi, 0EC48AB9Fh
          add  esi, [rdx+0B4h]              ; K + h32(hdr+0xB4)
      形态 B 的公式是 h32 + K（等价于 h32 - (2^32-K)），上报成 '+'。

    历史 bug 记录（都已修，改动这里前先读）：
      1. 内存操作数分支曾用 ``m in _LOADS`` 当门控 -> 形态 B 的
         ``add esi,[rdx+disp]`` 助记符是 add，**整个分支进不去**，
         3930 个函数里 0 命中。现在改为「只要操作数 1 是内存就进分支」，
         再按助记符分派。
      2. base 寄存器解析没剥 "dword ptr " 前缀，base 匹配全失败。
      3. 装 header 全局指针后，同一条指令末尾的「目的寄存器失效」逻辑
         会立刻把刚登记的寄存器 discard 掉。现在用 handled 标志跳过。
    """
    out = []
    hdr_f = set()      # 哪些寄存器族持有 header 指针
    pend = {}          # 族 -> disp   （已从 header 读出字段，待 ALU）
    kreg = {}          # 族 -> K      （已装常数，待与 header 字段运算）
    ea = f.start_ea
    while ea < f.end_ea:
        m = idc.print_insn_mnem(ea)
        if not m:
            ea = idc.next_head(ea, f.end_ea)
            continue
        f0 = _fam(_reg(ea, 0))
        t1 = idc.get_operand_type(ea, 1)
        handled = False

        # ---- 操作数 1 是内存：装 header 指针 / 读字段 / 形态 B 后半 ----
        if t1 in _DISPL:
            v = idc.get_operand_value(ea, 1) & 0xFFFFFFFFFFFFFFFF
            if v == hdr_global:
                if f0:
                    hdr_f.add(f0)          # mov reg, cs:[hdr_global]
                handled = True
            else:
                base = _mem_base_reg(ea, 1)
                d = _displ_of(ea, 1)
                if (base in hdr_f and d is not None
                        and d % 4 == 0 and d < HDR_BYTES):
                    if m in _LOADS and f0:
                        pend[f0] = d       # 形态 A 前半
                        handled = True
                    elif m in _ALU and f0 in kreg:
                        out.append((d, _ALU[m], kreg.pop(f0)))   # 形态 B 后半
                        handled = True
                    elif m == "lea" and base in pend and d:
                        s = d - (1 << 64) if d >= 0x8000000000000000 else d
                        out.append((pend.pop(base),
                                    "-" if s < 0 else "+", abs(s) & 0xFFFFFFFF))
                        handled = True
        # ---- 操作数 1 是立即数：形态 B 前半 / 形态 A 后半 ----
        elif t1 == ida_ua.o_imm:
            v1 = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
            if m in ("mov", "movabs") and f0:
                kreg[f0] = v1
                handled = True
            elif m in _ALU and f0 in pend:
                out.append((pend.pop(f0), _ALU[m], v1))
                handled = True
        # ---- lea reg,[reg±K] (操作数是寄存器+位移，无 base 匹配) ----
        elif m == "lea" and t1 == ida_ua.o_reg:
            src = _fam(_reg(ea, 1))
            d = _displ_of(ea, 1) or 0
            if src in pend and d:
                s = d - (1 << 64) if d >= 0x8000000000000000 else d
                out.append((pend.pop(src),
                            "-" if s < 0 else "+", abs(s) & 0xFFFFFFFF))
                handled = True

        # 目的寄存器被别处覆写 -> 三张表里对应项失效
        if f0 and not handled and m not in _NO_SIDE_EFFECT:
            hdr_f.discard(f0)
            pend.pop(f0, None)
            kreg.pop(f0, None)
        ea = idc.next_head(ea, f.end_ea)
    return out or None


    if m == "xor" and t1 == ida_ua.o_imm:
        return ("^", v1 & 0xFFFFFFFF)
    if m in ("add", "sub") and t1 == ida_ua.o_imm:
        v = v1 & 0xFFFFFFFF
        return ("+" if m == "add" else "-", v)
    if m == "lea" and t1 in _DISPL:
        # lea dst,[dst±K] —— 位移即 K，带符号
        if dst is not None and _mem_base_reg(ea) != dst:
            return None
        s = v1
        if s >= 0x8000000000000000:
            s -= 0x10000000000000000
        if s < 0:
            return ("-", (-s) & 0xFFFFFFFF)
        if s > 0:
            return ("+", s & 0xFFFFFFFF)
    return None


# ============================================================================
#  交叉验证
# ============================================================================
def cross_check(methods=None):
    """对扫描结果做交叉验证。

    真 MPT 的判据（由强到弱）：
      1. **长度 == 方法数** —— 最硬。7.1 实测 733442，与 dump 出的方法数完全相等
      2. **零重复** —— 每个方法一个唯一代码体
      3. **有代码 xref** —— 被「方法体分发器」以 index*8 访问
    7.1 实测反例：另有一张 460314 项的零重复指针表，长度与 xref 都能把它排除。
    """
    rows = RESULT.get("code_tables") or find_code_tables()
    if not rows:
        return
    uniq = [r for r in rows if r["rate"] < 1.0]
    dup = [r for r in rows if r["rate"] > 15]
    _p("  零重复表 %d 个，高重复表 %d 个" % (len(uniq), len(dup)))
    for r in uniq:
        _p("   [零重复] RVA 0x%08X  长度 %-8d xref %-4d %s"
           % (r["start"] - BASE, r["n"], r["xref"],
              "<= 主候选" if r.get("primary") else ""))
    for r in dup:
        _p("   [高重复] RVA 0x%08X  长度 %-8d 重复率 %.2f%%"
           % (r["start"] - BASE, r["n"], r["rate"]))
    if methods:
        _p("  外部给定方法数 = %d" % methods)
        hit = [r for r in uniq if abs(r["n"] - methods) <= 64]
        if hit:
            for r in hit:
                _p("    => 长度匹配: RVA 0x%08X (差 %d)"
                   % (r["start"] - BASE, r["n"] - methods))
        else:
            _p("    => 没有零重复表的长度与之相符，请人工检查")
    else:
        _p("  [!] 强烈建议用方法数交叉验证：跑一次旧版 dump 数出方法数，")
        _p("      或从 typedef 表累加 methodCount，再看哪个候选长度对得上。")
    RESULT["cross"] = (dup, uniq)


# ============================================================================
#  汇总
# ============================================================================
def report():
    _p("\n" + "=" * 72)
    _p(" 公式重定位报告   基址 0x%X" % BASE)
    _p("=" * 72)
    _p("[1] header")
    for c in RESULT.get("header", []):
        _p("     数据 RVA 0x%X" % (c - BASE))
    if not RESULT.get("header"):
        _p("     (未找到)")
    _p("[2] metadata 全局指针表")
    for g, t, ish in RESULT.get("globals_map", []):
        _p("     全局 RVA 0x%08X  ->  目标 RVA 0x%08X%s"
           % (g - BASE, t - BASE, "   <= header" if ish else ""))
    if not RESULT.get("globals_map"):
        _p("     (未解析)")
    _p("[3] 代码指针表")
    for r in RESULT.get("code_tables", [])[:8]:
        if r["rate"] < 1.0:
            tag = "真 MPT (主候选)" if r.get("primary") else "零重复表"
        elif r["rate"] > 15:
            tag = "桩表/高重复表"
        else:
            tag = "?"
        _p("     RVA 0x%08X  长度 %-8d 重复率 %6.2f%% xref %-4d %s"
           % (r["start"] - BASE, r["n"], r["rate"], r["xref"], tag))
    if not RESULT.get("code_tables"):
        _p("     (未扫描)")
    _p("[4] 从访问器解出的常数")
    for d, op, k in RESULT.get("accessors", []):
        _p("     hdr+0x%-5X %s 0x%08X" % (d, op, k))
    if not RESULT.get("accessors"):
        _p("     (未解出)")
    _p("=" * 72)
    _p("填表指引 —— [2] 给出全局槽 RVA，[4] 给出每个表的 (字段偏移, 运算, K):")
    _p("    blob_off = (u32)(hdr + disp_from_[4])  OP  K_from_[4]")
    _p("    实测 7.1 两例:  hdr+0x204 - 0x1ADC0BDB   (516, iface)")
    _p("                   hdr+0x1D8 ^ 0x1F85ABE5   (472, 12 字节记录)")
    _p("")
    _p("收尾:")
    _p("  1. **核对主 MPT 候选**: 长度必须等于方法数(7.1 = 733442)，且零重复。")
    _p("  2. 把 [4] 的结果填进 dumper.h 的 kT_* 表")
    _p("  3. 数据自证 (§18 [B]): 用 K 解析 .dat，看字符串/类型索引是否合法")
    _p("  4. 离线核对 §20.2; 最后跑 §20.1 的 58 项 formulaCheck")


def run_all():
    _p("[1/5] 扫描 header (魔数 %r) ..." % (MAGIC,))
    find_header()
    _p("\n[2/5] 解析 metadata 全局指针表 ...")
    find_globals_map()
    _p("\n[3/5] 扫描代码指针表 ...")
    find_code_tables()
    _p("\n[4/5] 解析表访问器 ...")
    find_table_accessors()
    _p("\n[5/5] 交叉验证 ...")
    cross_check()
    report()


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "header":
        find_header()
    elif arg == "globals":
        find_globals_map()
    elif arg == "tables":
        find_code_tables()
    elif arg == "accessors":
        find_table_accessors()
    elif arg == "cross":
        cross_check()
    else:
        run_all()
