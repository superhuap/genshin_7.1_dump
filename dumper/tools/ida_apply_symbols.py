#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ida_apply_symbols.py —— 用真机 dump 把 IDA 还原成「可读的 C# 索引」

原版只做一件事: 按 rva 重命名函数。其余信息（返回类型、参数、字段偏移、
属性存取器、事件订阅器、类继承）全在 dump.json 里躺着没人用。这个版本
把能恢复的都恢复:

  ┌────────────┬──────────────────────────────────────────┬──────────────┐
  │ 记什么     │ 写进 IDA 的形式                            │ 数据来源      │
  ├────────────┼──────────────────────────────────────────┼──────────────┤
  │ 方法名     │ 符号名 Cls__method                        │ types[].methods[]
  │ 方法签名   │ 函数可重复注释 System.Void Cls::m(int a) │ return/params/flags
  │ 类型信息   │ 函数可重复注释的多行块                     │ types[] 全部字段
  │ 字段偏移   │ 写进类型块的 "+0x20 name : type"          │ fields[].offset
  │ 属性       │ 写进 **getter/setter 地址**的注释          │ properties[]
  │ 事件       │ 写进 **add/remove/raise 地址**的注释       │ events[]
  └────────────┴──────────────────────────────────────────┴──────────────┘

属性/事件的访问器在 JSON 里是**全局方法下标**（不是 rva）。本脚本先按 type
顺序把所有 methods[] 拼起来建 下标->rva 表（实测拼接长度 733442 == 全局方法
总数，7.1 精确吻合），再据此把访问器落到真实地址上。

用法
----
推荐（IDA 内，弹窗选文件）:
    File > Script File... 选本脚本 -> 选 dump.json
命令行:
    python3 ida_apply_symbols.py <dump.json>          # 在 IDA 内跑
    python3 ida_apply_symbols.py <dump.json> --ns    # 符号带命名空间
    python3 ida_apply_symbols.py <dump.json> --no-comments   # 只改名, 最快
独立模式(无 IDA, 用于离线核对):
    python3 ida_apply_symbols.py --test  dump.json
    python3 ida_apply_symbols.py --export dump.json out.txt
    python3 ida_apply_symbols.py --export dump.json out.txt --full

设计约束
--------
* **只重命名自动名**（sub_/nullsub_/unk_/locret_/def_/jpt_ 前缀），
  不覆盖手工命名, 可安全重复运行。
* 注释一律用**可重复注释**(repeatable), 不用函数注释 —— 后者会触发
  IDA 对 71 万个函数做重量级原型/SP 分析, 实测能卡死整库。
* 共享桩(多方法同一 rva)取首个名字, 但签名注释会合并保留。
* 控制字符: 本游戏有 1783 个混淆方法名解码后内嵌 \\n 等控制字符。
  JSON 侧转义成 \\uXXXX 所以无损; dump.cs 侧会把行劈开, 详见 gen_from_cs。
"""

import re
import sys

# ---- 可调参数 -------------------------------------------------------------
CS_JOIN = 4          # dump.cs 签名被内嵌换行劈开时, 最多向前拼接几行
MAX_FIELDS_IN_COMMENT = 64   # 类型块注释里最多列多少个字段(防止超长)
MAX_COMMENT = 4000   # 单条注释最大字符数(超了截断并标注)
PROGRESS_EVERY = 20000        # 每多少条刷一次进度

# ---- 解析器 ---------------------------------------------------------------
# 类声明行(output.cpp ~L295):
#     public class Locale // TypeDefIndex: 5
#     public struct Point32 // TypeDefIndex: 7
#     public enum Weekday : System.Enum // TypeDefIndex: 9
#     public class Derived : Base // TypeDefIndex: 11
# ⚠️ 旧版本的正则要求类名后必须有冒号, 而 TypeDefIndex 注释跟在同一行、
#    多数类型**没有**基类 -> 冒号根本不存在 -> 类名从来没被抓到,
#    结果 .cs 路径产出的符号全丢了 "类名__" 前缀(与 .json 路径不一致)。
CLS_RE = re.compile(r"^\s*public\s+(?:class|struct|enum|interface)\s+"
                    r"([A-Za-z0-9_<>,.]+)")
NS_RE = re.compile(r"^\s*//\s*Namespace:\s*(\S+)")
RVA_RE = re.compile(r"^\s*//\s*RVA:\s*0x([0-9A-Fa-f]+)")
METHOD_RE = re.compile(r"^\s*(?:[^\s()]+\s+)*([^(),\s]+)\s*\(")
SKIP_PATTERN = re.compile(r"[^A-Za-z0-9_$]", re.UNICODE)
NONE_IDX = 0xFFFFFFFF          # properties/events 里表示"无"的哨兵


def sanitize(name):
    """把名字变成 IDA 可接受形式(替换非法字符,截断超长)。"""
    name = SKIP_PATTERN.sub("_", name)
    name = name.strip("_")
    if not name or name[0].isdigit():
        name = "m_" + name
    return name[:240]


def to_rva(v):
    """把 dump.json 的 rva 字段转成 int。

    ⚠️ dumper 把 rva 序列化成**十六进制字符串**(output.cpp: `hex0()` -> "0x%llX"),
    不是 JSON number。所以不能直接 `ib + rva` —— 早先版本就是这么炸的:
        TypeError: unsupported operand type(s) for +: 'int' and 'str'
    这里三种形态都收: int / "0x1A2B" / "1A2B" / "0" / None。
    """
    if v is None or isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return 0
        neg = s.startswith("-")
        if neg:
            s = s[1:]
        try:
            n = int(s, 16) if s.lower().startswith("0x") else int(s, 0)
        except ValueError:
            try:
                n = int(s, 16)
            except ValueError:
                return 0
        return -n if neg else n
    return 0


def _clip(s, limit=MAX_COMMENT):
    if len(s) <= limit:
        return s
    return s[:limit - 24] + "\n...[截断, 共 %d 字符]" % len(s)


def split_param(p):
    """'int keySize' -> ('int', 'keySize')；没有名字就 ('int', '')。"""
    p = p.strip()
    if not p:
        return "", ""
    parts = p.rsplit(" ", 1)
    if len(parts) == 2 and parts[1] and " " not in parts[1]:
        return parts[0], parts[1]
    return p, ""


def build_symbol(cls, ns, name, use_ns):
    """Cls__method / ns__Cls__method"""
    if name in (".ctor", ".cctor"):
        name = "ctor" if name == ".ctor" else "cctor"
    else:
        name = sanitize(name)
    if not name:
        return ""
    prefix = ""
    if use_ns and ns:
        prefix = sanitize(ns) + "__"
    if prefix or cls:
        return "%s%s__%s" % (prefix, cls, name)
    return name


# ============================================================================
#  dump.json -> 记录流
# ============================================================================
def _load_json(path):
    import json
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fp:
        return json.load(fp)


def _midx_to_rva(root):
    """按 type 顺序把所有 methods[] 拼起来 -> 全局方法下标到 rva 的表。

    依据: dumper 是按全局成员号(methodStart+序号)输出 methods[] 的, 且
    meta.methodCount == 各 type methods[] 长度之和。7.1 实测拼接长度
    733442 与 meta.methodCount 精确吻合, 所以拼接顺序就是全局下标顺序。
    这让 properties[].getter/setter 与 events[].add/remove/raise 这些
    **全局方法下标**能落到真实地址上。
    """
    import array
    tab = array.array("L")
    for t in root.get("types") or ():
        for m in t.get("methods") or ():
            tab.append(to_rva(m.get("rva")))
    return tab


def gen_from_json(path, use_ns, want_comments=True):
    """dump.json -> (kind, rva, name_or_text, extra) 记录流。

    kind:
      "m" 方法   -> (rva, 符号名, 签名注释)
      "t" 类型块 -> (rva, 多行注释, 类型全名)
      "p" 属性   -> (rva, 注释, 属性名)
      "e" 事件   -> (rva, 注释, 事件名)
    rva==0 的记录直接不产出(调用方还要靠 0 计数, 所以单独统计)。
    """
    root = _load_json(path)
    types = root.get("types") or ()
    if not isinstance(types, (list, tuple)):
        raise SystemExit("[ida_apply_symbols] %s 不是预期的 dump.json(缺 types 数组)" % path)
    midx = _midx_to_rva(root) if want_comments else None

    meta = root.get("meta") or {}
    n_methods = n_zero = 0
    for ti, t in enumerate(types):
        if not isinstance(t, dict):
            raise SystemExit(
                "[ida_apply_symbols] %s 的 types[%d] 是 %s 不是对象 —— 这是**旧格式**"
                "(methods 是下标数组, 字段名是 namespace)。\n"
                "    当前 v6 的 output.cpp 输出的是 rva 十六进制字符串 + namespace 字段。\n"
                "    请用当前版本重新 dump, 或改用 dump.cs (走 gen_from_cs)。"
                % (path, ti, type(t).__name__))

        raw_cls = str(t.get("name") or "")
        raw_ns = str(t.get("namespace") or t.get("ns") or "")
        cls = sanitize(raw_cls)
        if raw_cls in ("<Module>", "<PrivateImplementationDetails>"):
            cls = ""
        full = (raw_ns + "." + raw_cls) if raw_ns else raw_cls

        methods = t.get("methods") or ()
        fields = t.get("fields") or ()
        props = t.get("properties") or ()
        evs = t.get("events") or ()
        ifaces = t.get("interfaces") or ()

        # ---- 类型块注释: 挂在第一个有 rva 的方法地址上 ----
        anchor = 0
        for m in methods:
            r = to_rva(m.get("rva")) if isinstance(m, dict) else 0
            if r:
                anchor = r
                break

        if want_comments and anchor:
            L = []
            L.append("Class: %s" % full)
            if t.get("image"):
                L.append("Image: %s" % t["image"])
            if t.get("parent"):
                L.append("Parent: %s" % t["parent"])
            L.append("TypeDefIndex: %s" % t.get("index", "?"))
            if t.get("isValueType"):
                L.append("ValueType: yes  size=%s align=%s"
                         % (t.get("size", "?"), t.get("align", "?")))
            L.append("methods=%d fields=%d properties=%d events=%d interfaces=%d"
                     % (len(methods), len(fields), len(props), len(evs), len(ifaces)))
            if ifaces:
                L.append("interfaces: " + ", ".join(str(x) for x in ifaces[:16])
                         + (" ..." if len(ifaces) > 16 else ""))
            if fields:
                L.append("--- fields (%d) ---" % len(fields))
                for f in fields[:MAX_FIELDS_IN_COMMENT]:
                    if not isinstance(f, dict):
                        continue
                    stat = bool(f.get("isStatic"))
                    # 静态字段的 offset 字段是 instanceSize, 印成 +0x.. 会误导
                    where = "static" if stat else "+0x%-5x" % f.get("offset", 0)
                    tag = []
                    if stat:
                        tag.append("static")
                    if f.get("isConst"):
                        tag.append("const")
                    L.append("  %-8s %s : %s%s"
                             % (where, f.get("name", "?"), f.get("type", "?"),
                                ("  [%s]" % ",".join(tag)) if tag else ""))
                if len(fields) > MAX_FIELDS_IN_COMMENT:
                    L.append("  ...(还有 %d 个字段未列出)" % (len(fields) - MAX_FIELDS_IN_COMMENT))
            if props:
                L.append("--- properties (%d) ---" % len(props))
                for p in props[:MAX_FIELDS_IN_COMMENT]:
                    if not isinstance(p, dict):
                        continue
                    L.append("  %s : %s   get=%s set=%s"
                             % (p.get("name", "?"), p.get("type", "?"),
                                _idx_name(p.get("getter")), _idx_name(p.get("setter"))))
            if evs:
                L.append("--- events (%d) ---" % len(evs))
                for e in evs[:MAX_FIELDS_IN_COMMENT]:
                    if not isinstance(e, dict):
                        continue
                    L.append("  %s : %s   add=%s remove=%s raise=%s"
                             % (e.get("name", "?"), e.get("type", "?"),
                                _idx_name(e.get("add")), _idx_name(e.get("remove")),
                                _idx_name(e.get("raise"))))
            yield ("t", anchor, _clip("\n".join(L)), full)

        # ---- 方法 ----
        for m in methods:
            if not isinstance(m, dict):
                raise SystemExit(
                    "[ida_apply_symbols] %s 里 types[%d].methods 含非对象元素(%s)"
                    " —— 同样是**旧格式**。\n    请用当前版本重新 dump, 或改用 dump.cs。"
                    % (path, ti, type(m).__name__))
            n_methods += 1
            rva = to_rva(m.get("rva"))
            raw = str(m.get("name") or "")
            sym = build_symbol(cls, raw_ns, raw, use_ns)
            if not rva or not sym:
                n_zero += 1 if not rva else 0
                continue
            sig = ""
            if want_comments:
                ret = str(m.get("return") or "void")
                ps = []
                for p in (m.get("params") or ()):
                    ty, nm = split_param(str(p))
                    ps.append(("%s %s" % (ty, nm)).strip())
                sig = "%s %s::%s(%s)" % (ret, full, raw, ", ".join(ps))
                sig += "\nflags: 0x%X" % (m.get("flags") or 0)
            yield ("m", rva, sym, sig)

        # ---- 属性 / 事件: 挂到访问器真实地址上 ----
        if want_comments and midx is not None:
            for p in props:
                if not isinstance(p, dict):
                    continue
                for kind_key, word in (("getter", "get"), ("setter", "set")):
                    gi = p.get(kind_key)
                    r = _idx_rva(midx, gi)
                    if not r:
                        continue
                    yield ("p", r,
                           "Property: %s.%s : %s\n  %s accessor"
                           % (full, p.get("name", "?"), p.get("type", "?"), word),
                           "%s.%s" % (full, p.get("name", "?")))
            for e in evs:
                if not isinstance(e, dict):
                    continue
                for kind_key, word in (("add", "add"), ("remove", "remove"),
                                       ("raise", "raise")):
                    ei = e.get(kind_key)
                    r = _idx_rva(midx, ei)
                    if not r:
                        continue
                    yield ("e", r,
                           "Event: %s.%s : %s\n  %s accessor"
                           % (full, e.get("name", "?"), e.get("type", "?"), word),
                           "%s.%s" % (full, e.get("name", "?")))
    RESULT["methods"] = n_methods
    RESULT["rva0"] = n_zero


def _idx_rva(midx, gi):
    if gi is None or gi == NONE_IDX or gi < 0 or gi >= len(midx):
        return 0
    return midx[gi]


def _idx_name(gi):
    return "-" if (gi is None or gi == NONE_IDX) else str(gi)


# ============================================================================
#  dump.cs -> 记录流（只产方法, 能力弱于 JSON）
# ============================================================================
def gen_from_cs(path, use_ns, want_comments=True):
    """dump.cs -> ("m", rva, 符号名, 签名注释)。

    ⚠️ 本路径**天然不如 JSON 路径完整**, 两个原因:

    1) dump.cs 只为 rva != 0 的方法写 `// RVA:` 行, 所以少 22,421 个零项。
    2) **本游戏有 1,783 个混淆方法名解码后内嵌控制字符**(含 \\n / \\r /
       \\x18 等), 写出时把一条逻辑行劈成多条物理行, 行结构被打乱。
       7.1 实测: RVA 行 711,021 条, 其中 1,783 条的下一行含控制字符,
       拼接 CS_JOIN 行后仍剩 248 条匹配不上方法名 -> 只能解出 710,773 个。
       JSON 侧因为把控制字符转义成 \\uXXXX, 这 1,783 个一个不丢。
    所以**优先用 dump.json**。
    """
    ns = cls = ""
    skipped = 0
    pending = []          # 被前瞻消费、但本身有意义的行, 要回推
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fp:
        def pull():
            """取下一行。**整个循环只能走这一个入口。**

            踩过的坑: 一边 `for line in fp` 一边 `next(fp`) ——
            回推的行在物理流之后, 顺序一乱就整篇塌掉(实测只剩 13302 个)。
            """
            return pending.pop() if pending else next(fp, "")
        while True:
            line = pull()
            if not line:
                break
            m = NS_RE.match(line)
            if m:
                ns = m.group(1).strip()
                continue
            m = CLS_RE.match(line)
            if m:
                cls = m.group(1).strip()
                if cls in ("<Module>", "<PrivateImplementationDetails>"):
                    cls = ""
                continue
            m = RVA_RE.match(line)
            if not m:
                continue
            rva = int(m.group(1), 16)
            sig = ""
            mm = None
            for _ in range(CS_JOIN):
                nxt = pull()
                if not nxt:
                    break
                # 每轮都要判, 不能只在 sig 为空时判 —— 拼了垃圾续行之后
                # 再遇到 // RVA: 行, 照样会被当成续行吞掉。
                if RVA_RE.match(nxt) or NS_RE.match(nxt) or CLS_RE.match(nxt):
                    pending.append(nxt)        # 属于下一条, 原样回推
                    break
                sig = (sig + nxt) if sig else nxt
                mm = METHOD_RE.match(sig)
                if mm:
                    break
            if not mm:
                skipped += 1
                continue
            name = mm.group(1)
            full = ((ns + "." + cls) if (ns and cls) else cls)
            sym = build_symbol(cls, ns, name, use_ns)
            if not rva or not sym:
                continue
            yield ("m", rva, sym, sig.strip() if want_comments else "")
    if skipped:
        print("[ida_apply_symbols] 警告: dump.cs 有 %d 个方法签名因内嵌控制字符"
              "拼接后仍无法解析 —— 改用 dump.json 可一个不丢" % skipped)


def pick_generator(path, use_ns, want_comments=True):
    if path.lower().endswith(".json"):
        return gen_from_json(path, use_ns, want_comments)
    return gen_from_cs(path, use_ns, want_comments)


# ============================================================================
#  IDA 内执行
# ============================================================================
RESULT = {}


def get_imagebase():
    """取当前数据库的装载基址(与版本无关,rebase 后也正确)。

    rva 定义 = 运行时函数地址 - exe 基址,与 IDA 装载基址无关;
    IDA 地址 = 当前基址 + rva。

    ⚠️ IDA 9.x: get_imagebase() 只在 ida_nalt 上(ida_ida/ida_idaapi/idaapi
    都已移除), 早先版本调 idaapi.get_imagebase() 会直接崩。
    """
    import ida_nalt
    return ida_nalt.get_imagebase()


def _auto_analysis(enable):
    """批量改名时关掉自动分析, 否则 IDA 会在每个函数上做原型/SP 推断, 卡死。"""
    try:
        import ida_auto
        if enable:
            ida_auto.enable_auto(True)
            ida_auto.auto_wait()
        else:
            ida_auto.enable_auto(False)
        return True
    except Exception:
        return False


def ida_apply_path(path, use_ns=False, comments=True, full=False):
    """在 IDA 内:解析 dump -> 命名 + 写注释。只改自动名,可重复运行。"""
    import ida_bytes
    import ida_name
    ib = get_imagebase()
    if not ib:
        print("[ida_apply_symbols] 错误: 无法获取 image base")
        return 0
    has_ui = False
    try:
        import ida_kernwin
        has_ui = True
    except ImportError:
        pass

    if has_ui:
        ida_kernwin.show_wait_box("解析 dump ...")
    had_auto = _auto_analysis(False)
    if has_ui:
        ida_kernwin.replace_wait_box("应用符号与注释 ...")

    AUTO_PREFIX = ("sub_", "nullsub_", "unk_", "locret_", "def_", "jpt_",
                   "loc_", "sub")
    st = dict(m_named=0, m_skip_name=0, m_rva0=0, t_cmt=0, p_cmt=0, e_cmt=0,
              dup=0, bad=0, seen=set())
    try:
        for kind, rva, payload, extra in pick_generator(path, use_ns, comments):
            if not rva:
                continue
            ea = ib + rva
            # 单个地址出错(非法字节/地址非法)不能中断整批 71 万条
            try:
                if kind == "m":
                    if ea in st["seen"]:
                        st["dup"] += 1
                        continue
                    st["seen"].add(ea)
                    cur = _ida_str(ida_name.get_name, ea) or ""
                    if cur and not cur.startswith(AUTO_PREFIX):
                        st["m_skip_name"] += 1
                    else:
                        try:
                            ok = ida_name.set_name(
                                ea, payload,
                                ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
                        except Exception:
                            # 旧名含非法 UTF-8 字节等 -> set_name 会抛。
                            # 重试没有意义(同样的调用同样会抛), 直接放弃这一条。
                            ok = False
                        if ok:
                            st["m_named"] += 1
                    if comments and payload:
                        _put_cmt(ida_bytes, ea, extra)
                else:
                    # 类型/属性/事件: 挂可重复注释
                    if _put_cmt(ida_bytes, ea, payload):
                        st["t_cmt" if kind == "t" else
                           ("p_cmt" if kind == "p" else "e_cmt")] += 1
            except Exception as e:
                st["bad"] += 1
                if st["bad"] <= 5:
                    print("[ida_apply_symbols] 跳过 0x%X (%s): %s"
                          % (ea - ib, kind, e))
                continue
            n = len(st["seen"])
            if has_ui and n and n % PROGRESS_EVERY == 0:
                ida_kernwin.replace_wait_box("%d 个地址已处理 ..." % n)
    finally:
        if had_auto:
            _auto_analysis(True)
        if has_ui:
            ida_kernwin.hide_wait_box()

    if not comments:
        print("[ida_apply_symbols] 完成(仅命名): 方法=%d 命名=%d 已有名字跳过=%d "
              "共享桩=%d rva0=%d%s"
              % (RESULT.get("methods", 0), st["m_named"], st["m_skip_name"],
                 st["dup"], RESULT.get("rva0", 0),
                 ("  异常跳过=%d" % st["bad"]) if st["bad"] else ""))
    else:
        print("[ida_apply_symbols] 完成:")
        print("    方法 %d  命名 %d  已有名字不覆盖 %d  共享桩 %d  rva0 %d"
              % (RESULT.get("methods", 0), st["m_named"], st["m_skip_name"],
                 st["dup"], RESULT.get("rva0", 0)))
        print("    注释: 类型块 %d  属性 %d  事件 %d  (方法签名 %d)"
              % (st["t_cmt"], st["p_cmt"], st["e_cmt"], st["m_named"]))
        if st["bad"]:
            print("    ⚠ 异常跳过 %d 个地址(多为已有注释含非法 UTF-8 字节)" % st["bad"])
    return st["m_named"]


def _ida_str(fn, *a, **kw):
    """调 IDA 的取字符串 API，**把解码异常吃掉**。

    ⚠️ 必须防这一手: 本游戏有 1,783 个混淆方法名解码后含非法 UTF-8 字节。
    如果这些字节此前被别的工具写进过注释/符号, IDA 的 Python 绑定在**返回**时
    就会炸, 早先版本就是这么崩的:
        ida_bytes.get_cmt(ea, True)
        -> UnicodeDecodeError: 'utf-8' codec can't decode byte 0xc2 ...
    一个地址炸掉会中断整个 71 万条的批量任务, 所以统一走这里。
    """
    try:
        v = fn(*a, **kw)
    except UnicodeDecodeError:
        return None
    except Exception:
        return None
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return v


def _put_cmt(ida_bytes, ea, text):
    """写可重复注释; 已有完全一样的内容就跳过(幂等)。

    旧注释读不出来时当作空处理 —— 直接用干净文本覆盖掉那堆垃圾字节,
    否则这个地址永远过不去。
    """
    text = _clip(text)
    if not text:
        return False
    old = _ida_str(ida_bytes.get_cmt, ea, True) or ""
    if text in old:
        return False
    try:
        ida_bytes.set_cmt(ea, (old + "\n" + text) if old else text, True)
    except UnicodeDecodeError:
        # 旧内容含非法字节, set_cmt 带合并也会失败 -> 覆盖写
        ida_bytes.set_cmt(ea, text, True)
    return True


def ida_interactive():
    """IDA 内交互入口:弹窗选 dump 文件,自动还原。"""
    import ida_kernwin
    path = ida_kernwin.ask_file(0, "*.json *.cs", "选择 dump 文件(dump.json 或 dump.cs)")
    if not path:
        print("[ida_apply_symbols] 已取消")
        return
    print("[ida_apply_symbols] 解析 %s ..." % path)
    ida_apply_path(path)


# ============================================================================
#  独立模式
# ============================================================================
def standalone_export(in_path, out_path, use_ns, comments=True):
    import collections
    c = collections.Counter()
    seen = set()
    kinds = collections.Counter()
    with open(out_path, "w", encoding="utf-8", errors="replace") as out:
        for kind, rva, payload, extra in pick_generator(in_path, use_ns, comments):
            kinds[kind] += 1
            if not rva:
                c["rva0"] += 1
                continue
            if kind == "m":
                if rva in seen:
                    c["shared"] += 1
                    continue
                seen.add(rva)
            out.write("0x%X\t%s\t%s\t%s\n" % (rva, kind, payload,
                                              extra.replace("\n", " | ")))
    print("[export] %s -> %s" % (dict(kinds), out_path))
    print("         方法 unique=%d 共享桩=%d 零rva=%d" % (len(seen), c["shared"], c["rva0"]))


if __name__ == "__main__":
    try:
        import ida_idaapi  # noqa: F401  仅为探测是否在 IDA 内
        IN_IDA = True
    except ImportError:
        IN_IDA = False

    if IN_IDA:
        argv = sys.argv[1:]
        if not argv:
            ida_interactive()
        else:
            import argparse
            ap = argparse.ArgumentParser(description="dump -> IDA 符号+注释")
            ap.add_argument("path")
            ap.add_argument("--ns", action="store_true")
            ap.add_argument("--no-comments", action="store_true")
            ap.add_argument("--full", action="store_true",
                            help="同时写方法签名注释(默认已开, 此开关保留兼容)")
            a = ap.parse_args()
            ida_apply_path(a.path, a.ns, not a.no_comments, a.full)
    else:
        import argparse
        ap = argparse.ArgumentParser(description="dump -> 符号表(独立模式)")
        ap.add_argument("path", nargs="?", help="dump.json / dump.cs")
        ap.add_argument("--export", nargs=2, metavar=("IN", "OUT"), help="导出符号表")
        ap.add_argument("--test", nargs=1, metavar=("IN",), help="统计解析结果")
        ap.add_argument("--ns", action="store_true")
        ap.add_argument("--no-comments", action="store_true")
        a = ap.parse_args()
        if a.export:
            standalone_export(a.export[0], a.export[1], a.ns, not a.no_comments)
        elif a.test:
            import collections
            kinds = collections.Counter()
            seen = set()
            rva0 = 0
            shared = 0
            for kind, rva, payload, extra in pick_generator(a.test[0], a.ns,
                                                          not a.no_comments):
                kinds[kind] += 1
                if not rva:
                    rva0 += 1
                    continue
                if kind == "m":
                    if rva in seen:
                        shared += 1
                        continue
                    seen.add(rva)
            print("[test] 记录 %s" % dict(kinds))
            print("       方法 unique=%d 共享桩=%d 零rva=%d" % (len(seen), shared, rva0))
        elif a.path:
            ap.print_help()
        else:
            ap.print_help()
