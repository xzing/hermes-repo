#!/usr/bin/env python3
"""
Skill/MCP Poisoning Detector
Compares recent tool calls against established baseline to detect anomalies.
Exit codes: 0=safe, 1=suspicious, 2=error
"""
import json
import os
import sys
import glob
import argparse
from collections import defaultdict

HERMES_HOME = os.path.expanduser(os.environ.get("HERMES_HOME", "~/.hermes"))
BASELINE_FILE = os.path.join(HERMES_HOME, ".security/tool-baseline.json")
SESSIONS_DIR = os.path.join(HERMES_HOME, "sessions")
REPORT_FILE = os.environ.get("REPORT_FILE", "/dev/stdout")

def build_baseline():
    sessions = sorted(glob.glob(os.path.join(SESSIONS_DIR, "session_*.json")))
    tool_schema_counts = defaultdict(lambda: defaultdict(int))
    call_freq = defaultdict(int)
    call_arg_patterns = defaultdict(lambda: defaultdict(int))

    for sess_file in sessions:
        try:
            with open(sess_file) as f:
                d = json.load(f)
        except:
            continue
        for tool in d.get("tools", []):
            fname = tool.get("function", {}).get("name", "")
            params = tool.get("function", {}).get("parameters", {})
            req = len(params.get("required", []))
            props = len(params.get("properties", {}))
            tool_schema_counts[fname][(req, props)] += 1
        for msg in d.get("messages", []):
            for tc in msg.get("tool_calls", []):
                fname = tc.get("function", {}).get("name", "")
                args_str = tc.get("function", {}).get("arguments", "{}")
                try:
                    args = json.loads(args_str) if isinstance(args_str, str) else args_str
                except:
                    args = {}
                call_freq[fname] += 1
                if fname:
                    key = frozenset(args.keys())
                    call_arg_patterns[fname][key] += 1

    def serialize_key(k):
        """k is a frozenset of argument names → deterministic string"""
        return "|".join(sorted(k)) if k else "null"

    baseline = {
        "version": "1.0",
        "generated_from": [os.path.basename(s) for s in sessions],
        "tool_schemas": {k: {f"{r},{p}": v for (r, p), v in counts.items()} for k, counts in tool_schema_counts.items()},
        "call_freq": dict(call_freq),
        "arg_patterns": {k: {serialize_key(ks): v for ks, v in patterns.items()} for k, patterns in call_arg_patterns.items()}
    }

    os.makedirs(os.path.join(HERMES_HOME, ".security"), exist_ok=True)
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"✅ 基线已建立: {len(baseline['tool_schemas'])} 工具, {sum(baseline['call_freq'].values())} 次调用记录, 来自 {len(sessions)} 个 session 文件")
    return baseline

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return None
    with open(BASELINE_FILE) as f:
        return json.load(f)

def analyze_sessions():
    sessions = sorted(glob.glob(os.path.join(SESSIONS_DIR, "session_*.json")))
    if not sessions:
        return {}

    tool_registry = defaultdict(lambda: defaultdict(int))
    call_freq = defaultdict(int)
    arg_patterns = defaultdict(lambda: defaultdict(int))
    all_calls = []

    for sess_file in sessions:
        try:
            with open(sess_file) as f:
                d = json.load(f)
        except:
            continue

        for tool in d.get("tools", []):
            fname = tool.get("function", {}).get("name", "")
            params = tool.get("function", {}).get("parameters", {})
            req = len(params.get("required", []))
            props = len(params.get("properties", {}))
            tool_registry[fname][(req, props)] += 1

        for msg in d.get("messages", []):
            for tc in msg.get("tool_calls", []):
                fname = tc.get("function", {}).get("name", "")
                args_str = tc.get("function", {}).get("arguments", "{}")
                try:
                    args = json.loads(args_str) if isinstance(args_str, str) else args_str
                except:
                    args = {}
                call_freq[fname] += 1
                if fname:
                    key = frozenset(args.keys())
                    arg_patterns[fname][key] += 1
                    all_calls.append({"tool": fname, "args": args, "keys": list(key)})

    return {
        "registry": tool_registry,
        "freq": dict(call_freq),
        "patterns": arg_patterns,
        "calls": all_calls[-500:]
    }

def analyze_recent_sessions(n=3):
    """分析最近 N 个 session，与基线对比检测新增异常"""
    sessions = sorted(glob.glob(os.path.join(SESSIONS_DIR, "session_*.json")))
    if not sessions:
        return {}

    sessions = sessions[-n:]  # 只看最近 n 个

    new_tools = defaultdict(int)
    new_arg_patterns = defaultdict(lambda: defaultdict(int))
    recent_calls = []

    for sess_file in sessions:
        try:
            with open(sess_file) as f:
                d = json.load(f)
        except:
            continue

        for msg in d.get("messages", []):
            for tc in msg.get("tool_calls", []):
                fname = tc.get("function", {}).get("name", "")
                args_str = tc.get("function", {}).get("arguments", "{}")
                try:
                    args = json.loads(args_str) if isinstance(args_str, str) else args_str
                except:
                    args = {}
                if fname:
                    key = frozenset(args.keys())
                    new_arg_patterns[fname][key] += 1
                    new_tools[fname] += 1
                    recent_calls.append({"tool": fname, "args": args, "keys": list(key)})

    return {
        "tools": dict(new_tools),
        "patterns": new_arg_patterns,
        "calls": recent_calls
    }

def detect_anomalies(baseline, recent):
    """用最近 session 与基线比对，只检测真正的新增异常"""
    findings = []
    if not baseline:
        findings.append(("NO_BASELINE", "无基线，请先建立基线"))
        return findings

    base_freq = baseline.get("call_freq", {})
    base_patterns_raw = baseline.get("arg_patterns", {})
    base_schemas_raw = baseline.get("tool_schemas", {})

    def deserialize_key(k):
        return frozenset(k.split("|")) if k and k != "null" else frozenset()

    base_patterns = {
        tool: {deserialize_key(k): v for k, v in patterns.items()}
        for tool, patterns in base_patterns_raw.items()
    }

    curr_tools = recent.get("tools", {})
    curr_patterns = recent.get("patterns", {})

    # 1. 新工具出现（基线完全没有的工具）
    for tool in curr_tools:
        if tool not in base_freq:
            findings.append(("NEW_TOOL", f"新工具: {tool} (最近调用{ curr_tools[tool]}次)"))

    # 2. 新参数模式（在已知工具上出现基线没有的参数组合）
    for tool, patterns in curr_patterns.items():
        if tool not in base_patterns:
            continue
        base_p = base_patterns[tool]
        for arg_keys, count in patterns.items():
            if arg_keys and arg_keys not in base_p:
                findings.append(("NEW_ARG_PATTERN", f"工具 {tool} 新参数组合: {sorted(arg_keys)} (出现{count}次)"))

    # 3. 频率突增（该工具历史从未/很少调用，但最近频繁出现）
    for tool, count in curr_tools.items():
        base_count = base_freq.get(tool, 0)
        if base_count == 0 and count >= 3:
            findings.append(("HIGH_FREQ", f"工具 {tool} 历史无记录但最近调用{count}次 — 疑似污染"))

    return findings

def main():
    parser = argparse.ArgumentParser(description="Skill/MCP Poisoning Detector")
    parser.add_argument("--build-baseline", action="store_true", help="建立工具签名基线")
    parser.add_argument("--check", action="store_true", help="与基线比对检测异常")
    args = parser.parse_args()

    if args.build_baseline:
        build_baseline()
        return

    if args.check or not os.path.exists(BASELINE_FILE):
        baseline = load_baseline()
        recent = analyze_recent_sessions(n=3)
        findings = detect_anomalies(baseline, recent)

        if not baseline:
            print("⚠️  无基线文件，请先运行: python3 detect-skill-poisoning.py --build-baseline")
            sys.exit(0)

        if not findings:
            print(f"✅ 工具签名检测通过 (最近 3 个 session 共 {len(recent['calls'])} 次调用)")
            sys.exit(0)

        grouped = defaultdict(list)
        for kind, msg in findings:
            grouped[kind].append(msg)

        for kind, msgs in grouped.items():
            icon = {"NEW_TOOL": "🆕", "HIGH_FREQ": "⚠️", "NEW_ARG_PATTERN": "🔍", "SCHEMA_DRIFT": "🔄"}.get(kind, "❓")
            for m in msgs[:10]:
                print(f"{icon} [{kind}] {m}")
            if len(msgs) > 10:
                print(f"   ... 还有 {len(msgs)-10} 项")
        sys.exit(1)
    else:
        # Default: build baseline
        build_baseline()

if __name__ == "__main__":
    main()
