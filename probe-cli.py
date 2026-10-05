#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MyProbe 拨测任务终端管理工具（v6.2+）

直接读写服务端 SQLite，无需经过 Web 界面。适合 SSH 上服务器后快速增删改查拨测任务。

用法：
    probe-cli.py list
    probe-cli.py add --name 浙江移动 --type tcp --host 223.5.5.5 --port 53
    probe-cli.py add --name 浙江联通 --type http --host https://www.10010.com
    probe-cli.py add --name 内网网关 --type ping --host 192.168.1.1 --interval 30
    probe-cli.py del 3
    probe-cli.py enable 3 | probe-cli.py disable 3
    probe-cli.py test 3            # 服务端即时执行一次拨测，显示延迟/丢包

数据库路径：环境变量 MYPROBE_DB，默认 /opt/myprobe/data/myprobe.db（不存在则试 ./data/myprobe.db）
"""
import argparse
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request


def db_path():
    p = os.environ.get("MYPROBE_DB")
    if p:
        return p
    for c in ("/opt/myprobe/data/myprobe.db", "./data/myprobe.db",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "myprobe.db")):
        if os.path.exists(c):
            return c
    return "/opt/myprobe/data/myprobe.db"


def get_db():
    p = db_path()
    if not os.path.exists(p):
        sys.exit(f"找不到数据库：{p}（可用 MYPROBE_DB 环境变量指定）")
    db = sqlite3.connect(p)
    db.row_factory = sqlite3.Row
    return db


def valid(d):
    """与服务端 valid_probe_task 同规则的校验。返回 (ok, err)。"""
    name = (d.get("name") or "").strip()
    ttype = (d.get("type") or "").strip()
    host = (d.get("host") or "").strip()
    if not name or len(name) > 64:
        return False, "名称不能为空（64字符内）"
    if ttype not in ("ping", "tcp", "http"):
        return False, "类型只能是 ping / tcp / http"
    if not host or len(host) > 256:
        return False, "目标 host 不能为空"
    try:
        interval = int(d.get("interval") or 60)
    except Exception:
        return False, "间隔必须是数字"
    if not 10 <= interval <= 86400:
        return False, "间隔需在 10~86400 秒之间"
    if ttype == "tcp":
        try:
            port = int(d.get("port") or 0)
        except Exception:
            return False, "TCP 端口必须是数字"
        if not 1 <= port <= 65535:
            return False, "TCP 端口需在 1~65535 之间"
    return True, ""


def _ping_parse(out):
    """解析 ping 输出，返回 (avg_ms 或 None, loss_%)。"""
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    loss = float(m.group(1)) if m else 100.0
    m = re.search(r"(?:rtt|round-trip).*?=\s*[\d.]+/([\d.]+)/", out)
    if m:
        return float(m.group(1)), loss
    m = re.search(r"Average = (\d+)ms", out)
    if m:
        return float(m.group(1)), loss
    return (None, loss) if loss >= 100 else (None, loss)


def run_probe_now(t):
    """服务端即时执行单个拨测任务 3 次。返回 (avg_latency_ms 或 None, loss_%)。绝不抛异常。"""
    try:
        ttype = (t.get("type") or "").strip() if isinstance(t, dict) else t["type"]
        host = (t.get("host") or "").strip() if isinstance(t, dict) else t["host"]
        port = t.get("port") if isinstance(t, dict) else t["port"]
        path = (t.get("path") or "").strip() if isinstance(t, dict) else (t["path"] or "")
        if not host or ttype not in ("ping", "tcp", "http"):
            return (None, 100.0)
        n = 3
        if ttype == "ping":
            cmd = ["ping", "-c", str(n), "-W", "2", host]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return _ping_parse(p.stdout or "")
            except Exception:
                return (None, 100.0)
        elif ttype == "tcp":
            port = int(port or 80)
            lat, fails = [], 0
            for _ in range(n):
                s = socket.socket()
                s.settimeout(3)
                t0 = time.time()
                try:
                    s.connect((host, port))
                    lat.append((time.time() - t0) * 1000)
                except Exception:
                    fails += 1
                finally:
                    s.close()
            return (sum(lat) / len(lat) if lat else None, fails / n * 100.0)
        else:  # http（与 agent 一致，用 urllib，无第三方依赖）
            url = host if host.startswith("http") else "http://" + host
            if path:
                url = url.rstrip("/") + path
            lat, fails = [], 0
            for _ in range(n):
                t0 = time.time()
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 MyProbe"})
                    with urllib.request.urlopen(req, timeout=6) as r:
                        r.read(1024)  # 读到响应头即可
                    lat.append((time.time() - t0) * 1000)
                except Exception:
                    fails += 1
            return (sum(lat) / len(lat) if lat else None, fails / n * 100.0)
    except Exception:
        return (None, 100.0)


def cmd_list(args):
    db = get_db()
    rows = db.execute("SELECT * FROM probe_tasks ORDER BY id").fetchall()
    db.close()
    if not rows:
        print("暂无拨测任务")
        return
    print(f"{'ID':<4}{'名称':<14}{'类型':<6}{'目标':<32}{'间隔':<8}状态")
    print("-" * 80)
    for r in rows:
        tgt = r["host"]
        if r["type"] == "tcp" and r["port"]:
            tgt += f":{r['port']}"
        if r["type"] == "http" and r["path"]:
            tgt += r["path"]
        print(f"{r['id']:<4}{r['name']:<14}{r['type']:<6}{tgt:<32}{r['interval']}s     "
              f"{'启用' if r['enabled'] else '停用'}")


def cmd_add(args):
    d = {"name": args.name, "type": args.type, "host": args.host,
         "port": args.port, "path": args.path, "interval": args.interval}
    ok, err = valid(d)
    if not ok:
        sys.exit(f"参数错误：{err}")
    db = get_db()
    cur = db.execute(
        """INSERT INTO probe_tasks (name, type, host, port, path, interval, enabled, created)
           VALUES (?,?,?,?,?,?,1,?)""",
        (d["name"].strip(), d["type"], d["host"].strip(),
         int(d["port"]) if d["type"] == "tcp" and d["port"] else None,
         (d["path"] or "").strip()[:256] or None,
         int(d["interval"]), int(time.time())))
    db.commit()
    tid = cur.lastrowid
    db.close()
    print(f"✅ 已添加拨测任务 #{tid}（{d['name']}），各节点将在 60 秒内开始探测")


def cmd_del(args):
    db = get_db()
    cur = db.execute("DELETE FROM probe_tasks WHERE id=?", (args.id,))
    db.commit()
    db.close()
    print("✅ 已删除" if cur.rowcount else f"未找到任务 #{args.id}")


def cmd_enable(args, on):
    db = get_db()
    cur = db.execute("UPDATE probe_tasks SET enabled=? WHERE id=?", (1 if on else 0, args.id))
    db.commit()
    db.close()
    print(f"✅ 已{'启用' if on else '停用'}任务 #{args.id}" if cur.rowcount else f"未找到任务 #{args.id}")


def cmd_test(args):
    db = get_db()
    r = db.execute("SELECT * FROM probe_tasks WHERE id=?", (args.id,)).fetchone()
    db.close()
    if not r:
        sys.exit(f"未找到任务 #{args.id}")
    t = dict(r)
    print(f"正在测试 #{t['id']} {t['name']}（{t['type']} {t['host']}）…")
    lat, loss = run_probe_now(t)
    if lat is None:
        print(f"❌ 不通（丢包 {loss:.0f}%）")
    else:
        print(f"✅ 通！延迟 {lat:.0f} ms，丢包 {loss:.0f}%")


def main():
    ap = argparse.ArgumentParser(prog="probe-cli.py", description="MyProbe 拨测任务终端管理")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="列出所有拨测任务")

    a = sub.add_parser("add", help="添加拨测任务")
    a.add_argument("--name", required=True, help="任务名称，如 浙江移动")
    a.add_argument("--type", required=True, choices=["ping", "tcp", "http"], help="探测类型")
    a.add_argument("--host", required=True, help="ping/tcp 填 IP 或域名；http 填完整 URL 或域名")
    a.add_argument("--port", type=int, default=None, help="TCP 端口（tcp 类型必填）")
    a.add_argument("--path", default="", help="HTTP 路径（http 类型可选）")
    a.add_argument("--interval", type=int, default=60, help="探测间隔秒（默认 60）")

    d = sub.add_parser("del", help="删除拨测任务")
    d.add_argument("id", type=int)

    e = sub.add_parser("enable", help="启用拨测任务")
    e.add_argument("id", type=int)
    e2 = sub.add_parser("disable", help="停用拨测任务")
    e2.add_argument("id", type=int)

    t = sub.add_parser("test", help="服务端即时测试一次")
    t.add_argument("id", type=int)

    args = ap.parse_args()
    if args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "add":
        cmd_add(args)
    elif args.cmd == "del":
        cmd_del(args)
    elif args.cmd == "enable":
        cmd_enable(args, True)
    elif args.cmd == "disable":
        cmd_enable(args, False)
    elif args.cmd == "test":
        cmd_test(args)


if __name__ == "__main__":
    main()
