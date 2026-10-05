#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MyProbe Server —— 自建服务器探针服务端
- Flask + SQLite，单文件，零外部前端依赖（图表用原生 canvas 手写）
- Agent 通过共享 Token 上报指标（POST /api/report），默认 5 秒一次
- 看板公开只读；改名/删除节点需要管理员登录
- v6 新增内置 Web SSH 终端（💻 终端）：密码 Fernet 加密存库，仅管理员可用
  （用户明确要求，此功能改变了 v1"只读监控、不做远程命令执行"的定位）
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import collections
from datetime import date, datetime
from email.message import EmailMessage
from functools import wraps

from flask import Flask, Response, g, jsonify, redirect, request, send_from_directory, session, url_for

# ---------------- 配置 ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_TOKEN = os.environ.get("MYPROBE_TOKEN", "").strip()          # Agent 上报密钥（必填）
ADMIN_USER = os.environ.get("MYPROBE_ADMIN_USER", "admin").strip()
ADMIN_PASS = os.environ.get("MYPROBE_ADMIN_PASS", "").strip()      # 管理员密码（必填）
FLASK_SECRET = os.environ.get("MYPROBE_SECRET", "").strip()
DB_PATH = os.environ.get("MYPROBE_DB", os.path.join(BASE_DIR, "data", "myprobe.db"))
PORT = int(os.environ.get("MYPROBE_PORT", "17234"))
INTERVAL = int(os.environ.get("MYPROBE_INTERVAL", "5"))            # 期望上报间隔（秒）
RETENTION_DAYS = 30          # 原始数据保留天数
OFFLINE_AFTER = max(INTERVAL * 6, 30)  # 超过这么久没上报判为离线

if not FLASK_SECRET:
    FLASK_SECRET = secrets.token_hex(32)
    print("[WARN] 未设置 MYPROBE_SECRET，已随机生成（重启后登录会话失效）", file=sys.stderr)
if not AGENT_TOKEN:
    print("[FATAL] 必须设置环境变量 MYPROBE_TOKEN（Agent 上报密钥）", file=sys.stderr)
    sys.exit(1)
if not ADMIN_PASS:
    print("[FATAL] 必须设置环境变量 MYPROBE_ADMIN_PASS（管理员密码）", file=sys.stderr)
    sys.exit(1)

ADMIN_PASS_HASH = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()

app = Flask(__name__)
app.secret_key = FLASK_SECRET

# ---------------- 数据库 ----------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    hostname    TEXT,
    os          TEXT,
    platform    TEXT,
    arch        TEXT,
    cpu_model   TEXT,
    cpu_cores   INTEGER,
    mem_total   INTEGER,
    disk_total  INTEGER,
    ip          TEXT,
    first_seen  INTEGER,
    last_seen   INTEGER
);
CREATE TABLE IF NOT EXISTS metrics (
    node_id   TEXT NOT NULL,
    ts        INTEGER NOT NULL,
    cpu       REAL,
    mem       REAL,
    swap      REAL,
    disk      REAL,
    rx        INTEGER,   -- 下行速率 bytes/s
    tx        INTEGER,   -- 上行速率 bytes/s
    load1     REAL,
    uptime    INTEGER,
    PRIMARY KEY (node_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(ts);
"""

# v2 新增表（幂等：全部 IF NOT EXISTS）
SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS probe_tasks (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    type      TEXT NOT NULL,          -- ping / tcp / http
    host      TEXT NOT NULL,
    port      INTEGER,                -- tcp 用
    path      TEXT,                   -- http 用，如 /emby/System/Info/Public
    interval  INTEGER DEFAULT 60,     -- 探测间隔（秒）
    enabled   INTEGER DEFAULT 1,
    created   INTEGER
);
CREATE TABLE IF NOT EXISTS probe_results (
    task_id  INTEGER NOT NULL,
    ts       INTEGER NOT NULL,
    latency  REAL,                     -- 平均延迟 ms（全失败则为 NULL）
    loss     REAL,                     -- 丢包率 %
    ok       INTEGER,                  -- 至少一次成功=1
    PRIMARY KEY (task_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_probe_results_ts ON probe_results(ts);
CREATE TABLE IF NOT EXISTS traffic_monthly (
    node_id   TEXT NOT NULL,
    month     TEXT NOT NULL,            -- YYYY-MM
    rx_bytes  INTEGER DEFAULT 0,
    tx_bytes  INTEGER DEFAULT 0,
    PRIMARY KEY (node_id, month)
);
CREATE TABLE IF NOT EXISTS traffic_daily (
    node_id   TEXT NOT NULL,
    day       TEXT NOT NULL,            -- YYYY-MM-DD
    rx_bytes  INTEGER DEFAULT 0,
    tx_bytes  INTEGER DEFAULT 0,
    PRIMARY KEY (node_id, day)
);
CREATE TABLE IF NOT EXISTS alert_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    metric     TEXT NOT NULL,           -- cpu / mem / offline
    threshold  REAL DEFAULT 0,          -- cpu/mem 的百分比阈值；offline 不用
    duration   INTEGER DEFAULT 5,       -- 持续 N 分钟才告警（0=立即）
    enabled    INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS alert_channels (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    type    TEXT NOT NULL,              -- webhook / telegram / email
    name    TEXT NOT NULL,
    config  TEXT NOT NULL,              -- JSON
    enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS alert_state (
    rule_id   INTEGER NOT NULL,
    node_id   TEXT NOT NULL,
    bad_since INTEGER,
    alerted   INTEGER DEFAULT 0,
    PRIMARY KEY (rule_id, node_id)
);
CREATE TABLE IF NOT EXISTS alerts_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    rule_id  INTEGER,
    node_id  TEXT,
    message  TEXT,
    level    TEXT                       -- firing / resolved
);
CREATE INDEX IF NOT EXISTS idx_alerts_log_ts ON alerts_log(ts);
"""

# v2 新增的 nodes 列（幂等迁移）
NODE_NEW_COLS = [
    ("price", "REAL"),          # 套餐价格
    ("currency", "TEXT"),       # 货币符号，如 ¥ / $
    ("bill_cycle", "TEXT"),     # monthly / yearly
    ("buy_date", "TEXT"),       # 购买日期 YYYY-MM-DD
    ("expire_date", "TEXT"),    # 到期日期 YYYY-MM-DD
    ("quota_gb", "REAL"),       # 月流量配额 GB
    ("quota_base_gb", "REAL"),  # v4.1：本月已用基准 GB（上线前已用流量，手动填）
    ("quota_base_month", "TEXT"),  # v4.1：基准所属月份 YYYY-MM，跨月自动失效
    ("ssh_host", "TEXT DEFAULT ''"),    # v5.1：SSH 主机（IP/域名），空=不显示 SSH 按钮
    ("ssh_port", "INTEGER DEFAULT 22"),  # v5.1：SSH 端口
    ("ssh_user", "TEXT DEFAULT 'root'"),  # v5.1：SSH 用户名
    ("ssh_pass_enc", "TEXT DEFAULT ''"),  # v6.0：SSH 密码（Fernet 加密），空=未保存
    ("sort_order", "INTEGER DEFAULT 0"),  # v6.1：看板卡片手动排序（越小越靠前）
]

def migrate(db):
    """v2/v3 迁移：建新表 + 给 nodes 加列，全部幂等，老库直接可用。"""
    db.executescript(SCHEMA_V2)
    db.executescript(SCHEMA_V3)
    db.executescript(SCHEMA_V5)
    cols = {r[1] for r in db.execute("PRAGMA table_info(nodes)").fetchall()}
    had_sort_order = "sort_order" in cols
    for name, ddl in NODE_NEW_COLS:
        if name not in cols:
            db.execute(f"ALTER TABLE nodes ADD COLUMN {name} {ddl}")
    if not had_sort_order:
        # v6.1：老库回填排序基准（按 rowid 顺序），仅在列新建时执行一次
        for i, r in enumerate(db.execute("SELECT id FROM nodes ORDER BY rowid").fetchall()):
            db.execute("UPDATE nodes SET sort_order=? WHERE id=?", (i, r[0]))
    db.commit()

def db_conn():
    """给后台线程用的独立连接（带 WAL + 迁移）。"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    migrate(db)
    return db

def get_db():
    if "db" not in g:
        g.db = db_conn()
    return g.db

@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

_last_prune = 0

def maybe_prune(db):
    """定期清理超过保留期的数据（最多每小时跑一次）。"""
    global _last_prune
    now = int(time.time())
    if now - _last_prune < 3600:
        return
    _last_prune = now
    cutoff = now - RETENTION_DAYS * 86400
    cur = db.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))
    db.commit()
    # v2：拨测结果保留 30 天，告警记录保留 90 天
    try:
        db.execute("DELETE FROM probe_results WHERE ts < ?", (cutoff,))
        db.execute("DELETE FROM alerts_log WHERE ts < ?", (now - 90 * 86400,))
        # v5：各节点拨测历史只保留 48 小时
        db.execute("DELETE FROM node_probe_history WHERE ts < ?", (now - 48 * 3600,))
        db.commit()
    except Exception:
        pass
    if cur.rowcount:
        print(f"[prune] 清理 {cur.rowcount} 条过期指标数据", flush=True)

# ---------------- 工具 ----------------
NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

def valid_node_id(nid):
    return isinstance(nid, str) and bool(NODE_ID_RE.match(nid))

def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""

def is_online(last_seen):
    return (int(time.time()) - (last_seen or 0)) <= OFFLINE_AFTER

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("admin"):
            return jsonify({"ok": False, "error": "需要管理员登录"}), 401
        return f(*a, **kw)
    return wrapper

# ---------------- Agent 上报 ----------------
# v4.2：agent 自助下发 —— 看板直接提供 agent.py 和一键安装脚本，无需第三方文件链接
with open(os.path.join(BASE_DIR, "agent.py"), encoding="utf-8") as _f:
    AGENT_PY_SRC = _f.read()

AGENT_INSTALL_SH = r"""#!/bin/bash
# MyProbe Agent 一键安装（在「被监控」机器上以 root 执行）
# 用法：curl -fsSL <看板地址>/dl/agent-install.sh | bash -s -- <看板地址> <Token> <节点ID> <显示名>
# 例子：curl -fsSL https://probe.example.com/dl/agent-install.sh | bash -s -- https://probe.example.com 你的Token de-vps "德国CF"
set -e
SERVER="$1"; TOKEN="$2"; NODE_ID="$3"; NAME="$4"
if [ "$(id -u)" != "0" ]; then echo "请用 root 运行"; exit 1; fi
if [ -z "$SERVER" ] || [ -z "$TOKEN" ] || [ -z "$NODE_ID" ] || [ -z "$NAME" ]; then
  echo "用法: curl -fsSL <看板地址>/dl/agent-install.sh | bash -s -- <看板地址> <Token> <节点ID> <显示名>"
  echo '例子: curl -fsSL https://probe.example.com/dl/agent-install.sh | bash -s -- https://probe.example.com 你的Token de-vps "德国CF"'
  exit 1
fi
echo "== 装依赖 psutil =="
if ! python3 -c "import psutil" >/dev/null 2>&1; then
  if command -v pip3 >/dev/null 2>&1; then
    pip3 install -q --break-system-packages psutil
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq python3-psutil
  else
    echo "[ERROR] 装不上 psutil：没有 pip3 也没有 apt-get，手动装一个再重跑"; exit 1
  fi
  python3 -c "import psutil" >/dev/null 2>&1 || { echo "[ERROR] psutil 还是装不上"; exit 1; }
else
  echo "psutil 已存在，跳过"
fi
echo "== 下载 agent =="
mkdir -p /opt/myprobe
curl -fsSL "$SERVER/dl/agent.py" -o /opt/myprobe/agent.py
echo "== 写 systemd 服务 =="
cat > /etc/systemd/system/myprobe-agent.service <<EOF
[Unit]
Description=MyProbe Agent ($NODE_ID)
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/opt/myprobe
Environment=MYPROBE_SERVER=$SERVER
Environment=MYPROBE_TOKEN=$TOKEN
Environment=MYPROBE_NODE_ID=$NODE_ID
Environment=MYPROBE_NAME=$NAME
ExecStart=/usr/bin/python3 /opt/myprobe/agent.py
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable myprobe-agent >/dev/null 2>&1
systemctl restart myprobe-agent
sleep 4
if systemctl is-active --quiet myprobe-agent; then
  echo "🎉 Agent 已启动：$NAME（$NODE_ID），正在向 $SERVER 上报，约 10 秒后看板可见"
else
  echo "[ERROR] Agent 没起来：journalctl -u myprobe-agent -n 50"; exit 1
fi
"""

@app.route("/dl/agent.py")
def dl_agent():
    return Response(AGENT_PY_SRC, mimetype="text/plain")

@app.route("/dl/agent-install.sh")
def dl_agent_install():
    return Response(AGENT_INSTALL_SH, mimetype="text/x-sh")

@app.route("/api/report", methods=["POST"])
def api_report():
    token = request.headers.get("X-Token", "")
    if not hmac.compare_digest(token, AGENT_TOKEN):
        return jsonify({"ok": False, "error": "token 无效"}), 403
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "JSON 解析失败"}), 400
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "数据格式错误"}), 400

    nid = data.get("node_id") or ""
    if not valid_node_id(nid):
        return jsonify({"ok": False, "error": "node_id 不合法（限字母数字/_/-，64字符内）"}), 400

    host = data.get("host") or {}
    m = data.get("metrics") or {}
    now = int(time.time())
    db = get_db()

    row = db.execute("SELECT id, name FROM nodes WHERE id=?", (nid,)).fetchone()
    if row is None:
        # v6.1：新节点排到末尾
        mx = db.execute("SELECT MAX(sort_order) FROM nodes").fetchone()[0]
        new_order = (mx if mx is not None else -1) + 1
        db.execute(
            """INSERT INTO nodes (id, name, hostname, os, platform, arch, cpu_model,
                                  cpu_cores, mem_total, disk_total, ip, first_seen, last_seen, sort_order)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (nid, data.get("name") or host.get("hostname") or nid,
             host.get("hostname"), host.get("os"), host.get("platform"),
             host.get("arch"), host.get("cpu_model"), host.get("cpu_cores"),
             host.get("mem_total"), host.get("disk_total"),
             client_ip(), now, now, new_order),
        )
    else:
        db.execute(
            """UPDATE nodes SET hostname=?, os=?, platform=?, arch=?, ip=?, last_seen=?
               WHERE id=?""",
            (host.get("hostname"), host.get("os"), host.get("platform"),
             host.get("arch"), client_ip(), now, nid),
        )

    def f(key):
        v = m.get(key)
        return float(v) if isinstance(v, (int, float)) else None

    def i(key):
        v = m.get(key)
        return int(v) if isinstance(v, (int, float)) else None

    # v2：流量累计 —— 用（速率 × 时间差）折算字节数，记入当月桶
    prev = db.execute(
        "SELECT ts FROM metrics WHERE node_id=? ORDER BY ts DESC LIMIT 1",
        (nid,),
    ).fetchone()
    rxv, txv = i("rx"), i("tx")

    db.execute(
        """INSERT OR REPLACE INTO metrics
           (node_id, ts, cpu, mem, swap, disk, rx, tx, load1, uptime)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (nid, now, f("cpu"), f("mem"), f("swap"), f("disk"),
         rxv, txv, f("load1"), i("uptime")),
    )
    if prev and prev["ts"] and rxv is not None and txv is not None:
        dt = now - prev["ts"]
        if 0 < dt <= INTERVAL * 3:  # 间隔异常大（离线很久）则不计，避免虚增
            month = time.strftime("%Y-%m", time.localtime(now))
            db.execute(
                """INSERT INTO traffic_monthly (node_id, month, rx_bytes, tx_bytes)
                   VALUES (?,?,?,?)
                   ON CONFLICT(node_id, month) DO UPDATE SET
                     rx_bytes = rx_bytes + excluded.rx_bytes,
                     tx_bytes = tx_bytes + excluded.tx_bytes""",
                (nid, month, rxv * dt, txv * dt),
            )
            # v4：每日流量 —— 同一份数据再记入按天桶（累计流量只读月桶，不重复计）
            day = time.strftime("%Y-%m-%d", time.localtime(now))
            db.execute(
                """INSERT INTO traffic_daily (node_id, day, rx_bytes, tx_bytes)
                   VALUES (?,?,?,?)
                   ON CONFLICT(node_id, day) DO UPDATE SET
                     rx_bytes = rx_bytes + excluded.rx_bytes,
                     tx_bytes = tx_bytes + excluded.tx_bytes""",
                (nid, day, rxv * dt, txv * dt),
            )
    db.commit()
    # v5：agent 自带拨测结果入库（最新值 + 历史）
    np = data.get("probes")
    if isinstance(np, dict):
        for tid_s, v in np.items():
            try:
                tid = int(tid_s)
            except (TypeError, ValueError):
                continue
            if not isinstance(v, dict):
                continue
            lat = v.get("lat")
            loss = v.get("loss")
            lat = float(lat) if isinstance(lat, (int, float)) else None
            loss = float(loss) if isinstance(loss, (int, float)) else None
            if lat is not None and not (0 <= lat <= 600000):
                lat = None
            if loss is not None:
                loss = max(0.0, min(100.0, loss))
            ok = 1 if lat is not None else 0
            db.execute(
                """INSERT INTO node_probe_results (node_id, task_id, ts, latency_ms, loss_pct)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(node_id, task_id) DO UPDATE SET
                     ts=excluded.ts, latency_ms=excluded.latency_ms, loss_pct=excluded.loss_pct""",
                (nid, tid, now, lat, loss),
            )
            db.execute(
                """INSERT OR IGNORE INTO node_probe_history
                   (node_id, task_id, ts, latency_ms, ok) VALUES (?,?,?,?,?)""",
                (nid, tid, now, lat, ok),
            )
        db.commit()
    maybe_prune(db)
    # v3：插件钩子（异常隔离，单个插件出错不影响上报）
    try:
        fire_plugin_hook("on_report", node_id=nid,
                         report={"node_id": nid, "host": host, "metrics": m, "ts": now})
    except Exception:
        pass
    # v5：下发拨测任务列表，agent 每 60 秒自行探测
    ptasks = db.execute(
        "SELECT id, name, type, host, port, path FROM probe_tasks WHERE enabled=1 ORDER BY id"
    ).fetchall()
    return jsonify({"ok": True, "interval": INTERVAL,
                    "probes": [{"id": t["id"], "name": t["name"], "type": t["type"],
                                "host": t["host"], "port": t["port"], "path": t["path"]}
                               for t in ptasks]})

# ---------------- 公开查询 API ----------------
def parse_ymd(s):
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%d").date()
    except Exception:
        return None

def node_extra(db, row):
    """v2：配额 / 到期 / 余值 等计算字段。"""
    extra = {}
    for k in ("price", "currency", "bill_cycle", "buy_date", "expire_date", "quota_gb",
               "quota_base_gb", "quota_base_month",
               "ssh_host", "ssh_port", "ssh_user"):
        try:
            extra[k] = row[k]
        except (IndexError, KeyError):
            extra[k] = None
    # —— 到期 & 余值 ——
    days_left = None
    remain_value = None
    exp = parse_ymd(extra["expire_date"] or "")
    if exp:
        days_left = (exp - date.today()).days
        if extra["price"]:
            buy = parse_ymd(extra["buy_date"] or "")
            if buy and (exp - buy).days > 0:
                total = (exp - buy).days
            else:
                total = 365 if (extra["bill_cycle"] or "") == "yearly" else 30
            remain_value = round(float(extra["price"]) * max(0, days_left) / total, 2)
    extra["days_left"] = days_left
    extra["remain_value"] = remain_value
    # —— v6.0：SSH 终端就绪（主机已填 + 已存密码）；密码本身永不外泄 ——
    try:
        _enc = row["ssh_pass_enc"] or ""
    except (IndexError, KeyError):
        _enc = ""
    extra["ssh_ready"] = bool((extra.get("ssh_host") or "").strip()) and bool(_enc)
    # —— 流量 ——
    month = time.strftime("%Y-%m", time.localtime())
    mr = db.execute(
        "SELECT rx_bytes, tx_bytes FROM traffic_monthly WHERE node_id=? AND month=?",
        (row["id"], month),
    ).fetchone()
    month_rx = (mr["rx_bytes"] or 0) if mr else 0
    month_tx = (mr["tx_bytes"] or 0) if mr else 0
    tr = db.execute(
        "SELECT SUM(rx_bytes) r, SUM(tx_bytes) t FROM traffic_monthly WHERE node_id=?",
        (row["id"],),
    ).fetchone()
    extra["month_rx_gb"] = round(month_rx / 1024**3, 2)
    extra["month_tx_gb"] = round(month_tx / 1024**3, 2)
    extra["total_rx_gb"] = round((tr["r"] or 0) / 1024**3, 2)
    extra["total_tx_gb"] = round((tr["t"] or 0) / 1024**3, 2)
    q = extra["quota_gb"]
    if q and q > 0:
        used = (month_rx + month_tx) / 1024**3
        # v4.1：加上本月已用基准（仅当月有效，跨月自动失效）
        base = extra.get("quota_base_gb")
        if base and base > 0 and extra.get("quota_base_month") == month:
            used += base
        extra["quota_used_gb"] = round(used, 2)
        extra["quota_pct"] = round(min(100.0, used / q * 100), 1)
    else:
        extra["quota_used_gb"] = None
        extra["quota_pct"] = None
    return extra

def node_probes(db, nid):
    """v5：该节点各拨测任务的最新结果 + 近 22 次历史（画条形图用，最老在前）。"""
    tasks = db.execute("SELECT id, name FROM probe_tasks ORDER BY id").fetchall()
    out = []
    for t in tasks:
        r = db.execute(
            "SELECT latency_ms, loss_pct, ts FROM node_probe_results"
            " WHERE node_id=? AND task_id=?",
            (nid, t["id"]),
        ).fetchone()
        hist = db.execute(
            "SELECT ok, latency_ms FROM node_probe_history WHERE node_id=? AND task_id=?"
            " ORDER BY ts DESC LIMIT 22",
            (nid, t["id"]),
        ).fetchall()
        hist = list(reversed(hist))  # 最老在前（与旧版 /api/probes 一致）
        out.append({
            "task_id": t["id"], "name": t["name"],
            "latency_ms": r["latency_ms"] if r else None,
            "loss_pct": r["loss_pct"] if r else None,
            "ts": r["ts"] if r else None,
            "bars": [int(h["ok"]) for h in hist],
            "hist_lat": [h["latency_ms"] for h in hist],
        })
    return out

def node_latest(db, row):
    """拼出节点 + 最新一条指标。"""
    m = db.execute(
        "SELECT * FROM metrics WHERE node_id=? ORDER BY ts DESC LIMIT 1",
        (row["id"],),
    ).fetchone()
    md = dict(m) if m else {}
    d = {
        "id": row["id"],
        "name": row["name"],
        "hostname": row["hostname"],
        "os": row["os"],
        "platform": row["platform"],
        "arch": row["arch"],
        "cpu_cores": row["cpu_cores"],
        "mem_total": row["mem_total"],
        "disk_total": row["disk_total"],
        "ip": row["ip"],
        "last_seen": row["last_seen"],
        "online": is_online(row["last_seen"]),
        "cpu": md.get("cpu"),
        "mem": md.get("mem"),
        "swap": md.get("swap"),
        "disk": md.get("disk"),
        "rx": md.get("rx"),
        "tx": md.get("tx"),
        "load1": md.get("load1"),
        "uptime": md.get("uptime"),
        "sort_order": row["sort_order"] if "sort_order" in row.keys() else 0,
        "probes": node_probes(db, row["id"]),   # v5：本节点独立拨测结果
    }
    d.update(node_extra(db, row))
    return d

@app.route("/api/nodes")
def api_nodes():
    db = get_db()
    rows = db.execute("SELECT * FROM nodes ORDER BY sort_order ASC, id ASC").fetchall()
    return jsonify({"ok": True, "now": int(time.time()),
                    "interval": INTERVAL, "offline_after": OFFLINE_AFTER,
                    "nodes": [node_latest(db, r) for r in rows]})

RANGES = {
    "1h":  (3600, 5),        # 范围秒数, 采样桶秒数
    "6h":  (6 * 3600, 60),
    "24h": (24 * 3600, 300),
    "7d":  (7 * 86400, 1800),
    "30d": (30 * 86400, 7200),
}

@app.route("/api/history/<nid>")
def api_history(nid):
    if not valid_node_id(nid):
        return jsonify({"ok": False, "error": "node_id 不合法"}), 400
    rng = request.args.get("range", "1h")
    span, bucket = RANGES.get(rng, RANGES["1h"])
    now = int(time.time())
    since = now - span
    db = get_db()
    exists = db.execute("SELECT 1 FROM nodes WHERE id=?", (nid,)).fetchone()
    if not exists:
        return jsonify({"ok": False, "error": "节点不存在"}), 404
    rows = db.execute(
        """SELECT ts, AVG(cpu) c, AVG(mem) m, AVG(disk) d,
                  AVG(rx) rx, AVG(tx) tx, AVG(swap) s
           FROM metrics WHERE node_id=? AND ts>=?
           GROUP BY CAST(ts/? AS INTEGER) ORDER BY ts""",
        (nid, since, bucket),
    ).fetchall()
    return jsonify({
        "ok": True, "range": rng,
        "ts": [r[0] * 1000 for r in rows],
        "cpu": [round(r[1], 1) if r[1] is not None else None for r in rows],
        "mem": [round(r[2], 1) if r[2] is not None else None for r in rows],
        "disk": [round(r[3], 1) if r[3] is not None else None for r in rows],
        "rx": [int(r[4]) if r[4] is not None else None for r in rows],
        "tx": [int(r[5]) if r[5] is not None else None for r in rows],
        "swap": [round(r[6], 1) if r[6] is not None else None for r in rows],
    })

@app.route("/api/traffic/daily")
def api_traffic_daily():
    """v4：每日流量。node_id 必填，days 默认 30（1~90）。缺失的天补 0，老→新排序。"""
    from datetime import date as _date, timedelta as _td
    nid = request.args.get("node_id", "").strip()
    if not valid_node_id(nid):
        return jsonify({"ok": False, "error": "node_id 不合法"}), 400
    try:
        days = int(request.args.get("days", "30"))
    except ValueError:
        days = 30
    days = max(1, min(90, days))
    db = get_db()
    exists = db.execute("SELECT 1 FROM nodes WHERE id=?", (nid,)).fetchone()
    if not exists:
        return jsonify({"ok": False, "error": "节点不存在"}), 404
    today = _date.today()
    start = (today - _td(days=days - 1)).isoformat()
    rows = db.execute(
        "SELECT day, rx_bytes, tx_bytes FROM traffic_daily WHERE node_id=? AND day>=?",
        (nid, start),
    ).fetchall()
    by_day = {r["day"]: r for r in rows}
    out = []
    for i in range(days):
        d = (today - _td(days=days - 1 - i)).isoformat()
        r = by_day.get(d)
        rx = (r["rx_bytes"] or 0) if r else 0
        tx = (r["tx_bytes"] or 0) if r else 0
        out.append({
            "day": d,
            "rx_gb": round(rx / 1024**3, 2),
            "tx_gb": round(tx / 1024**3, 2),
            "total_gb": round((rx + tx) / 1024**3, 2),
        })
    return jsonify({"ok": True, "node_id": nid, "days": out})

# ---------------- 管理员 ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if u == ADMIN_USER and hmac.compare_digest(
                hashlib.sha256(p.encode()).hexdigest(), ADMIN_PASS_HASH):
            session["admin"] = True
            session.permanent = True
            return redirect(url_for("index"))
        err = "用户名或密码错误"
    return LOGIN_HTML.replace("__ERR__", err)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/api/me")
def api_me():
    return jsonify({"ok": True, "admin": bool(session.get("admin"))})

@app.route("/api/admin/agent-token")
@login_required
def api_agent_token():
    return jsonify({"ok": True, "token": AGENT_TOKEN})

@app.route("/api/admin/node/<nid>/rename", methods=["POST"])
@login_required
def admin_rename(nid):
    if not valid_node_id(nid):
        return jsonify({"ok": False, "error": "node_id 不合法"}), 400
    name = (request.get_json(silent=True) or {}).get("name", "").strip()[:64]
    if not name:
        return jsonify({"ok": False, "error": "名称不能为空"}), 400
    db = get_db()
    cur = db.execute("UPDATE nodes SET name=? WHERE id=?", (name, nid))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "节点不存在"}), 404
    return jsonify({"ok": True})

@app.route("/api/admin/node/<nid>", methods=["DELETE"])
@login_required
def admin_delete(nid):
    if not valid_node_id(nid):
        return jsonify({"ok": False, "error": "node_id 不合法"}), 400
    db = get_db()
    db.execute("DELETE FROM metrics WHERE node_id=?", (nid,))
    db.execute("DELETE FROM traffic_monthly WHERE node_id=?", (nid,))
    db.execute("DELETE FROM traffic_daily WHERE node_id=?", (nid,))
    db.execute("DELETE FROM alert_state WHERE node_id=?", (nid,))
    cur = db.execute("DELETE FROM nodes WHERE id=?", (nid,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "节点不存在"}), 404
    return jsonify({"ok": True})

@app.route("/api/admin/nodes/order", methods=["POST"])
@login_required
def admin_nodes_order():
    """v6.1：看板卡片手动排序。body: {"order": ["id1","id2",...]}，必须恰好包含全部现有节点 id。"""
    try:
        d = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "JSON 解析失败"}), 400
    order = (d or {}).get("order")
    if not isinstance(order, list) or not order or not all(isinstance(x, str) for x in order):
        return jsonify({"ok": False, "error": "order 须为非空 id 数组"}), 400
    db = get_db()
    existing = [r[0] for r in db.execute("SELECT id FROM nodes").fetchall()]
    if set(order) != set(existing) or len(order) != len(existing):
        return jsonify({"ok": False, "error": "order 必须恰好包含全部 %d 个节点 id" % len(existing)}), 400
    for i, nid in enumerate(order):
        db.execute("UPDATE nodes SET sort_order=? WHERE id=?", (i, nid))
    db.commit()
    return jsonify({"ok": True})

# ================= v6.0：Web SSH 终端 =================
# 用户明确要求在面板内置终端（改变 v1"只读监控"定位）。
# 安全措施：密码 Fernet 加密存库（密钥 CRED_KEY 在 .env），所有接口仅管理员，
# 明文密码永不记日志、永不返回前端；一次性密码不入库。
ENV_PATH = os.path.join(BASE_DIR, ".env")

def _cred_key():
    """取 Fernet 密钥；.env 里没有则生成并追加写入（600 权限）。"""
    key = os.environ.get("CRED_KEY", "").strip()
    if not key and os.path.isfile(ENV_PATH):
        try:
            with open(ENV_PATH, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("CRED_KEY="):
                        key = line.split("=", 1)[1].strip().strip('"').strip("'")
                        break
        except Exception:
            pass
    if not key:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        try:
            with open(ENV_PATH, "a", encoding="utf-8") as f:
                f.write(f"\nCRED_KEY={key}\n")
            os.chmod(ENV_PATH, 0o600)
        except Exception as e:
            print(f"[WARN] CRED_KEY 写入 .env 失败：{e}", file=sys.stderr, flush=True)
    os.environ["CRED_KEY"] = key
    return key.encode()

def encrypt_pass(plain):
    from cryptography.fernet import Fernet
    return Fernet(_cred_key()).encrypt(plain.encode("utf-8")).decode("utf-8")

def decrypt_pass(token):
    from cryptography.fernet import Fernet
    return Fernet(_cred_key()).decrypt(token.encode("utf-8")).decode("utf-8")

def _clamp_int(v, lo, hi, default):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))

_SSH_SESSIONS = {}
_SSH_LOCK = threading.Lock()

class _SSHSession:
    """一条 SSH 会话：paramiko 通道 + 输出缓冲（上限 256KB）+ 读线程。"""
    def __init__(self, sid, node_id, name, client, channel):
        self.id = sid
        self.node_id = node_id
        self.name = name
        self.client = client
        self.channel = channel
        self.buf = collections.deque()
        self.buf_len = 0
        self.lock = threading.Lock()
        self.last_active = time.time()
        self.closed = False

    def push(self, data):
        with self.lock:
            self.buf.append(data)
            self.buf_len += len(data)
            while self.buf_len > 256 * 1024 and self.buf:
                old = self.buf.popleft()
                self.buf_len -= len(old)

    def drain(self):
        with self.lock:
            if not self.buf:
                return b""
            data = b"".join(self.buf)
            self.buf.clear()
            self.buf_len = 0
            return data

def _ssh_reader(sess):
    """后台读线程：把通道输出 pump 进缓冲；异常隔离，不影响其他会话。"""
    try:
        while not sess.closed:
            try:
                data = sess.channel.recv(65536)
            except Exception:
                break
            if not data:
                break
            sess.push(data)
    except Exception:
        pass
    finally:
        sess.closed = True

def _ssh_get(sid):
    if not sid or not isinstance(sid, str):
        return None
    with _SSH_LOCK:
        return _SSH_SESSIONS.get(sid)

def _ssh_drop(sid):
    with _SSH_LOCK:
        sess = _SSH_SESSIONS.pop(sid, None)
    if sess is not None:
        sess.closed = True
        try:
            sess.channel.close()
        except Exception:
            pass
        try:
            sess.client.close()
        except Exception:
            pass

def _ssh_alive(sess):
    try:
        t = sess.client.get_transport()
        return bool(t is not None and t.is_active())
    except Exception:
        return False

def _ssh_reaper():
    """每 60 秒清理：空闲超 15 分钟或传输层已死的会话。"""
    while True:
        time.sleep(60)
        try:
            now = time.time()
            dead = []
            with _SSH_LOCK:
                for sid, sess in list(_SSH_SESSIONS.items()):
                    if now - sess.last_active > 15 * 60 or not _ssh_alive(sess):
                        dead.append(sid)
            for sid in dead:
                _ssh_drop(sid)
                print(f"[ssh] 回收会话 {sid}", flush=True)
        except Exception:
            pass

@app.route("/api/admin/ssh/connect", methods=["POST"])
@login_required
def admin_ssh_connect():
    """建立 SSH 会话。password 为一次性密码（不保存）；不传则用已存密码。"""
    try:
        import paramiko
    except ImportError:
        return jsonify({"ok": False, "error": "服务端未安装 paramiko，请先 pip install -r requirements.txt"}), 500
    d = request.get_json(silent=True) or {}
    nid = (d.get("node_id") or "").strip()
    if not valid_node_id(nid):
        return jsonify({"ok": False, "error": "node_id 不合法"}), 400
    db = get_db()
    try:
        row = db.execute(
            "SELECT id, name, ssh_host, ssh_port, ssh_user, ssh_pass_enc"
            " FROM nodes WHERE id=?", (nid,)).fetchone()
    except Exception:
        row = db.execute(
            "SELECT id, name, ssh_host, ssh_port, ssh_user FROM nodes WHERE id=?",
            (nid,)).fetchone()
    if row is None:
        return jsonify({"ok": False, "error": "节点不存在"}), 404
    host = (row["ssh_host"] or "").strip()
    if not host:
        return jsonify({"ok": False, "error": "该节点未配置 SSH 主机"}), 400
    port = _clamp_int(row["ssh_port"], 1, 65535, 22)
    user = (row["ssh_user"] or "").strip() or "root"
    pw = d.get("password") or ""
    if not pw:
        enc = row["ssh_pass_enc"] if "ssh_pass_enc" in row.keys() else ""
        if enc:
            try:
                pw = decrypt_pass(enc)
            except Exception:
                return jsonify({"ok": False, "error": "已存密码解密失败（CRED_KEY 可能已变更），请重新保存密码"}), 400
    if not pw:
        return jsonify({"ok": False, "error": "请输入 SSH 密码"}), 400
    cols = _clamp_int(d.get("cols"), 20, 300, 100)
    rows = _clamp_int(d.get("rows"), 10, 100, 30)
    client = None
    try:
        client = paramiko.SSHClient()
        # 务实选择：自动接受主机密钥（与 JuiceSSH 首次连接点"接受"等价）
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=pw,
                       timeout=10, banner_timeout=10, auth_timeout=10,
                       look_for_keys=False, allow_agent=False)
        chan = client.get_transport().open_session()
        chan.get_pty(term="xterm-256color", width=cols, height=rows)
        chan.invoke_shell()
    except paramiko.AuthenticationException:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        return jsonify({"ok": False, "error": "SSH 认证失败：用户名或密码错误"}), 400
    except Exception as e:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        return jsonify({"ok": False, "error": f"SSH 连接失败：{type(e).__name__}"}), 400
    sid = secrets.token_hex(8)
    sess = _SSHSession(sid, nid, row["name"], client, chan)
    with _SSH_LOCK:
        _SSH_SESSIONS[sid] = sess
    threading.Thread(target=_ssh_reader, args=(sess,), daemon=True,
                     name=f"ssh-reader-{sid}").start()
    print(f"[ssh] 新会话 {sid} -> {user}@{host}:{port}（节点 {nid}）", flush=True)
    return jsonify({"ok": True, "session_id": sid})

@app.route("/api/admin/ssh/input", methods=["POST"])
@login_required
def admin_ssh_input():
    d = request.get_json(silent=True) or {}
    sess = _ssh_get(d.get("session_id"))
    if sess is None:
        return jsonify({"ok": False, "error": "会话不存在或已关闭"}), 404
    data = d.get("data")
    if not isinstance(data, str):
        return jsonify({"ok": False, "error": "data 必须是字符串"}), 400
    if len(data) > 65536:
        return jsonify({"ok": False, "error": "单次输入过大"}), 400
    try:
        sess.channel.send(data)
        sess.last_active = time.time()
        return jsonify({"ok": True})
    except Exception:
        sess.closed = True
        return jsonify({"ok": False, "error": "发送失败，会话已断开"}), 400

@app.route("/api/admin/ssh/resize", methods=["POST"])
@login_required
def admin_ssh_resize():
    d = request.get_json(silent=True) or {}
    sess = _ssh_get(d.get("session_id"))
    if sess is None:
        return jsonify({"ok": False, "error": "会话不存在或已关闭"}), 404
    cols = _clamp_int(d.get("cols"), 20, 300, 100)
    rows = _clamp_int(d.get("rows"), 10, 100, 30)
    try:
        sess.channel.resize_pty(width=cols, height=rows)
        sess.last_active = time.time()
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False, "error": "调整终端大小失败"}), 400

@app.route("/api/admin/ssh/poll")
@login_required
def admin_ssh_poll():
    sess = _ssh_get(request.args.get("session_id", ""))
    if sess is None:
        return jsonify({"ok": False, "error": "会话不存在或已关闭", "closed": True}), 404
    sess.last_active = time.time()
    data = sess.drain()
    closed = sess.closed or not _ssh_alive(sess)
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    return jsonify({"ok": True, "data": text, "closed": bool(closed)})

@app.route("/api/admin/ssh/close", methods=["POST"])
@login_required
def admin_ssh_close():
    d = request.get_json(silent=True) or {}
    _ssh_drop(d.get("session_id"))
    return jsonify({"ok": True})

# ---------------- 看板 ----------------
@app.route("/")
def index():
    return render_dashboard()

@app.route("/health")
def health():
    return jsonify({"ok": True, "time": int(time.time())})

# ================= 前端 =================
LOGIN_HTML = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyProbe 登录</title>
<style>
body{background:#0d1117;color:#e6edf3;font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;width:320px}
h2{margin:0 0 20px;text-align:center}
input{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;color:#e6edf3;
border-radius:8px;padding:10px;margin:6px 0;font-size:15px}
button{width:100%;background:#238636;border:0;color:#fff;border-radius:8px;padding:10px;margin-top:10px;
font-size:15px;cursor:pointer}
.err{color:#f85149;font-size:13px;min-height:18px;text-align:center}
</style></head><body>
<div class="card"><h2>🔭 MyProbe</h2>
<div class="err">__ERR__</div>
<form method="post">
<input name="username" placeholder="用户名" autocomplete="username">
<input name="password" type="password" placeholder="密码" autocomplete="current-password">
<button type="submit">登录</button>
</form></div></body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyProbe · 服务器探针</title>
<link rel="stylesheet" href="/static/vendor/xterm/xterm.min.css">
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--txt:#e6edf3;--dim:#8b949e;
--green:#3fb950;--red:#f85149;--blue:#58a6ff;--purple:#a371f7;--yellow:#d29922}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--txt);margin:0;
font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
header{display:flex;align-items:center;justify-content:space-between;
padding:14px 20px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg);z-index:10}
header h1{margin:0;font-size:18px}
header .meta{color:var(--dim);font-size:13px}
header a{color:var(--blue);text-decoration:none;font-size:13px;margin-left:12px}
main{padding:16px;max-width:1200px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;cursor:pointer}
.card:hover{border-color:var(--blue)}
.card .top{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.dot{width:10px;height:10px;border-radius:50%;flex:none}
.dot.on{background:var(--green);box-shadow:0 0 6px var(--green)}
.dot.off{background:var(--red)}
.card .name{font-weight:600;font-size:15px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card .sub{color:var(--dim);font-size:12px;margin-top:2px}
.bar-row{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:12px}
.bar-row .lb{width:44px;color:var(--dim);flex:none}
.bar{flex:1;height:8px;background:#21262d;border-radius:4px;overflow:hidden}
.bar i{display:block;height:100%;border-radius:4px;background:var(--blue);transition:width .5s}
.bar-row .vl{width:52px;text-align:right;color:var(--dim);flex:none}
.net{display:flex;gap:16px;margin-top:8px;font-size:12px;color:var(--dim)}
.net b{color:var(--txt);font-weight:600}
#detail{display:none;background:var(--card);border:1px solid var(--border);border-radius:12px;
padding:16px;margin-bottom:16px}
#detail h2{margin:0 0 4px;font-size:17px}
#detail .info{color:var(--dim);font-size:13px;margin-bottom:12px}
.ranges{margin:10px 0}
.ranges button{background:#21262d;border:1px solid var(--border);color:var(--txt);
border-radius:6px;padding:6px 12px;margin-right:6px;cursor:pointer;font-size:13px}
.ranges button.sel{background:var(--blue);border-color:var(--blue);color:#fff}
.chart-box{margin:12px 0}
.chart-box .t{font-size:13px;color:var(--dim);margin-bottom:4px}
canvas{width:100%;height:150px;display:block;background:#0d1117;border:1px solid var(--border);border-radius:8px}
.admin-row{margin-top:12px;display:none;gap:8px}
.admin-row.show{display:flex}
.admin-row button{background:#21262d;border:1px solid var(--border);color:var(--txt);
border-radius:6px;padding:6px 12px;cursor:pointer;font-size:13px}
.admin-row button.danger{color:var(--red);border-color:var(--red)}
#detail .bill{background:#0d1117;border:1px solid var(--border);border-radius:8px;
padding:10px 12px;margin:10px 0;font-size:13px;color:var(--dim);display:flex;gap:18px;flex-wrap:wrap}
#detail .bill b{color:var(--txt)}
nav{display:flex;gap:6px;margin:10px 0 0}
nav button{background:#21262d;border:1px solid var(--border);color:var(--txt);
border-radius:8px;padding:7px 14px;cursor:pointer;font-size:13px}
nav button.sel{background:var(--blue);border-color:var(--blue);color:#fff}
.badge{display:inline-block;font-size:11px;border-radius:10px;padding:2px 8px;margin-left:6px;vertical-align:middle}
.badge.red{background:#f8514933;color:var(--red);border:1px solid var(--red)}
.badge.yellow{background:#d2992233;color:var(--yellow);border:1px solid var(--yellow)}
.badge.green{background:#3fb95033;color:var(--green);border:1px solid var(--green)}
.badge.dim{background:#21262d;color:var(--dim);border:1px solid var(--border)}
/* v6.0：Web SSH 终端 */
.termbtn{display:inline-block;font-size:11px;border-radius:10px;padding:2px 8px;margin-left:6px;
  vertical-align:middle;background:#a371f733;color:var(--purple);border:1px solid var(--purple);
  text-decoration:none;cursor:pointer;white-space:nowrap}
.termbtn:hover{background:#a371f755}
#termOverlay{position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.92);
  display:none;flex-direction:column}
#termOverlay.open{display:flex}
#termBar{display:flex;align-items:center;gap:10px;padding:8px 12px;
  background:#161b22;border-bottom:1px solid var(--border);flex:none}
#termBar .t{font-weight:600;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
#termBar button{background:#21262d;border:1px solid var(--border);color:var(--txt);
  border-radius:8px;padding:6px 12px;font-size:13px;cursor:pointer}
#termBar button:hover{border-color:var(--blue)}
#termBody{flex:1;min-height:0;padding:6px}
#termBody .xterm{height:100%}
#termAuth{display:none;flex:none;padding:10px 12px;background:#161b22;
  border-bottom:1px solid var(--border);gap:8px;align-items:center}
#termAuth.show{display:flex}
#termAuth input{flex:1;background:#0d1117;border:1px solid var(--border);color:var(--txt);
  border-radius:8px;padding:8px;font-size:14px}
#termMsg{flex:none;padding:6px 12px;font-size:13px;color:var(--yellow);display:none}
#termMsg.show{display:block}
#termMsg.err{color:var(--red)}
table.tbl{width:100%;border-collapse:collapse;font-size:13px;margin:10px 0}
table.tbl th,table.tbl td{border-bottom:1px solid var(--border);padding:8px 6px;text-align:left;vertical-align:middle}
table.tbl th{color:var(--dim);font-weight:500;font-size:12px}
.minibars{display:flex;align-items:flex-end;gap:2px;height:34px}
.minibars i{width:5px;border-radius:2px;background:var(--green);min-height:3px}
.minibars i.bad{background:var(--red)}
.minibars i.warn{background:var(--yellow)}
/* v5：节点卡片内独立拨测区 */
.probes{margin-top:8px;border-top:1px solid var(--border);padding-top:6px}
.probe-head,.probe-row{display:grid;grid-template-columns:1fr 76px 62px;gap:6px;align-items:center;font-size:12px;padding:3px 0}
.probe-head{color:var(--dim);font-size:11px}
.probe-row .minibars{height:20px;grid-column:1/-1}
.probe-row{border-bottom:1px dashed var(--border)}
.probe-row:last-child{border-bottom:none}
/* v5：拨测页按节点分组 */
.probe-node{margin:12px 0}
.probe-node>h3{margin:6px 0;font-size:14px}
.tabs{display:flex;gap:6px;margin:12px 0;flex-wrap:wrap}
.tabs button{background:#21262d;border:1px solid var(--border);color:var(--txt);
border-radius:8px;padding:7px 14px;cursor:pointer;font-size:13px}
.tabs button.sel{background:var(--blue);border-color:var(--blue);color:#fff}
.frm{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;margin:12px 0}
.frm h3{margin:0 0 10px;font-size:15px}
.frm label{display:block;font-size:12px;color:var(--dim);margin:8px 0 3px}
.frm input,.frm select{width:100%;background:#0d1117;border:1px solid var(--border);
color:var(--txt);border-radius:8px;padding:8px;font-size:14px}
.frm .row2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.btn{background:var(--blue);border:0;color:#fff;border-radius:8px;padding:8px 16px;
cursor:pointer;font-size:14px;margin-top:10px}
.btn.ghost{background:#21262d;border:1px solid var(--border)}
.btn.danger{background:transparent;color:var(--red);border:1px solid var(--red)}
.btn.sm{padding:5px 10px;font-size:12px;margin:2px 4px 2px 0}
.note{font-size:12px;color:var(--dim);margin-top:8px}
.empty{color:var(--dim);text-align:center;padding:60px 0}
</style></head><body>
<header>
<div><h1>🔭 MyProbe</h1><div class="meta" id="meta"></div>
<nav id="nav">
<button data-v="board" class="sel" onclick="nav('board')">📊 看板</button>
<button data-v="probes" onclick="nav('probes')">📡 拨测</button>
<button data-v="admin" id="nav-admin" style="display:none" onclick="nav('admin')">⚙️ 管理</button>
</nav></div>
<div><span id="clock" style="color:var(--dim);font-size:13px"></span>
<span id="auth"></span></div>
</header>
<main>
<div id="view-board">
<div id="plugin-cards">{{ plugin_cards|safe }}</div>
<div id="detail"></div>
<div class="grid" id="grid"></div>
<div class="empty" id="empty" style="display:none">还没有节点上报数据<br>
<small>在被监控的机器上运行 agent.py 即可接入</small></div>
</div>
<div id="view-probes" style="display:none"></div>
<div id="view-admin" style="display:none"></div>
</main>
<div id="termOverlay">
  <div id="termBar"><span class="t" id="termTitle">💻 终端</span>
    <button onclick="termRefit()" title="重新适配大小">⛶ 自适应</button>
    <button onclick="termClose()">✕ 关闭</button></div>
  <div id="termAuth"><input id="termPass" type="password" placeholder="输入一次性 SSH 密码（不保存）" autocomplete="off" onkeydown="if(event.key==='Enter')termConnectWithPass()">
    <button class="btn sm" onclick="termConnectWithPass()">连接</button></div>
  <div id="termMsg"></div>
  <div id="termBody"></div>
</div>
<script src="/static/vendor/xterm/xterm.min.js"></script>
<script src="/static/vendor/xterm/addon-fit.min.js"></script>
<script>
const PLUGIN_TABS = {{ plugin_admin_tabs_json|safe }};
const S = {nodes: [], sel: null, range: "1h", admin: false, timer: null,
  view: "board", probes: [], atab: "nodes", rules: [], channels: [], alerts: []};
const $ = id => document.getElementById(id);

function nav(v){
  S.view = v;
  document.querySelectorAll("#nav button").forEach(b =>
    b.classList.toggle("sel", b.dataset.v === v));
  $("view-board").style.display = v === "board" ? "" : "none";
  $("view-probes").style.display = v === "probes" ? "" : "none";
  $("view-admin").style.display = v === "admin" ? "" : "none";
  if (v === "probes") loadProbes();
  if (v === "admin") loadAdmin();
}

function fmtBytes(v){ // bytes/s -> 人性化
  if (v == null) return "--";
  const u = ["B/s","KB/s","MB/s","GB/s"]; let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 ? 0 : 1) + " " + u[i];
}
function fmtUptime(s){
  if (s == null) return "--";
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return (d > 0 ? d + "天 " : "") + h + "小时 " + m + "分";
}
function esc(s){ return String(s == null ? "" : s).replace(/[&<>"]/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }

async function boot(){
  const me = await (await fetch("/api/me")).json();
  S.admin = me.admin;
  $("auth").innerHTML = S.admin
    ? '<a href="/logout">退出登录</a>'
    : '<a href="/login">管理员登录</a>';
  if (S.admin) $("nav-admin").style.display = "";
  await refresh();
  S.timer = setInterval(refresh, 5000);
  setInterval(() => { $("clock").textContent = new Date().toLocaleString("zh-CN"); }, 1000);
}

async function refresh(){
  const r = await (await fetch("/api/nodes")).json();
  S.nodes = r.nodes || [];
  const on = S.nodes.filter(n => n.online).length;
  $("meta").textContent = `节点 ${S.nodes.length} · 在线 ${on} · 上报间隔 ${r.interval || 5}s`;
  $("empty").style.display = S.nodes.length ? "none" : "block";
  renderGrid();
  if (S.sel) {
    const n = S.nodes.find(x => x.id === S.sel);
    if (!n) { closeDetail(); } else { renderDetailHead(n); }
  }
  if (S.view === "probes") loadProbes();
}

function bar(label, pct, color){
  const v = pct == null ? 0 : pct;
  return `<div class="bar-row"><span class="lb">${label}</span>
    <div class="bar"><i style="width:${Math.min(100, v).toFixed(1)}%;background:${color}"></i></div>
    <span class="vl">${pct == null ? "--" : pct.toFixed(1) + "%"}</span></div>`;
}

function expiryBadge(n){
  if (n.days_left == null) return "";
  const d = n.days_left;
  const cls = d < 0 ? "red" : d <= 7 ? "red" : d <= 30 ? "yellow" : "green";
  const txt = d < 0 ? `过期${-d}天` : d === 0 ? "今天到期" : `余期${d}天`;
  let rv = "";
  if (n.remain_value != null && n.currency)
    rv = `<span class="badge dim">余值${esc(n.currency)}${n.remain_value}</span>`;
  return `<span class="badge ${cls}">${txt}</span>${rv}`;
}

function quotaBar(n){
  if (n.quota_gb == null || n.quota_pct == null) return "";
  const c = n.quota_pct >= 100 ? "var(--red)" : n.quota_pct >= 80 ? "var(--yellow)" : "var(--green)";
  return `<div class="bar-row"><span class="lb">月流量</span>
    <div class="bar"><i style="width:${n.quota_pct}%;background:${c}"></i></div>
    <span class="vl">${n.quota_used_gb}/${n.quota_gb}G</span></div>`;
}

// v6.0：内置 Web 终端按钮（ssh_host 已填才显示）
function termBtn(n){
  if (!(n.ssh_host || "").trim()) return "";
  return `<a class="termbtn" href="javascript:void(0)" onclick="event.stopPropagation();openTerminal('${esc(n.id)}')" title="在面板内打开 SSH 终端">💻 终端</a>`;
}

// ================= v6.0：Web SSH 终端 =================
const T = {sid: null, term: null, fit: null, timer: null, node: null};

function termMsg(t, isErr){
  const m = $("termMsg");
  m.textContent = t || "";
  m.className = t ? ("show" + (isErr ? " err" : "")) : "";
}

async function openTerminal(nid){
  const n = S.nodes.find(x => x.id === nid);
  if (!n) return;
  if (typeof Terminal === "undefined"){ alert("终端组件未加载，请检查 /static/vendor/xterm/"); return; }
  await termClose(true);
  T.node = n;
  $("termTitle").textContent = "💻 " + n.name + " 终端";
  $("termOverlay").classList.add("open");
  $("termAuth").classList.toggle("show", !n.ssh_ready);
  $("termPass").value = "";
  termMsg("");
  T.term = new Terminal({cursorBlink: true, fontSize: 14,
    theme: {background: "#0d1117", foreground: "#e6edf3"}});
  T.fit = new FitAddon.FitAddon();
  T.term.loadAddon(T.fit);
  T.term.open($("termBody"));
  T.term.focus();
  T.term.onData(d => termSend(d));
  termRefit();
  window.addEventListener("resize", termOnWinResize);
  if (n.ssh_ready){
    termMsg("正在连接 " + (n.ssh_user || "root") + "@" + n.ssh_host + " …");
    await termConnect("");
  } else {
    termMsg("该节点未保存 SSH 密码：输入一次性密码连接（不保存）。");
    $("termPass").focus();
  }
}

async function termConnect(pw){
  let dims = null;
  try { dims = T.fit.proposeDimensions(); } catch(e){}
  const body = {node_id: T.node.id,
    cols: dims ? dims.cols : 100, rows: dims ? dims.rows : 30};
  if (pw) body.password = pw;
  let r;
  try { r = await apiAdmin("POST", "/api/admin/ssh/connect", body); }
  catch(e){ r = {ok: false, error: "网络错误"}; }
  if (!r.ok){ termMsg("❌ " + (r.error || "连接失败"), true); return; }
  T.sid = r.session_id;
  $("termAuth").classList.remove("show");
  termMsg("");
  try { T.term.clear(); } catch(e){}
  termStopPoll();
  T.timer = setInterval(termPoll, 250);
}

async function termConnectWithPass(){
  const pw = $("termPass").value;
  if (!pw){ termMsg("请输入密码", true); return; }
  termMsg("正在连接…");
  await termConnect(pw);
  $("termPass").value = "";
}

async function termPoll(){
  if (!T.sid) return;
  let r;
  try {
    r = await (await fetch("/api/admin/ssh/poll?session_id=" +
      encodeURIComponent(T.sid))).json();
  } catch(e){ return; }
  if (r.data && T.term){ try { T.term.write(r.data); } catch(e){} }
  if (!r.ok || r.closed){
    termStopPoll();
    termMsg("⚠ 连接已关闭", true);
  }
}

let _sendQ = Promise.resolve();
function termSend(d){
  if (!T.sid) return;
  _sendQ = _sendQ.then(() =>
    apiAdmin("POST", "/api/admin/ssh/input", {session_id: T.sid, data: d})
      .catch(() => {})).catch(() => {});
}

function termRefit(){
  if (!T.term || !T.fit) return;
  try {
    T.fit.fit();
    const d = T.fit.proposeDimensions();
    if (d && T.sid)
      apiAdmin("POST", "/api/admin/ssh/resize",
        {session_id: T.sid, cols: d.cols, rows: d.rows}).catch(() => {});
  } catch(e){}
}
function termOnWinResize(){ termRefit(); }
function termStopPoll(){ if (T.timer){ clearInterval(T.timer); T.timer = null; } }

async function termClose(silent){
  termStopPoll();
  window.removeEventListener("resize", termOnWinResize);
  if (T.sid){
    const sid = T.sid; T.sid = null;
    try { await apiAdmin("POST", "/api/admin/ssh/close", {session_id: sid}); }
    catch(e){}
  }
  if (T.term){ try { T.term.dispose(); } catch(e){} T.term = null; T.fit = null; }
  T.node = null;
  if (!silent){ $("termOverlay").classList.remove("open"); termMsg(""); }
}

// v5：节点卡片内拨测区（本节点 agent 独立探测的结果）
function probeHtml(n){
  const ps = n.probes || [];
  if (!ps.length) return "";
  if (!ps.some(p => p.latency_ms != null))
    return `<div class="probes"><div class="note">📡 等待节点上报拨测数据…</div></div>`;
  const rows = ps.map(p => {
    const lat = p.latency_ms == null ? "—" : `${p.latency_ms.toFixed(0)} ms`;
    const loss = p.loss_pct == null ? "—" : `${p.loss_pct.toFixed(1)}%`;
    const bars = (p.bars || []).map(b =>
      `<i class="${b ? "" : "bad"}" style="height:${b ? 14 : 4}px"></i>`).join("");
    return `<div class="probe-row"><span>${esc(p.name)}</span><span>${lat}</span><span>${loss}</span><div class="minibars">${bars}</div></div>`;
  }).join("");
  return `<div class="probes"><div class="probe-head"><span>探测目标</span><span>延迟</span><span>丢包</span></div>${rows}</div>`;
}

function renderGrid(){
  $("grid").innerHTML = S.nodes.map(n => `
    <div class="card" onclick="openDetail('${esc(n.id)}')">
      <div class="top"><span class="dot ${n.online ? "on" : "off"}"></span>
        <span class="name">${esc(n.name)}${expiryBadge(n)}${termBtn(n)}</span></div>
      <div class="sub">${esc(n.hostname || "")} · ${esc(n.os || n.platform || "")} · ${n.online ? "在线" : "离线"}</div>
      ${bar("CPU", n.cpu, "var(--blue)")}
      ${bar("内存", n.mem, "var(--purple)")}
      ${bar("磁盘", n.disk, "var(--yellow)")}
      ${quotaBar(n)}
      <div class="net"><span>↓ <b>${fmtBytes(n.rx)}</b></span>
        <span>↑ <b>${fmtBytes(n.tx)}</b></span>
        <span>运行 <b>${fmtUptime(n.uptime)}</b></span></div>
      <div class="net"><span>累计 ↓ <b>${n.total_rx_gb} GB</b> ↑ <b>${n.total_tx_gb} GB</b></span></div>
      ${probeHtml(n)}
    </div>`).join("");
}

async function openDetail(id){
  S.sel = id; S.range = "1h";
  const n = S.nodes.find(x => x.id === id);
  if (!n) return;
  renderDetailHead(n);
  $("detail").style.display = "block";
  $("detail").scrollIntoView({behavior: "smooth", block: "start"});
  await loadHistory();
}

function closeDetail(){
  S.sel = null; $("detail").style.display = "none"; renderGrid();
}

function billHtml(n){
  const items = [];
  if (n.price != null)
    items.push(`套餐 <b>${esc(n.currency || "")}${n.price}</b>${n.bill_cycle === "yearly" ? " /年" : n.bill_cycle === "monthly" ? " /月" : ""}`);
  if (n.buy_date) items.push(`购买 <b>${esc(n.buy_date)}</b>`);
  if (n.expire_date) items.push(`到期 <b>${esc(n.expire_date)}</b>${expiryBadge(n)}`);
  if (n.quota_gb != null)
    items.push(`月配额 <b>${n.quota_gb} GB</b>（本月已用 ${n.quota_used_gb} GB）`);
  items.push(`累计流量 ↓ <b>${n.total_rx_gb} GB</b> ↑ <b>${n.total_tx_gb} GB</b>`);
  if (!items.length) return "";
  return `<div class="bill">${items.map(i => `<span>${i}</span>`).join("")}</div>`;
}

function renderDetailHead(n){
  const d = $("detail");
  d.innerHTML = `
    <h2>${esc(n.name)} <small style="color:var(--dim);font-weight:400">${n.online ? "🟢 在线" : "🔴 离线"}</small></h2>
    <div class="info">${esc(n.hostname || "")} · ${esc(n.os || "")} · ${esc(n.arch || "")} ·
      ${n.cpu_cores || "?"}核 · 最后上报 <span id="d-last">${new Date(n.last_seen * 1000).toLocaleString("zh-CN")}</span></div>
    ${billHtml(n)}
    <div class="ranges" id="ranges">
      ${["1h","6h","24h","7d","30d"].map(r =>
        `<button data-r="${r}" class="${r === S.range ? "sel" : ""}" onclick="setRange('${r}')">${r}</button>`).join("")}
      <button onclick="closeDetail()" style="float:right">✕ 关闭</button>
    </div>
    <div class="chart-box"><div class="t">CPU 使用率 %</div><canvas id="c-cpu"></canvas></div>
    <div class="chart-box"><div class="t">内存 / Swap %</div><canvas id="c-mem"></canvas></div>
    <div class="chart-box"><div class="t">磁盘 %</div><canvas id="c-disk"></canvas></div>
    <div class="chart-box"><div class="t">网络速率</div><canvas id="c-net"></canvas></div>
    <div class="chart-box"><div class="t">每日流量（近30天，GB） <span id="d-total" style="color:var(--dim);font-weight:400"></span></div><canvas id="c-daily"></canvas></div>
    <div class="admin-row ${S.admin ? "show" : ""}">
      <button onclick="renameNode()">✏️ 改名</button>
      <button class="danger" onclick="deleteNode()">🗑 删除节点</button>
    </div>`;
}

async function setRange(r){ S.range = r; await loadHistory(); }

function fmtT(ts, range){
  const d = new Date(ts);
  const p = n => String(n).padStart(2, "0");
  if (range === "7d" || range === "30d")
    return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

// 极简 canvas 折线图：series = [{color, data:[[ts,val],...], fill}]
function drawLine(id, series, opt){
  opt = opt || {};
  const cv = $(id); if (!cv) return;
  const dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth, H = cv.clientHeight;
  cv.width = W * dpr; cv.height = H * dpr;
  const ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  const padL = 44, padR = 8, padT = 8, padB = 18;
  const iw = W - padL - padR, ih = H - padT - padB;
  let all = [];
  series.forEach(s => s.data.forEach(p => { if (p[1] != null) all.push(p[1]); }));
  let mx = Math.max(1, ...all), mn = Math.min(0, ...all);
  if (opt.max != null) { mx = opt.max; mn = 0; }
  if (mx === mn) mx = mn + 1;
  const t0 = Math.min(...series.flatMap(s => s.data.map(p => p[0])));
  const t1 = Math.max(...series.flatMap(s => s.data.map(p => p[0])));
  const X = t => padL + (t - t0) / Math.max(1, t1 - t0) * iw;
  const Y = v => padT + ih - (v - mn) / (mx - mn) * ih;
  // 网格 + Y 轴标签
  ctx.strokeStyle = "#21262d"; ctx.fillStyle = "#8b949e";
  ctx.font = "10px system-ui"; ctx.lineWidth = 1;
  for (let g = 0; g <= 4; g++){
    const v = mn + (mx - mn) * g / 4, y = Y(v);
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillText(opt.fmtY ? opt.fmtY(v) : v.toFixed(0), 4, y + 3);
  }
  // X 轴时间标签
  ctx.fillStyle = "#6e7681";
  for (let g = 0; g <= 4; g++){
    const t = t0 + (t1 - t0) * g / 4;
    ctx.fillText(fmtT(t, S.range), padL + iw * g / 4 - 14, H - 5);
  }
  // 曲线
  series.forEach(s => {
    const pts = s.data.filter(p => p[1] != null);
    if (!pts.length) return;
    ctx.beginPath();
    pts.forEach((p, i) => { i ? ctx.lineTo(X(p[0]), Y(p[1])) : ctx.moveTo(X(p[0]), Y(p[1])); });
    ctx.strokeStyle = s.color; ctx.lineWidth = 1.5; ctx.stroke();
    if (s.fill){
      ctx.lineTo(X(pts[pts.length-1][0]), Y(mn)); ctx.lineTo(X(pts[0][0]), Y(mn)); ctx.closePath();
      ctx.fillStyle = s.color + "22"; ctx.fill();
    }
  });
  // 图例
  ctx.font = "11px system-ui";
  let lx = padL;
  series.forEach(s => {
    ctx.fillStyle = s.color; ctx.fillRect(lx, 4, 10, 3);
    ctx.fillStyle = "#8b949e"; ctx.fillText(s.label || "", lx + 14, 10); lx += 14 + ctx.measureText(s.label || "").width + 16;
  });
}

async function loadHistory(){
  if (!S.sel) return;
  const h = await (await fetch(`/api/history/${encodeURIComponent(S.sel)}?range=${S.range}`)).json();
  if (!h.ok) return;
  const zip = arr => h.ts.map((t, i) => [t, arr[i]]);
  drawLine("c-cpu", [{label: "CPU%", color: "#58a6ff", data: zip(h.cpu), fill: true}], {max: 100});
  drawLine("c-mem", [
    {label: "内存%", color: "#a371f7", data: zip(h.mem), fill: true},
    {label: "Swap%", color: "#d29922", data: zip(h.swap)}
  ], {max: 100});
  drawLine("c-disk", [{label: "磁盘%", color: "#d29922", data: zip(h.disk), fill: true}], {max: 100});
  drawLine("c-net", [
    {label: "下行", color: "#3fb950", data: zip(h.rx), fill: true},
    {label: "上行", color: "#f85149", data: zip(h.tx)}
  ], {fmtY: v => fmtBytes(v)});
  loadDaily();
}

// v4：每日流量分组柱状图（下行绿 / 上行红），无 CDN
function drawBars(id, days){
  const cv = $(id); if (!cv) return;
  const dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth, H = cv.clientHeight;
  cv.width = W * dpr; cv.height = H * dpr;
  const ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  const padL = 44, padR = 8, padT = 8, padB = 18;
  const iw = W - padL - padR, ih = H - padT - padB;
  const mx = Math.max(1, ...days.map(d => Math.max(d.rx_gb, d.tx_gb)));
  const Y = v => padT + ih - v / mx * ih;
  ctx.font = "10px system-ui"; ctx.lineWidth = 1;
  for (let g = 0; g <= 4; g++){
    const v = mx * g / 4, y = Y(v);
    ctx.strokeStyle = "#21262d"; ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillStyle = "#8b949e"; ctx.fillText(v.toFixed(1), 4, y + 3);
  }
  const n = days.length, slot = iw / Math.max(1, n), bw = Math.max(2, slot * 0.28);
  days.forEach((d, i) => {
    const x = padL + slot * i + slot / 2;
    ctx.fillStyle = "#3fb950";
    const hrx = (d.rx_gb / mx) * ih;
    ctx.fillRect(x - bw - 1, Y(d.rx_gb), bw, hrx);
    ctx.fillStyle = "#f85149";
    const htx = (d.tx_gb / mx) * ih;
    ctx.fillRect(x + 1, Y(d.tx_gb), bw, htx);
    if (n <= 31 && i % Math.ceil(n / 10) === 0){
      ctx.fillStyle = "#6e7681";
      ctx.fillText(d.day.slice(5), x - 12, H - 5);
    }
  });
  ctx.font = "11px system-ui";
  ctx.fillStyle = "#3fb950"; ctx.fillRect(padL, 4, 10, 3);
  ctx.fillStyle = "#8b949e"; ctx.fillText("下行", padL + 14, 10);
  ctx.fillStyle = "#f85149"; ctx.fillRect(padL + 52, 4, 10, 3);
  ctx.fillStyle = "#8b949e"; ctx.fillText("上行", padL + 66, 10);
}

async function loadDaily(){
  if (!S.sel) return;
  try{
    const r = await (await fetch(`/api/traffic/daily?node_id=${encodeURIComponent(S.sel)}&days=30`)).json();
    if (!r.ok) return;
    drawBars("c-daily", r.days);
    const n = S.nodes.find(x => x.id === S.sel);
    if (n && $("d-total"))
      $("d-total").textContent = `累计 ↓ ${n.total_rx_gb} GB ↑ ${n.total_tx_gb} GB`;
  }catch(e){}
}

async function renameNode(){
  const n = S.nodes.find(x => x.id === S.sel); if (!n) return;
  const name = prompt("节点显示名称：", n.name);
  if (!name || !name.trim()) return;
  const r = await (await fetch(`/api/admin/node/${encodeURIComponent(S.sel)}/rename`, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({name: name.trim()})
  })).json();
  if (r.ok) { await refresh(); } else alert("改名失败：" + (r.error || ""));
}

async function deleteNode(){
  if (!confirm("确定删除该节点及其全部历史数据吗？")) return;
  const r = await (await fetch(`/api/admin/node/${encodeURIComponent(S.sel)}`, {method: "DELETE"})).json();
  if (r.ok) { closeDetail(); await refresh(); } else alert("删除失败：" + (r.error || ""));
}

// ================= v5：拨测视图（各节点 agent 独立探测） =================
async function loadProbes(){
  const r = await (await fetch("/api/nodes")).json();
  const nodes = r.nodes || [];  // v6.1：信任 API 的 sort_order，不再前端重排
  const v = $("view-probes");
  if (!nodes.length){
    v.innerHTML = `<div class="empty">还没有节点<br><small>先去装 agent 吧</small></div>`;
    return;
  }
  const hasTasks = nodes.some(n => (n.probes || []).length);
  if (!hasTasks){
    v.innerHTML = `<div class="empty">还没有拨测任务<br>
      <small>${S.admin ? "去 ⚙️管理 → 拨测任务 添加" : "管理员登录后可添加"}</small></div>`;
    return;
  }
  v.innerHTML = nodes.map(n => {
    const ps = n.probes || [];
    const rows = ps.map(p => {
      const lat = p.latency_ms == null ? '<span style="color:var(--dim)">等待上报…</span>' : `<b>${p.latency_ms.toFixed(1)} ms</b>`;
      const loss = p.loss_pct == null ? "--" : `<b style="color:${p.loss_pct >= 100 ? "var(--red)" : p.loss_pct > 0 ? "var(--yellow)" : "var(--green)"}">${p.loss_pct.toFixed(1)}%</b>`;
      const bars = (p.bars || []).map(b => `<i class="${b ? "" : "bad"}" style="height:${b ? 16 : 4}px"></i>`).join("");
      return `<tr><td>${esc(p.name)}</td>
        <td>${lat}</td><td>${loss}</td>
        <td><div class="minibars">${bars || '<span style="color:var(--dim)">--</span>'}</div></td></tr>`;
    }).join("");
    return `<div class="probe-node"><h3>${n.online ? "🟢" : "🔴"} ${esc(n.name)}</h3>
      <table class="tbl"><tr><th>任务</th><th>延迟</th><th>丢包</th><th>近22次</th></tr>${rows}</table></div>`;
  }).join("") +
    `<div class="note">各节点 agent 每 60 秒独立探测 · 绿=正常 红=失败 · agent 未升级时显示"等待上报…"</div>`;
}

// ================= v2：管理后台 =================
const ATABS = [["nodes", "🖥 节点信息"], ["probes", "📡 拨测任务"],
  ["rules", "🚨 告警规则"], ["channels", "🔔 通知渠道"], ["alerts", "📋 告警记录"],
  ["themes", "🎨 主题"], ["plugins", "🔌 插件"]];

async function loadAdmin(){
  const v = $("view-admin");
  v.innerHTML = `<div class="tabs">${ATABS.concat(PLUGIN_TABS.map(t => ["plugin:" + t.slug, "\u0001f50c " + t.title])).map(([k, t]) =>
    `<button class="${S.atab === k ? "sel" : ""}" onclick="atab('${k}')">${t}</button>`).join("")}</div>
    <div id="atab-body"><div class="note">加载中…</div></div>`;
  await renderAtab();
}

async function atab(k){ S.atab = k; await loadAdmin(); }

async function renderAtab(){
  const b = $("atab-body");
  if (S.atab.startsWith("plugin:")){
    const t = PLUGIN_TABS.find(x => "plugin:" + x.slug === S.atab);
    b.innerHTML = t ? t.html : `<div class="empty">插件页面不存在</div>`; return;
  }
  if (S.atab === "nodes") return tabNodes(b);
  if (S.atab === "probes") return tabProbes(b);
  if (S.atab === "rules") return tabRules(b);
  if (S.atab === "channels") return tabChannels(b);
  if (S.atab === "alerts") return tabAlerts(b);
  if (S.atab === "themes") return tabThemes(b);
  if (S.atab === "plugins") return tabPlugins(b);
}

async function apiAdmin(method, url, body){
  const r = await fetch(url, {method,
    headers: {"Content-Type": "application/json"},
    body: body ? JSON.stringify(body) : undefined});
  return r.json();
}

// ---- 节点信息 ----
// v4.2：添加节点（仿 Komari 自动发现，一键生成安装命令）
let AGENT_TOKEN_CACHE = null;
async function getAgentToken(){
  if (AGENT_TOKEN_CACHE) return AGENT_TOKEN_CACHE;
  try {
    const r = await (await fetch("/api/admin/agent-token")).json();
    if (r.ok && r.token){ AGENT_TOKEN_CACHE = r.token; return r.token; }
  } catch(e){}
  return null;
}
function updAddNodeCmd(){
  const nidEl = $("add-nid");
  if (!nidEl) return;
  const nid = (nidEl.value || "").replace(/\\s+/g, "");
  const nm = (($("add-nm") || {}).value || "").trim();
  const t = $("add-cmd");
  if (!AGENT_TOKEN_CACHE){ t.value = "正在获取 Token…"; return; }
  if (!nid){ t.value = "请先填写节点 ID（英文，如 de-vps）"; return; }
  t.value = `curl -fsSL ${location.origin}/dl/agent-install.sh | bash -s -- ${location.origin} ${AGENT_TOKEN_CACHE} ${nid} "${nm || nid}"`;
}
async function copyAddNodeCmd(){
  const t = $("add-cmd").value;
  try { await navigator.clipboard.writeText(t); }
  catch(e){
    const ta = document.createElement("textarea");
    ta.value = t; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch(_){}
    ta.remove();
  }
  const m = $("add-msg");
  if (m){ m.textContent = "✅ 已复制，去目标机器粘贴运行"; setTimeout(()=>{ m.textContent = ""; }, 3000); }
}
function addNodeCardHTML(){
  return `
    <div class="frm">
      <h3>➕ 添加节点</h3>
      <div class="row2">
        <div><label>节点 ID（英文，如 de-vps）</label><input id="add-nid" placeholder="de-vps" oninput="updAddNodeCmd()"></div>
        <div><label>显示名</label><input id="add-nm" placeholder="德国CF" oninput="updAddNodeCmd()"></div>
      </div>
      <div><label>一键安装命令（去目标机器以 root 粘贴运行）</label>
      <textarea id="add-cmd" rows="3" readonly style="width:100%;box-sizing:border-box" placeholder="填写节点 ID 后自动生成"></textarea></div>
      <div style="margin-top:8px"><button class="btn" onclick="copyAddNodeCmd()">📋 复制命令</button>
      <span class="note" id="add-msg"></span></div>
      <div class="note">运行后约 10 秒看板自动出现新节点，再去下方节点表单填价格 / 配额 / 到期。</div>
    </div>`;
}
async function tabNodes(b){
  const r = await (await fetch("/api/nodes")).json();
  const nodes = r.nodes || [];
  const h = addNodeCardHTML();
  if (!nodes.length){ b.innerHTML = h + `<div class="empty">暂无节点</div>`; }
  else {
  b.innerHTML = h + nodes.map(n => `
    <div class="frm" id="meta-${esc(n.id)}">
      <h3>${esc(n.name)} <small style="color:var(--dim)">${esc(n.id)}</small></h3>
      <div class="row2">
        <div><label>套餐价格</label><input data-k="price" value="${n.price == null ? "" : n.price}" placeholder="如 249"></div>
        <div><label>货币符号</label><input data-k="currency" value="${esc(n.currency || "¥")}" placeholder="¥ 或 $"></div>
      </div>
      <div class="row2">
        <div><label>计费周期</label><select data-k="bill_cycle">
          <option value="">—</option>
          <option value="monthly" ${n.bill_cycle === "monthly" ? "selected" : ""}>月付</option>
          <option value="yearly" ${n.bill_cycle === "yearly" ? "selected" : ""}>年付</option>
        </select></div>
        <div><label>月流量配额 (GB)</label><input data-k="quota_gb" value="${n.quota_gb == null ? "" : n.quota_gb}" placeholder="如 820"></div>
      </div>
      <div class="row2">
        <div><label>本月已用基准 (GB)</label><input data-k="quota_base_gb" value="${n.quota_base_gb == null ? "" : n.quota_base_gb}" placeholder="如 110.17，面板已用量"></div>
        <div><label>基准月份</label><input value="${esc(n.quota_base_month || "—")}" disabled style="opacity:.6"></div>
      </div>
      <div class="row2">
        <div><label>购买日期</label><input data-k="buy_date" type="date" value="${esc(n.buy_date || "")}"></div>
        <div><label>到期日期</label><input data-k="expire_date" type="date" value="${esc(n.expire_date || "")}"></div>
      </div>
      <div class="row2">
        <div><label>SSH 主机 (IP/域名)</label><input data-k="ssh_host" value="${esc(n.ssh_host || "")}" placeholder="如 203.0.113.10，留空则不显示按钮"></div>
        <div><label>SSH 端口</label><input data-k="ssh_port" value="${n.ssh_port == null ? "" : n.ssh_port}" placeholder="默认 22"></div>
      </div>
      <div class="row2">
        <div><label>SSH 用户名</label><input data-k="ssh_user" value="${esc(n.ssh_user || "root")}" placeholder="默认 root"></div>
        <div><label>SSH 密码（Fernet 加密存库）</label><input data-k="ssh_password" type="password" value="" autocomplete="new-password" placeholder="${n.ssh_ready ? "已保存（留空不改）" : "root 密码"}"></div>
      </div>
      <div class="row2">
        <div><label>&nbsp;</label><div style="padding-top:8px"><button class="btn sm danger" onclick="clearSshPass('${esc(n.id)}')">清除已存密码</button></div></div>
        <div><label>&nbsp;</label><div class="note" style="padding-top:8px">密码 Fernet 加密存库，仅管理员可用 💻 终端。</div></div>
      </div>
      <button class="btn" onclick="saveNodeMeta('${esc(n.id)}')">💾 保存</button>
      <span class="note" id="meta-msg-${esc(n.id)}"></span>
    </div>`).join("");
  }
  getAgentToken().then(updAddNodeCmd);
}

async function saveNodeMeta(id){
  const box = $("meta-" + id);
  const d = {};
  // v6.0：密码框不 trim（密码首尾空格是合法字符）
  box.querySelectorAll("[data-k]").forEach(el => d[el.dataset.k] =
    (el.type === "password" ? el.value : el.value.trim()));
  const r = await apiAdmin("PUT", `/api/admin/node/${encodeURIComponent(id)}/meta`, d);
  const m = $("meta-msg-" + id);
  if (r.ok){ m.textContent = "✅ 已保存"; await refresh(); }
  else m.textContent = "❌ " + (r.error || "保存失败");
}

// v6.0：清除已存 SSH 密码
async function clearSshPass(id){
  if (!confirm("确定清除该节点已保存的 SSH 密码？")) return;
  const r = await apiAdmin("PUT", `/api/admin/node/${encodeURIComponent(id)}/meta`,
    {ssh_clear_pass: true});
  const m = $("meta-msg-" + id);
  if (r.ok){ m.textContent = "✅ 已清除"; await refresh(); }
  else m.textContent = "❌ " + (r.error || "清除失败");
}

// ---- 拨测任务 ----
async function tabProbes(b){
  const r = await apiAdmin("GET", "/api/admin/probes");
  const tasks = r.tasks || [];
  b.innerHTML = `<table class="tbl"><tr><th>名称</th><th>类型</th><th>目标</th><th>间隔</th><th>状态</th><th>操作</th></tr>` +
    tasks.map(t => `<tr>
      <td>${esc(t.name)}</td><td>${esc(t.type)}</td>
      <td style="color:var(--dim)">${esc(t.host)}${t.type === "tcp" && t.port ? ":" + t.port : ""}${t.type === "http" && t.path ? esc(t.path) : ""}</td>
      <td>${t.interval}s</td><td>${t.enabled ? "启用" : "停用"}</td>
      <td><button class="btn sm ghost" onclick='testProbe(${t.id})'>⚡测试</button>
          <button class="btn sm ghost" onclick='editProbe(${t.id})'>编辑</button>
          <button class="btn sm danger" onclick="delProbe(${t.id})">删除</button></td>
    </tr>`).join("") + `</table>
    <div class="frm"><h3>➕ 添加拨测任务</h3><div id="probe-form"></div>
      <button class="btn" onclick="saveProbe(null)">添加</button></div>`;
  probeForm(null);
}

function probeForm(t){
  t = t || {name: "", type: "ping", host: "", port: 53, path: "", interval: 60, enabled: 1};
  $("probe-form").innerHTML = `
    <div class="row2">
      <div><label>任务名称</label><input id="pf-name" value="${esc(t.name)}" placeholder="如 浙江移动"></div>
      <div><label>类型</label><select id="pf-type" onchange="pfType()">
        ${["ping", "tcp", "http"].map(x => `<option ${t.type === x ? "selected" : ""}>${x}</option>`).join("")}
      </select></div>
    </div>
    <label>目标 host（ping/tcp 填 IP 或域名；http 填完整 URL 或域名）</label>
    <input id="pf-host" value="${esc(t.host)}" placeholder="如 223.5.5.5 或 https://www.10010.com">
    <div class="row2">
      <div id="pf-port-w"><label>TCP 端口</label><input id="pf-port" type="number" value="${t.port || 53}"></div>
      <div id="pf-path-w"><label>HTTP 路径（可空）</label><input id="pf-path" value="${esc(t.path || "")}" placeholder="如 /emby/System/Info/Public"></div>
    </div>
    <div class="row2">
      <div><label>探测间隔（秒）</label><input id="pf-interval" type="number" value="${t.interval || 60}"></div>
      <div><label>状态</label><select id="pf-enabled">
        <option value="1" ${t.enabled ? "selected" : ""}>启用</option>
        <option value="0" ${t.enabled ? "" : "selected"}>停用</option>
      </select></div>
    </div>
    <div class="note">ping 用系统 ping 命令测 4 次取平均；tcp 测端口连通耗时；http 测 GET 耗时。结果保留 30 天。</div>`;
  pfType();
}

function pfType(){
  const t = $("pf-type").value;
  $("pf-port-w").style.display = t === "tcp" ? "" : "none";
  $("pf-path-w").style.display = t === "http" ? "" : "none";
}

async function saveProbe(id){
  const d = {
    name: $("pf-name").value.trim(), type: $("pf-type").value,
    host: $("pf-host").value.trim(), port: $("pf-port").value,
    path: $("pf-path").value.trim(), interval: $("pf-interval").value,
    enabled: $("pf-enabled").value === "1",
  };
  const r = id == null
    ? await apiAdmin("POST", "/api/admin/probes", d)
    : await apiAdmin("PUT", `/api/admin/probes/${id}`, d);
  if (r.ok) renderAtab(); else alert("保存失败：" + (r.error || ""));
}

async function editProbe(id){
  const r = await apiAdmin("GET", "/api/admin/probes");
  const t = (r.tasks || []).find(x => x.id === id);
  if (!t) return;
  S.atab = "probes";
  const b = $("atab-body");
  b.innerHTML = `<div class="frm"><h3>✏️ 编辑拨测任务</h3><div id="probe-form"></div>
    <button class="btn" onclick="saveProbe(${id})">保存</button>
    <button class="btn ghost" onclick="renderAtab()">取消</button></div>`;
  probeForm(t);
  window.scrollTo(0, 0);
}

async function delProbe(id){
  if (!confirm("确定删除该拨测任务及其历史结果吗？")) return;
  const r = await apiAdmin("DELETE", `/api/admin/probes/${id}`);
  if (r.ok) renderAtab(); else alert("删除失败：" + (r.error || ""));
}

// v6.2：服务端即时测试拨测任务（服务端视角，各节点结果仍走 agent 周期）
async function testProbe(id){
  const btn = event && event.target ? event.target : null;
  if (btn) { btn.disabled = true; btn.textContent = "⏳…"; }
  try {
    const r = await apiAdmin("POST", `/api/admin/probes/${id}/test`);
    if (!r.ok) { alert("测试失败：" + (r.error || "")); return; }
    alert(r.reachable
      ? `✅ ${r.name}\n服务端即时测试：延迟 ${r.latency} ms，丢包 ${r.loss}%\n（各节点独立结果将在 60 秒内出现在拨测页）`
      : `❌ ${r.name}\n服务端即时测试：不通（丢包 ${r.loss}%），请检查目标地址/端口`);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "⚡测试"; }
  }
}

// ---- 告警规则 ----
const METRIC_LABEL = {cpu: "CPU%", mem: "内存%", offline: "节点离线"};
async function tabRules(b){
  const r = await apiAdmin("GET", "/api/admin/rules");
  const rules = r.rules || [];
  b.innerHTML = `<table class="tbl"><tr><th>规则</th><th>条件</th><th>持续</th><th>状态</th><th>操作</th></tr>` +
    (rules.map(x => `<tr>
      <td>${esc(x.name)}</td>
      <td>${METRIC_LABEL[x.metric] || x.metric}${x.metric === "offline" ? "" : " ≥ " + x.threshold + "%"}</td>
      <td>${x.duration} 分钟</td><td>${x.enabled ? "启用" : "停用"}</td>
      <td><button class="btn sm danger" onclick="delRule(${x.id})">删除</button></td>
    </tr>`).join("") || `<tr><td colspan="5" style="color:var(--dim)">暂无规则</td></tr>`) + `</table>
    <div class="frm"><h3>➕ 添加告警规则</h3>
      <div class="row2">
        <div><label>规则名称</label><input id="rf-name" placeholder="如 CPU 过高告警"></div>
        <div><label>指标</label><select id="rf-metric" onchange="rfMetric()">
          <option value="cpu">CPU%</option><option value="mem">内存%</option><option value="offline">节点离线</option>
        </select></div>
      </div>
      <div class="row2">
        <div id="rf-thr-w"><label>阈值 %</label><input id="rf-thr" type="number" value="90"></div>
        <div><label>持续 N 分钟后告警（0=立即）</label><input id="rf-dur" type="number" value="5"></div>
      </div>
      <button class="btn" onclick="saveRule()">添加</button>
      <div class="note">同一事件只告警一次，恢复后会发一条恢复通知；条件再次成立会重新告警。</div>
    </div>`;
}

function rfMetric(){
  $("rf-thr-w").style.display = $("rf-metric").value === "offline" ? "none" : "";
}

async function saveRule(){
  const d = {name: $("rf-name").value.trim(), metric: $("rf-metric").value,
    threshold: $("rf-thr").value, duration: $("rf-dur").value, enabled: true};
  const r = await apiAdmin("POST", "/api/admin/rules", d);
  if (r.ok) renderAtab(); else alert("保存失败：" + (r.error || ""));
}

async function delRule(id){
  if (!confirm("确定删除该告警规则吗？")) return;
  const r = await apiAdmin("DELETE", `/api/admin/rules/${id}`);
  if (r.ok) renderAtab(); else alert("删除失败：" + (r.error || ""));
}

// ---- 通知渠道 ----
const CTYPE_LABEL = {webhook: "Webhook", telegram: "Telegram", email: "邮件"};
function channelFields(type, cfg){
  cfg = cfg || {};
  const inp = (k, label, ph, pw) => `
    <div><label>${label}</label>
    <input data-k="${k}" type="${pw ? "password" : "text"}" value="${esc(cfg[k] == null ? "" : cfg[k])}" placeholder="${ph || ""}"></div>`;
  if (type === "webhook")
    return inp("url", "Webhook 地址（POST JSON）", "https://...");
  if (type === "telegram")
    return inp("bot_token", "Bot Token", "123456:ABC...", true) + inp("chat_id", "Chat ID", "123456789");
  return `<div class="row2">${inp("smtp_host", "SMTP 服务器", "smtp.resend.com")}${inp("smtp_port", "SMTP 端口", "587")}</div>
    <div class="row2">${inp("username", "SMTP 用户名", "")}${inp("password", "SMTP 密码 / 授权码", "", true)}</div>
    <div class="row2">${inp("from", "发件人（可空=用户名）", "")}${inp("to", "收件人（逗号分隔）", "a@b.com")}</div>
    <div class="note">默认 STARTTLS；端口 465 的 SSL 请确认服务商支持（当前实现为 STARTTLS）。</div>`;
}

async function tabChannels(b){
  const r = await apiAdmin("GET", "/api/admin/channels");
  const chs = r.channels || [];
  b.innerHTML = `<table class="tbl"><tr><th>名称</th><th>类型</th><th>状态</th><th>操作</th></tr>` +
    (chs.map(c => `<tr>
      <td>${esc(c.name)}</td><td>${CTYPE_LABEL[c.type] || c.type}</td>
      <td>${c.enabled ? "启用" : "停用"}</td>
      <td><button class="btn sm ghost" onclick="testChannel(${c.id})">测试</button>
          <button class="btn sm danger" onclick="delChannel(${c.id})">删除</button></td>
    </tr>`).join("") || `<tr><td colspan="4" style="color:var(--dim)">暂无渠道（不配置则告警只记日志）</td></tr>`) + `</table>
    <div class="frm"><h3>➕ 添加通知渠道</h3>
      <div class="row2">
        <div><label>名称</label><input id="cf-name" placeholder="如 我的TG"></div>
        <div><label>类型</label><select id="cf-type" onchange="cfType()">
          <option value="webhook">Webhook</option><option value="telegram">Telegram</option><option value="email">邮件</option>
        </select></div>
      </div>
      <div id="cf-fields"></div>
      <button class="btn" onclick="saveChannel()">添加</button>
      <div class="note">Webhook 会 POST JSON：{"text": "告警内容", "source": "myprobe", "time": 时间戳}。</div>
    </div>`;
  cfType();
}

function cfType(){ $("cf-fields").innerHTML = channelFields($("cf-type").value, {}); }

async function saveChannel(){
  const cfg = {};
  document.querySelectorAll("#cf-fields [data-k]").forEach(el => cfg[el.dataset.k] = el.value.trim());
  if (cfg.use_tls === undefined && $("cf-type").value === "email") cfg.use_tls = true;
  const d = {name: $("cf-name").value.trim(), type: $("cf-type").value, config: cfg, enabled: true};
  const r = await apiAdmin("POST", "/api/admin/channels", d);
  if (r.ok) renderAtab(); else alert("保存失败：" + (r.error || ""));
}

async function testChannel(id){
  const r = await apiAdmin("POST", `/api/admin/channels/${id}/test`);
  alert(r.ok ? "✅ 测试通知已发送，请查收" : "❌ " + (r.error || "发送失败"));
}

async function delChannel(id){
  if (!confirm("确定删除该通知渠道吗？")) return;
  const r = await apiAdmin("DELETE", `/api/admin/channels/${id}`);
  if (r.ok) renderAtab(); else alert("删除失败：" + (r.error || ""));
}

// ---- 告警记录 ----
async function tabAlerts(b){
  const r = await apiAdmin("GET", "/api/admin/alerts");
  const list = r.alerts || [];
  b.innerHTML = list.length ? `<table class="tbl"><tr><th>时间</th><th>类型</th><th>内容</th></tr>` +
    list.map(a => `<tr>
      <td style="white-space:nowrap">${new Date(a.ts * 1000).toLocaleString("zh-CN")}</td>
      <td>${a.level === "firing" ? "🚨 告警" : "✅ 恢复"}</td>
      <td style="white-space:pre-wrap">${esc(a.message)}</td>
    </tr>`).join("") + `</table>`
    : `<div class="empty">暂无告警记录</div>`;
}

window.openDetail = openDetail; window.closeDetail = closeDetail;
window.setRange = setRange; window.renameNode = renameNode; window.deleteNode = deleteNode;
window.nav = nav; window.atab = atab; window.saveNodeMeta = saveNodeMeta; window.updAddNodeCmd = updAddNodeCmd; window.copyAddNodeCmd = copyAddNodeCmd;
window.saveProbe = saveProbe; window.editProbe = editProbe; window.delProbe = delProbe; window.testProbe = testProbe;
window.pfType = pfType; window.saveRule = saveRule; window.delRule = delRule;
window.rfMetric = rfMetric; window.cfType = cfType; window.saveChannel = saveChannel;
window.testChannel = testChannel; window.delChannel = delChannel;
window.addEventListener("resize", () => { if (S.sel) loadHistory(); });

// ================= v3：主题 / 插件管理 =================
async function tabThemes(b){
  const r = await apiAdmin("GET", "/api/admin/themes");
  const ts = r.themes || [];
  b.innerHTML = `<table class="tbl"><tr><th>主题</th><th>版本</th><th>作者</th><th>说明</th><th>状态</th><th>操作</th></tr>` +
    ts.map(t => `<tr><td>${esc(t.name)}<br><small style="color:var(--dim)">${esc(t.id)}</small></td>` +
      `<td>${esc(t.version || "")}</td><td>${esc(t.author || "")}</td>` +
      `<td style="color:var(--dim)">${esc(t.description || "")}</td>` +
      `<td>${t.active ? '<span class="badge green">使用中</span>' : ""}${t.builtin ? ' <span class="badge dim">内建</span>' : ""}</td>` +
      `<td>${t.active ? "" : `<button class="btn sm ghost" onclick="activateTheme('${esc(t.id)}')">启用</button>`}` +
      `${(!t.active && !t.builtin) ? ` <button class="btn sm danger" onclick="delTheme('${esc(t.id)}')">删除</button>` : ""}</td></tr>`).join("") +
    `</table>
    <div class="frm"><h3>⬆️ 上传主题（zip 包）</h3>
      <input type="file" id="theme-file" accept=".zip">
      <button class="btn" onclick="uploadTheme()">上传</button>
      <div class="note">zip 内必须包含 theme.json（里面写清 id / 名称 / 版本 / 作者）。<br>
      主题目录结构：<code>theme.json</code> / <code>templates/dashboard.html</code>（覆盖默认看板；缺文件自动回退默认模板）/ <code>static/</code>（经 <code>/theme-static/&lt;id&gt;/</code> 访问）。<br>
      含路径穿越的 zip 会被直接拒绝。模板可用变量见 README「主题开发指南」。</div></div>`;
}
async function uploadTheme(){
  const f = $("theme-file").files[0];
  if (!f) return alert("请先选择 zip 文件");
  const fd = new FormData(); fd.append("file", f);
  const r = await (await fetch("/api/admin/themes/upload", {method: "POST", body: fd})).json();
  if (!r.ok) return alert("上传失败：" + (r.error || "未知错误"));
  atab("themes");
}
async function activateTheme(id){
  const r = await apiAdmin("POST", `/api/admin/themes/${encodeURIComponent(id)}/activate`);
  if (!r.ok) return alert("启用失败：" + (r.error || ""));
  location.reload();
}
async function delTheme(id){
  if (!confirm("确定删除主题 " + id + "？")) return;
  const r = await apiAdmin("DELETE", `/api/admin/themes/${encodeURIComponent(id)}`);
  if (!r.ok) return alert("删除失败：" + (r.error || ""));
  atab("themes");
}
async function tabPlugins(b){
  const r = await apiAdmin("GET", "/api/admin/plugins");
  const ps = r.plugins || [];
  b.innerHTML = `<div class="frm" style="border-color:var(--yellow)"><h3>⚠️ 安全提醒</h3>
    <div class="note">插件是以服务端代码运行的（和 server.py 同等权限），只安装信任来源的插件。单个插件出错不会拖垮服务（钩子调用有异常隔离）。</div></div>` +
    `<table class="tbl"><tr><th>插件</th><th>版本</th><th>作者</th><th>说明</th><th>钩子</th><th>状态</th><th>操作</th></tr>` +
    ps.map(p => `<tr><td>${esc(p.name)}<br><small style="color:var(--dim)">${esc(p.id)}</small></td>` +
      `<td>${esc(p.version || "")}</td><td>${esc(p.author || "")}</td>` +
      `<td style="color:var(--dim)">${esc(p.description || "")}</td>` +
      `<td><small style="color:var(--dim)">${esc((p.hooks || []).join(", "))}</small></td>` +
      `<td>${p.enabled ? '<span class="badge green">已启用</span>' : '<span class="badge dim">已停用</span>'}</td>` +
      `<td><button class="btn sm ghost" onclick="togglePlugin('${esc(p.id)}', ${p.enabled ? 0 : 1})">${p.enabled ? "停用" : "启用"}</button>` +
      ` <button class="btn sm danger" onclick="delPlugin('${esc(p.id)}')">删除</button></td></tr>`).join("") +
    `</table>
    <div class="frm"><h3>⬆️ 上传插件（zip 包）</h3>
      <input type="file" id="plugin-file" accept=".zip">
      <button class="btn" onclick="uploadPlugin()">上传</button>
      <button class="btn ghost" onclick="reloadPlugins()">🔄 重新加载插件</button>
      <div class="note">zip 内必须包含 plugin.json + plugin.py。钩子：<code>on_report</code> / <code>on_alert</code> / <code>dashboard_cards</code> / <code>admin_pages</code>，详见 README「插件开发指南」。</div></div>`;
}
async function uploadPlugin(){
  const f = $("plugin-file").files[0];
  if (!f) return alert("请先选择 zip 文件");
  const fd = new FormData(); fd.append("file", f);
  const r = await (await fetch("/api/admin/plugins/upload", {method: "POST", body: fd})).json();
  if (!r.ok) return alert("上传失败：" + (r.error || "未知错误"));
  atab("plugins");
}
async function togglePlugin(id, on){
  const r = await apiAdmin("POST", `/api/admin/plugins/${encodeURIComponent(id)}/${on ? "enable" : "disable"}`);
  if (!r.ok) return alert("操作失败：" + (r.error || ""));
  atab("plugins");
}
async function reloadPlugins(){
  const r = await apiAdmin("POST", "/api/admin/plugins/reload");
  if (!r.ok) return alert("重载失败：" + (r.error || ""));
  alert("已重载 " + r.count + " 个插件");
  atab("plugins");
}
async function delPlugin(id){
  if (!confirm("确定删除插件 " + id + "？")) return;
  const r = await apiAdmin("DELETE", `/api/admin/plugins/${encodeURIComponent(id)}`);
  if (!r.ok) return alert("删除失败：" + (r.error || ""));
  atab("plugins");
}
window.uploadTheme = uploadTheme; window.activateTheme = activateTheme; window.delTheme = delTheme;
window.uploadPlugin = uploadPlugin; window.togglePlugin = togglePlugin;
window.reloadPlugins = reloadPlugins; window.delPlugin = delPlugin;

boot();
</script>
</body></html>"""

# ================= v2/v5：拨测任务定义（CRUD 见下方 admin API） =================
# v5 起拨测由各节点 agent 自行执行并上报，服务端不再定时执行。
# run_probe / probe_worker 已删除；probe_results 表保留但不再写入。
def valid_probe_task(d):
    """校验拨测任务字段，返回 (ok, error)。"""
    if not isinstance(d, dict):
        return False, "数据格式错误"
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
    """v6.2：服务端即时执行单个拨测任务 3 次（与 agent 逻辑一致）。
    返回 (avg_latency_ms 或 None, loss_%)。绝不抛异常。注意：这是从服务端视角探测，
    各节点的独立探测结果仍由 agent 按周期上报。"""
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
        else:  # http
            url = host if host.startswith("http") else "http://" + host
            if path:
                url = url.rstrip("/") + path
            lat, fails = [], 0
            for _ in range(n):
                t0 = time.time()
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 MyProbe"})
                    with urllib.request.urlopen(req, timeout=6) as r:
                        r.read(1024)
                    lat.append((time.time() - t0) * 1000)
                except Exception:
                    fails += 1
            return (sum(lat) / len(lat) if lat else None, fails / n * 100.0)
    except Exception:
        return (None, 100.0)


@app.route("/api/probes")
def api_probes():
    """公开：拨测任务 + 最新结果 + 近 30 次历史（画小条形图用）。"""
    db = get_db()
    tasks = db.execute("SELECT * FROM probe_tasks ORDER BY id").fetchall()
    out = []
    for t in tasks:
        last = db.execute(
            "SELECT * FROM probe_results WHERE task_id=? ORDER BY ts DESC LIMIT 1",
            (t["id"],),
        ).fetchone()
        bars = db.execute(
            "SELECT ts, latency, loss, ok FROM probe_results WHERE task_id=?"
            " ORDER BY ts DESC LIMIT 30",
            (t["id"],),
        ).fetchall()
        out.append({
            "id": t["id"], "name": t["name"], "type": t["type"],
            "host": t["host"], "port": t["port"], "path": t["path"],
            "interval": t["interval"], "enabled": t["enabled"],
            "latency": last["latency"] if last else None,
            "loss": last["loss"] if last else None,
            "ok": bool(last["ok"]) if last else None,
            "last_ts": last["ts"] if last else None,
            "bars": [{"ts": b["ts"], "latency": b["latency"],
                      "loss": b["loss"], "ok": bool(b["ok"])} for b in reversed(bars)],
        })
    return jsonify({"ok": True, "tasks": out})

@app.route("/api/admin/probes", methods=["GET"])
@login_required
def admin_probes_list():
    db = get_db()
    rows = db.execute("SELECT * FROM probe_tasks ORDER BY id").fetchall()
    return jsonify({"ok": True, "tasks": [dict(r) for r in rows]})

@app.route("/api/admin/probes", methods=["POST"])
@login_required
def admin_probe_create():
    d = request.get_json(silent=True) or {}
    ok, err = valid_probe_task(d)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    db = get_db()
    cur = db.execute(
        """INSERT INTO probe_tasks (name, type, host, port, path, interval, enabled, created)
           VALUES (?,?,?,?,?,?,?,?)""",
        (d["name"].strip(), d["type"].strip(), d["host"].strip(),
         int(d.get("port") or 0) or None, (d.get("path") or "").strip()[:256] or None,
         int(d.get("interval") or 60), 1 if d.get("enabled", True) else 0,
         int(time.time())),
    )
    db.commit()
    return jsonify({"ok": True, "id": cur.lastrowid})

@app.route("/api/admin/probes/<int:tid>", methods=["PUT"])
@login_required
def admin_probe_update(tid):
    d = request.get_json(silent=True) or {}
    ok, err = valid_probe_task(d)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    db = get_db()
    cur = db.execute(
        """UPDATE probe_tasks SET name=?, type=?, host=?, port=?, path=?,
           interval=?, enabled=? WHERE id=?""",
        (d["name"].strip(), d["type"].strip(), d["host"].strip(),
         int(d.get("port") or 0) or None, (d.get("path") or "").strip()[:256] or None,
         int(d.get("interval") or 60), 1 if d.get("enabled", True) else 0, tid),
    )
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    return jsonify({"ok": True})

@app.route("/api/admin/probes/<int:tid>", methods=["DELETE"])
@login_required
def admin_probe_delete(tid):
    db = get_db()
    db.execute("DELETE FROM probe_results WHERE task_id=?", (tid,))
    cur = db.execute("DELETE FROM probe_tasks WHERE id=?", (tid,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    return jsonify({"ok": True})

@app.route("/api/admin/probes/<int:tid>/test", methods=["POST"])
@login_required
def admin_probe_test(tid):
    """v6.2：服务端即时执行一次拨测任务，返回延迟/丢包（服务端视角）。"""
    db = get_db()
    r = db.execute("SELECT * FROM probe_tasks WHERE id=?", (tid,)).fetchone()
    if not r:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    lat, loss = run_probe_now(dict(r))
    return jsonify({"ok": True, "id": tid, "name": r["name"],
                    "latency": round(lat, 1) if lat is not None else None,
                    "loss": round(loss, 1), "reachable": lat is not None})

# ================= v2：节点计费/到期/配额 =================
@app.route("/api/admin/node/<nid>/meta", methods=["PUT"])
@login_required
def admin_node_meta(nid):
    if not valid_node_id(nid):
        return jsonify({"ok": False, "error": "node_id 不合法"}), 400
    d = request.get_json(silent=True) or {}

    def num(key):
        v = d.get(key)
        if v is None or v == "":
            return None
        try:
            return float(v)
        except Exception:
            return "ERR"

    price, quota = num("price"), num("quota_gb")
    if price == "ERR" or quota == "ERR":
        return jsonify({"ok": False, "error": "价格/配额必须是数字"}), 400
    if quota is not None and quota <= 0:
        return jsonify({"ok": False, "error": "配额必须大于 0"}), 400
    # v4.1：本月已用基准（老表单没这个字段时保持原值不动）
    base_raw = d.get("quota_base_gb", None) if "quota_base_gb" in d else "##ABSENT##"
    base = num("quota_base_gb") if base_raw != "##ABSENT##" else "##ABSENT##"
    if base == "ERR":
        return jsonify({"ok": False, "error": "已用基准必须是数字"}), 400
    if isinstance(base, float) and base < 0:
        return jsonify({"ok": False, "error": "已用基准不能为负"}), 400
    currency = (d.get("currency") or "").strip()[:8] or None
    cycle = (d.get("bill_cycle") or "").strip()
    if cycle not in ("", "monthly", "yearly"):
        return jsonify({"ok": False, "error": "计费周期只能是 monthly / yearly"}), 400
    buy = (d.get("buy_date") or "").strip() or None
    exp = (d.get("expire_date") or "").strip() or None
    if buy and not parse_ymd(buy):
        return jsonify({"ok": False, "error": "购买日期格式应为 YYYY-MM-DD"}), 400
    if exp and not parse_ymd(exp):
        return jsonify({"ok": False, "error": "到期日期格式应为 YYYY-MM-DD"}), 400
    # v5.1/v6.0：SSH 连接信息 —— 每个字段独立处理，缺席=保持原值不动
    # （避免只改一项时把同组其他字段重置为默认值）
    ssh_sets, ssh_vals = [], []
    if "ssh_host" in d:
        ssh_sets.append("ssh_host=?")
        ssh_vals.append((d.get("ssh_host") or "").strip()[:253])
    if "ssh_port" in d:
        ssh_port_raw = str(d.get("ssh_port") if d.get("ssh_port") is not None else "").strip()
        if not ssh_port_raw:
            ssh_port = 22
        else:
            try:
                ssh_port = int(ssh_port_raw)
            except Exception:
                return jsonify({"ok": False, "error": "SSH 端口必须是 1-65535 的数字"}), 400
            if not 1 <= ssh_port <= 65535:
                return jsonify({"ok": False, "error": "SSH 端口必须是 1-65535 的数字"}), 400
        ssh_sets.append("ssh_port=?")
        ssh_vals.append(ssh_port)
    if "ssh_user" in d:
        ssh_sets.append("ssh_user=?")
        ssh_vals.append((d.get("ssh_user") or "").strip()[:64] or "root")
    # v6.0：SSH 密码 —— Fernet 加密存库；字段存在但为空=不改；ssh_clear_pass=true=清除
    ssh_pass_new = "##ABSENT##"
    if "ssh_password" in d:
        _pw = d.get("ssh_password") or ""
        if _pw:
            try:
                ssh_pass_new = encrypt_pass(_pw)
            except Exception as e:
                return jsonify({"ok": False, "error": f"密码加密失败：{e}"}), 500
    ssh_clear_pass = bool(d.get("ssh_clear_pass"))
    db = get_db()
    sets = ["price=?", "currency=?", "bill_cycle=?", "buy_date=?",
            "expire_date=?", "quota_gb=?"]
    vals = [price, currency, cycle or None, buy, exp, quota]
    if base != "##ABSENT##":
        cur_month = time.strftime("%Y-%m", time.localtime())
        sets += ["quota_base_gb=?", "quota_base_month=?"]
        vals += [base, (cur_month if base is not None else None)]
    sets += ssh_sets
    vals += ssh_vals
    if ssh_pass_new != "##ABSENT##":
        sets += ["ssh_pass_enc=?"]
        vals += [ssh_pass_new]
    elif ssh_clear_pass:
        sets += ["ssh_pass_enc=?"]
        vals += [""]
    vals.append(nid)
    cur = db.execute(f"UPDATE nodes SET {', '.join(sets)} WHERE id=?", vals)
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "节点不存在"}), 404
    return jsonify({"ok": True})

# ================= v2：阈值告警 =================
def eval_rule(db, rule, node, now):
    """评估单条规则对单个节点是否触发。返回 (触发?, 描述)。"""
    metric = rule["metric"]
    if metric == "offline":
        last = node["last_seen"] or 0
        if last and now - last >= OFFLINE_AFTER:
            mins = (now - last) // 60
            return True, f"节点已离线约 {mins} 分钟"
        return False, ""
    m = db.execute("SELECT cpu, mem FROM metrics WHERE node_id=? ORDER BY ts DESC LIMIT 1",
                   (node["id"],)).fetchone()
    if not m:
        return False, ""
    v = m["cpu"] if metric == "cpu" else m["mem"]
    label = "CPU" if metric == "cpu" else "内存"
    if v is not None and v >= (rule["threshold"] or 0):
        return True, f"{label} {v:.1f}% ≥ {rule['threshold']}%"
    return False, ""

def send_webhook(cfg, text):
    url = (cfg.get("url") or "").strip()
    if not url:
        return
    req = urllib.request.Request(
        url, data=json.dumps({"text": text, "source": "myprobe",
                              "time": int(time.time())}).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read(1024)

def send_telegram(cfg, text):
    token = (cfg.get("bot_token") or "").strip()
    chat_id = (cfg.get("chat_id") or "").strip()
    if not token or not chat_id:
        return
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read(1024)

def send_email(cfg, text):
    host = (cfg.get("smtp_host") or "").strip()
    if not host:
        return
    port = int(cfg.get("smtp_port") or 587)
    user = (cfg.get("username") or "").strip()
    pwd = cfg.get("password") or ""
    from_addr = (cfg.get("from") or user).strip()
    to_addrs = [a.strip() for a in (cfg.get("to") or "").split(",") if a.strip()]
    if not to_addrs:
        return
    msg = EmailMessage()
    msg["Subject"] = "MyProbe 告警"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(text)
    with smtplib.SMTP(host, port, timeout=15) as s:
        if cfg.get("use_tls", True):
            s.starttls()
        if user:
            s.login(user, pwd)
        s.send_message(msg)

def send_all(db, text):
    """通过所有启用的渠道发通知，单个渠道失败不影响其他。"""
    senders = {"webhook": send_webhook, "telegram": send_telegram, "email": send_email}
    for ch in db.execute("SELECT * FROM alert_channels WHERE enabled=1").fetchall():
        fn = senders.get(ch["type"])
        if not fn:
            continue
        try:
            cfg = json.loads(ch["config"] or "{}")
            fn(cfg, text)
            print(f"[alert] 已通过 [{ch['name']}] 发送通知", flush=True)
        except Exception as e:
            print(f"[alert] 渠道 [{ch['name']}] 发送失败: {e}", file=sys.stderr, flush=True)

def fire_alert(db, r, n, now, desc):
    """触发一条告警：发通知 + 写日志 + 标记已告警。"""
    text = (f"🚨 MyProbe 告警\n规则：{r['name']}\n节点：{n['name']}\n{desc}\n"
            f"时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    send_all(db, text)
    db.execute(
        "INSERT INTO alerts_log (ts, rule_id, node_id, message, level)"
        " VALUES (?,?,?,?,?)",
        (now, r["id"], n["id"], text, "firing"))
    db.execute(
        "UPDATE alert_state SET alerted=1 WHERE rule_id=? AND node_id=?",
        (r["id"], n["id"]))
    db.commit()
    # v3：插件钩子（异常隔离）
    try:
        fire_plugin_hook("on_alert", alert={
            "rule": r["name"], "rule_id": r["id"], "node_id": n["id"],
            "node_name": n["name"], "message": text, "level": "firing", "time": now})
    except Exception:
        pass

def check_alerts():
    db = db_conn()
    try:
        rules = [dict(r) for r in
                 db.execute("SELECT * FROM alert_rules WHERE enabled=1").fetchall()]
        if not rules:
            return
        nodes = db.execute("SELECT * FROM nodes").fetchall()
        now = int(time.time())
        for r in rules:
            for n in nodes:
                cond, desc = eval_rule(db, r, n, now)
                st = db.execute(
                    "SELECT * FROM alert_state WHERE rule_id=? AND node_id=?",
                    (r["id"], n["id"])).fetchone()
                if cond:
                    need = (r["duration"] or 0) * 60
                    if st is None:
                        db.execute(
                            "INSERT INTO alert_state (rule_id, node_id, bad_since, alerted)"
                            " VALUES (?,?,?,0)", (r["id"], n["id"], now))
                        db.commit()
                        if need == 0:
                            # 持续时间为 0 = 立即告警，不等下一轮
                            fire_alert(db, r, n, now, desc)
                        continue
                    if now - (st["bad_since"] or now) >= need and not st["alerted"]:
                        fire_alert(db, r, n, now, desc)
                else:
                    if st is not None:
                        if st["alerted"]:
                            text = (f"✅ MyProbe 恢复\n规则：{r['name']}\n"
                                    f"节点：{n['name']}\n"
                                    f"时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
                            send_all(db, text)
                            db.execute(
                                "INSERT INTO alerts_log (ts, rule_id, node_id, message, level)"
                                " VALUES (?,?,?,?,?)",
                                (now, r["id"], n["id"], text, "resolved"))
                            db.commit()
                        db.execute("DELETE FROM alert_state WHERE rule_id=? AND node_id=?",
                                   (r["id"], n["id"]))
                        db.commit()
    finally:
        db.close()

def alert_worker():
    """后台告警线程：每分钟评估一次。"""
    print("[alert] 告警线程启动", flush=True)
    while True:
        try:
            check_alerts()
        except Exception as e:
            print(f"[alert] 线程异常: {e}", file=sys.stderr, flush=True)
        time.sleep(60)

# ---- 告警规则管理 ----
@app.route("/api/admin/rules", methods=["GET"])
@login_required
def admin_rules_list():
    db = get_db()
    rows = db.execute("SELECT * FROM alert_rules ORDER BY id").fetchall()
    return jsonify({"ok": True, "rules": [dict(r) for r in rows]})

@app.route("/api/admin/rules", methods=["POST"])
@login_required
def admin_rule_create():
    d = request.get_json(silent=True) or {}
    name = (d.get("name") or "").strip()
    metric = (d.get("metric") or "").strip()
    if not name or len(name) > 64:
        return jsonify({"ok": False, "error": "规则名称不能为空（64字符内）"}), 400
    if metric not in ("cpu", "mem", "offline"):
        return jsonify({"ok": False, "error": "指标只能是 cpu / mem / offline"}), 400
    try:
        threshold = float(d.get("threshold") or 0)
        duration = int(d.get("duration") or 0)
    except Exception:
        return jsonify({"ok": False, "error": "阈值/持续时间必须是数字"}), 400
    if metric in ("cpu", "mem") and not 1 <= threshold <= 100:
        return jsonify({"ok": False, "error": "CPU/内存阈值需在 1~100 之间"}), 400
    if not 0 <= duration <= 1440:
        return jsonify({"ok": False, "error": "持续时间需在 0~1440 分钟之间"}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO alert_rules (name, metric, threshold, duration, enabled)"
        " VALUES (?,?,?,?,?)",
        (name, metric, threshold, duration, 1 if d.get("enabled", True) else 0))
    db.commit()
    return jsonify({"ok": True, "id": cur.lastrowid})

@app.route("/api/admin/rules/<int:rid>", methods=["PUT"])
@login_required
def admin_rule_update(rid):
    d = request.get_json(silent=True) or {}
    name = (d.get("name") or "").strip()
    metric = (d.get("metric") or "").strip()
    if not name or metric not in ("cpu", "mem", "offline"):
        return jsonify({"ok": False, "error": "参数不合法"}), 400
    try:
        threshold = float(d.get("threshold") or 0)
        duration = int(d.get("duration") or 0)
    except Exception:
        return jsonify({"ok": False, "error": "阈值/持续时间必须是数字"}), 400
    db = get_db()
    cur = db.execute(
        "UPDATE alert_rules SET name=?, metric=?, threshold=?, duration=?, enabled=?"
        " WHERE id=?",
        (name, metric, threshold, duration, 1 if d.get("enabled", True) else 0, rid))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "规则不存在"}), 404
    return jsonify({"ok": True})

@app.route("/api/admin/rules/<int:rid>", methods=["DELETE"])
@login_required
def admin_rule_delete(rid):
    db = get_db()
    db.execute("DELETE FROM alert_state WHERE rule_id=?", (rid,))
    cur = db.execute("DELETE FROM alert_rules WHERE id=?", (rid,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "规则不存在"}), 404
    return jsonify({"ok": True})

# ---- 通知渠道管理 ----
CHANNEL_FIELDS = {
    "webhook": ["url"],
    "telegram": ["bot_token", "chat_id"],
    "email": ["smtp_host", "smtp_port", "username", "password", "from", "to", "use_tls"],
}

@app.route("/api/admin/channels", methods=["GET"])
@login_required
def admin_channels_list():
    db = get_db()
    rows = db.execute("SELECT * FROM alert_channels ORDER BY id").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            cfg = json.loads(d["config"] or "{}")
        except Exception:
            cfg = {}
        if d["type"] == "email" and cfg.get("password"):
            cfg["password"] = "******"  # 列表里不回显密码
        d["config"] = cfg
        out.append(d)
    return jsonify({"ok": True, "channels": out})

@app.route("/api/admin/channels", methods=["POST"])
@login_required
def admin_channel_create():
    return _channel_save(None)

@app.route("/api/admin/channels/<int:cid>", methods=["PUT"])
@login_required
def admin_channel_update(cid):
    return _channel_save(cid)

def _channel_save(cid):
    d = request.get_json(silent=True) or {}
    ctype = (d.get("type") or "").strip()
    name = (d.get("name") or "").strip()
    cfg = d.get("config") or {}
    if ctype not in CHANNEL_FIELDS:
        return jsonify({"ok": False, "error": "渠道类型只能是 webhook / telegram / email"}), 400
    if not name or len(name) > 64:
        return jsonify({"ok": False, "error": "渠道名称不能为空（64字符内）"}), 400
    if not isinstance(cfg, dict):
        return jsonify({"ok": False, "error": "配置格式错误"}), 400
    db = get_db()
    if cid is not None:
        # 更新时密码填 ****** 表示不改
        old = db.execute("SELECT config FROM alert_channels WHERE id=?", (cid,)).fetchone()
        if not old:
            return jsonify({"ok": False, "error": "渠道不存在"}), 404
        try:
            old_cfg = json.loads(old["config"] or "{}")
        except Exception:
            old_cfg = {}
        if cfg.get("password") in (None, "", "******"):
            if old_cfg.get("password"):
                cfg["password"] = old_cfg["password"]
        cur = db.execute(
            "UPDATE alert_channels SET type=?, name=?, config=?, enabled=? WHERE id=?",
            (ctype, name, json.dumps(cfg), 1 if d.get("enabled", True) else 0, cid))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({"ok": False, "error": "渠道不存在"}), 404
    else:
        cur = db.execute(
            "INSERT INTO alert_channels (type, name, config, enabled) VALUES (?,?,?,?)",
            (ctype, name, json.dumps(cfg), 1 if d.get("enabled", True) else 0))
        db.commit()
    return jsonify({"ok": True, "id": cid or cur.lastrowid})

@app.route("/api/admin/channels/<int:cid>", methods=["DELETE"])
@login_required
def admin_channel_delete(cid):
    db = get_db()
    cur = db.execute("DELETE FROM alert_channels WHERE id=?", (cid,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "渠道不存在"}), 404
    return jsonify({"ok": True})

@app.route("/api/admin/channels/<int:cid>/test", methods=["POST"])
@login_required
def admin_channel_test(cid):
    """发一条测试通知，验证渠道配置。"""
    db = get_db()
    ch = db.execute("SELECT * FROM alert_channels WHERE id=?", (cid,)).fetchone()
    if not ch:
        return jsonify({"ok": False, "error": "渠道不存在"}), 404
    senders = {"webhook": send_webhook, "telegram": send_telegram, "email": send_email}
    fn = senders.get(ch["type"])
    if not fn:
        return jsonify({"ok": False, "error": "未知渠道类型"}), 400
    try:
        cfg = json.loads(ch["config"] or "{}")
        if ch["type"] == "email" and cfg.get("password") == "******":
            return jsonify({"ok": False, "error": "请先重新填写邮箱密码再测试"}), 400
        fn(cfg, f"🔔 MyProbe 测试通知\n渠道：{ch['name']}\n"
                f"时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n如果你收到这条，说明渠道配置正确。")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": f"发送失败：{e}"}), 500

@app.route("/api/admin/alerts", methods=["GET"])
@login_required
def admin_alerts_log():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM alerts_log ORDER BY ts DESC LIMIT 100").fetchall()
    return jsonify({"ok": True, "alerts": [dict(r) for r in rows]})

# ================= v3：主题与插件 =================
import shutil as _shutil
from jinja2 import ChoiceLoader as _ChoiceLoader
from jinja2 import DictLoader as _DictLoader
from jinja2 import Environment as _JinjaEnv
from jinja2 import FileSystemLoader as _FileSystemLoader

MYPROBE_VERSION = "6.2"

THEMES_DIR = os.environ.get("MYPROBE_THEMES_DIR", os.path.join(BASE_DIR, "themes"))
PLUGINS_DIR = os.environ.get("MYPROBE_PLUGINS_DIR", os.path.join(BASE_DIR, "plugins"))
os.makedirs(THEMES_DIR, exist_ok=True)
os.makedirs(PLUGINS_DIR, exist_ok=True)

SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# v5：各节点独立拨测结果（agent 上报）
SCHEMA_V5 = """
CREATE TABLE IF NOT EXISTS node_probe_results (
    node_id    TEXT NOT NULL,
    task_id    INTEGER NOT NULL,
    ts         INTEGER NOT NULL,
    latency_ms REAL,                 -- 平均延迟 ms（全失败则为 NULL）
    loss_pct   REAL,                 -- 丢包率 %
    PRIMARY KEY (node_id, task_id)
);
CREATE TABLE IF NOT EXISTS node_probe_history (
    node_id    TEXT NOT NULL,
    task_id    INTEGER NOT NULL,
    ts         INTEGER NOT NULL,
    latency_ms REAL,
    ok         INTEGER,               -- 至少一次成功=1
    PRIMARY KEY (node_id, task_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_nph_node_task_ts ON node_probe_history(node_id, task_id, ts);
"""

DEFAULT_THEME = {
    "id": "default", "name": "默认深色", "version": MYPROBE_VERSION,
    "author": "MyProbe", "description": "内建深色看板（不可删除，模板缺失时自动回退到它）",
    "builtin": True,
}

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _valid_id(s):
    return bool(_ID_RE.match(s or ""))


def _read_json_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# ---------- settings 键值 ----------
def get_setting_db(db, key, default=None):
    r = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def get_setting(key, default=None):
    return get_setting_db(get_db(), key, default)


def set_setting(key, value):
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value))
    db.commit()


# ---------- 主题 ----------
def list_themes():
    active = get_setting("active_theme", "default")
    out = [dict(DEFAULT_THEME, active=(active == "default"))]
    if os.path.isdir(THEMES_DIR):
        for tid in sorted(os.listdir(THEMES_DIR)):
            if not _valid_id(tid):
                continue
            tdir = os.path.join(THEMES_DIR, tid)
            if not os.path.isdir(tdir):
                continue
            meta = _read_json_file(os.path.join(tdir, "theme.json")) or {}
            out.append({
                "id": tid,
                "name": str(meta.get("name", tid)),
                "version": str(meta.get("version", "")),
                "author": str(meta.get("author", "")),
                "description": str(meta.get("description", "")),
                "builtin": False,
                "active": (active == tid),
            })
    return out


def _jinja_env_for(active):
    loaders = []
    tdir = os.path.join(THEMES_DIR, active, "templates")
    if active != "default" and os.path.isdir(tdir):
        loaders.append(_FileSystemLoader(tdir))
    loaders.append(_DictLoader({"dashboard.html": DASHBOARD_HTML}))
    return _JinjaEnv(loader=_ChoiceLoader(loaders), autoescape=False)


def render_dashboard():
    """用当前主题渲染看板；主题模板出错时回退内建默认模板。"""
    cards, tabs = collect_plugin_ui()
    active = get_setting("active_theme", "default")
    ctx = {
        # ---- 模板变量（主题开发见 README）----
        "plugin_cards": cards,                       # 插件注入的看板卡片 HTML
        "plugin_admin_tabs_json": json.dumps(tabs, ensure_ascii=False),  # 插件管理页标签
        "theme": {"id": active},                     # 当前主题 id
        "theme_static": f"/theme-static/{active}",   # 主题静态文件前缀
        "version": MYPROBE_VERSION,                  # 服务端版本
    }
    try:
        return _jinja_env_for(active).get_template("dashboard.html").render(**ctx)
    except Exception as e:
        print(f"[theme] 主题 {active} 渲染失败，已回退默认模板：{e}", file=sys.stderr, flush=True)
        return _JinjaEnv(loader=_DictLoader({"dashboard.html": DASHBOARD_HTML}),
                         autoescape=False).get_template("dashboard.html").render(**ctx)


@app.route("/theme-static/<tid>/<path:filename>")
def theme_static(tid, filename):
    if not _valid_id(tid) or tid == "default":
        return "not found", 404
    sdir = os.path.join(THEMES_DIR, tid, "static")
    if not os.path.isdir(sdir):
        return "not found", 404
    return send_from_directory(sdir, filename)


def safe_extract_zip(zpath, dest_dir, required):
    """安全解压 zip：防路径穿越，required 为 zip 根（允许套一层目录）必须包含的文件。
    返回 (True, "") 或 (False, 错误信息)。"""
    import zipfile
    try:
        zf = zipfile.ZipFile(zpath)
    except Exception as e:
        return False, f"不是有效的 zip 文件：{e}"
    infos = [i for i in zf.infolist()
             if not i.is_dir() and not i.filename.startswith("__MACOSX")]
    if not infos:
        return False, "zip 是空的"
    for i in infos:
        n = i.filename
        if n.startswith("/") or "\\" in n or ".." in n.split("/"):
            return False, f"zip 内含非法路径，已拒绝：{n}"
    parts = [i.filename.split("/") for i in infos]
    prefix_len = 0
    if len(parts[0]) > 1:
        cand = parts[0][0]
        if all(len(p) > 1 and p[0] == cand for p in parts):
            prefix_len = 1  # 允许 zip 里套一层文件夹
    rel = {}
    for i, p in zip(infos, parts):
        r = "/".join(p[prefix_len:])
        if r:
            rel[r] = i
    for req in required:
        if req not in rel:
            return False, f"zip 缺少必需文件：{req}"
    os.makedirs(dest_dir, exist_ok=True)
    abs_dest = os.path.abspath(dest_dir)
    for r, info in rel.items():
        target = os.path.abspath(os.path.join(dest_dir, *r.split("/")))
        if os.path.commonpath([target, abs_dest]) != abs_dest:
            return False, f"非法路径：{r}"
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as dst:
            _shutil.copyfileobj(src, dst)
    return True, ""


def _stage_upload(file_storage, required):
    """把上传的 zip 存到临时目录并安全解压，返回 (stage_dir, err)。"""
    tmp = "/tmp/mp_up_%d_%d.zip" % (os.getpid(), int(time.time() * 1000))
    file_storage.save(tmp)
    stage = tmp + ".d"
    os.makedirs(stage, exist_ok=True)
    ok, msg = safe_extract_zip(tmp, stage, required)
    try:
        os.remove(tmp)
    except OSError:
        pass
    if not ok:
        _shutil.rmtree(stage, ignore_errors=True)
        return None, msg
    return stage, ""


@app.route("/api/admin/themes")
@login_required
def admin_themes_list():
    return jsonify({"ok": True, "themes": list_themes()})


@app.route("/api/admin/themes/upload", methods=["POST"])
@login_required
def admin_theme_upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        return jsonify({"ok": False, "error": "请选择 zip 文件"}), 400
    stage, err = _stage_upload(f, ["theme.json"])
    if stage is None:
        return jsonify({"ok": False, "error": err}), 400
    try:
        meta = _read_json_file(os.path.join(stage, "theme.json")) or {}
        tid = str(meta.get("id", "")).strip()
        if not _valid_id(tid):
            return jsonify({"ok": False, "error": "theme.json 里的 id 不合法（限字母数字/_/-，64字符内）"}), 400
        if tid == "default":
            return jsonify({"ok": False, "error": "不能覆盖内建 default 主题"}), 400
        dest = os.path.join(THEMES_DIR, tid)
        if os.path.exists(dest):
            return jsonify({"ok": False, "error": f"主题 {tid} 已存在，请先删除"}), 400
        _shutil.move(stage, dest)
        return jsonify({"ok": True, "id": tid})
    finally:
        _shutil.rmtree(stage, ignore_errors=True)


@app.route("/api/admin/themes/<tid>/activate", methods=["POST"])
@login_required
def admin_theme_activate(tid):
    if tid not in {t["id"] for t in list_themes()}:
        return jsonify({"ok": False, "error": "主题不存在"}), 404
    set_setting("active_theme", tid)
    return jsonify({"ok": True})


@app.route("/api/admin/themes/<tid>", methods=["DELETE"])
@login_required
def admin_theme_delete(tid):
    if tid == "default":
        return jsonify({"ok": False, "error": "内建 default 主题不能删除"}), 400
    if get_setting("active_theme", "default") == tid:
        return jsonify({"ok": False, "error": "正在使用的主题不能删除，请先切换"}), 400
    tdir = os.path.join(THEMES_DIR, tid)
    if not _valid_id(tid) or not os.path.isdir(tdir):
        return jsonify({"ok": False, "error": "主题不存在"}), 404
    _shutil.rmtree(tdir)
    return jsonify({"ok": True})


# ---------- 插件 ----------
class PluginCtx:
    """传给插件钩子的上下文：db()/setting()/log()/is_online()。"""

    def __init__(self, pid):
        self.plugin_id = pid

    def db(self):
        db = sqlite3.connect(DB_PATH, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    def setting(self, key, default=None):
        try:
            return get_setting(key, default)
        except Exception:
            db = self.db()
            try:
                return get_setting_db(db, key, default)
            finally:
                db.close()

    def log(self, msg):
        print(f"[plugin:{self.plugin_id}] {msg}", file=sys.stderr, flush=True)

    def is_online(self, last_seen):
        try:
            return (time.time() - float(last_seen or 0)) < OFFLINE_AFTER
        except Exception:
            return False


_PLUGINS = {}  # id -> {"id","meta","module","enabled"}


def _plugins_sorted():
    return [_PLUGINS[k] for k in sorted(_PLUGINS)]


def load_plugins():
    """扫描 plugins/ 并导入（启动时 + 管理页"重新加载"时调用）。"""
    import importlib.util
    _PLUGINS.clear()
    if not os.path.isdir(PLUGINS_DIR):
        return
    for pid in sorted(os.listdir(PLUGINS_DIR)):
        pdir = os.path.join(PLUGINS_DIR, pid)
        if not _valid_id(pid) or not os.path.isdir(pdir):
            continue
        meta = _read_json_file(os.path.join(pdir, "plugin.json"))
        pypath = os.path.join(pdir, "plugin.py")
        if not meta or not os.path.isfile(pypath):
            print(f"[plugin:{pid}] 缺少 plugin.json 或 plugin.py，已跳过", file=sys.stderr, flush=True)
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"myprobe_plugin_{pid}", pypath)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"[plugin:{pid}] 加载失败: {e}", file=sys.stderr, flush=True)
            continue
        try:
            enabled = get_setting(f"plugin_enabled_{pid}", "1") == "1"
        except Exception:
            enabled = True
        _PLUGINS[pid] = {"id": pid, "meta": meta, "module": mod, "enabled": enabled}
    print(f"[plugin] 已加载 {len(_PLUGINS)} 个插件", flush=True)


def _call_plugin_hook(p, hook, **kwargs):
    fn = p["module"].__dict__.get(hook)
    if not callable(fn):
        return None
    import inspect
    params = inspect.signature(fn).parameters
    kw = dict(kwargs)
    if "ctx" in params and "ctx" not in kw:
        kw["ctx"] = PluginCtx(p["id"])
    kw = {k: v for k, v in kw.items() if k in params}
    try:
        return fn(**kw)
    except Exception as e:
        print(f"[plugin:{p['id']}] hook {hook} 出错: {e}", file=sys.stderr, flush=True)
        return None


def fire_plugin_hook(hook, **kwargs):
    for p in _plugins_sorted():
        if p["enabled"]:
            _call_plugin_hook(p, hook, **kwargs)


def collect_plugin_ui():
    """收集插件的看板卡片 HTML 和管理页标签。"""
    cards, tabs = [], []
    for p in _plugins_sorted():
        if not p["enabled"]:
            continue
        h = _call_plugin_hook(p, "dashboard_cards")
        if h:
            cards.append(f"<!-- plugin:{p['id']} -->" + str(h))
        pages = _call_plugin_hook(p, "admin_pages") or []
        try:
            for slug, title, html in pages:
                slug = re.sub(r"[^A-Za-z0-9_-]", "", str(slug))[:32]
                if slug:
                    tabs.append({"slug": slug, "title": str(title)[:64], "html": str(html)})
        except Exception as e:
            print(f"[plugin:{p['id']}] admin_pages 格式错误: {e}", file=sys.stderr, flush=True)
    return "".join(cards), tabs


@app.route("/api/admin/plugins")
@login_required
def admin_plugins_list():
    return jsonify({"ok": True, "plugins": [
        {"id": p["id"],
         "name": str(p["meta"].get("name", p["id"])),
         "version": str(p["meta"].get("version", "")),
         "author": str(p["meta"].get("author", "")),
         "description": str(p["meta"].get("description", "")),
         "hooks": p["meta"].get("hooks", []),
         "enabled": p["enabled"]}
        for p in _plugins_sorted()]})


@app.route("/api/admin/plugins/upload", methods=["POST"])
@login_required
def admin_plugin_upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        return jsonify({"ok": False, "error": "请选择 zip 文件"}), 400
    stage, err = _stage_upload(f, ["plugin.json", "plugin.py"])
    if stage is None:
        return jsonify({"ok": False, "error": err}), 400
    try:
        meta = _read_json_file(os.path.join(stage, "plugin.json")) or {}
        pid = str(meta.get("id", "")).strip()
        if not _valid_id(pid):
            return jsonify({"ok": False, "error": "plugin.json 里的 id 不合法（限字母数字/_/-，64字符内）"}), 400
        dest = os.path.join(PLUGINS_DIR, pid)
        if os.path.exists(dest):
            return jsonify({"ok": False, "error": f"插件 {pid} 已存在，请先删除"}), 400
        _shutil.move(stage, dest)
        load_plugins()  # 上传后立即加载
        return jsonify({"ok": True, "id": pid})
    finally:
        _shutil.rmtree(stage, ignore_errors=True)


def _plugin_set_enabled(pid, on):
    if pid not in _PLUGINS:
        return jsonify({"ok": False, "error": "插件不存在"}), 404
    set_setting(f"plugin_enabled_{pid}", "1" if on else "0")
    _PLUGINS[pid]["enabled"] = bool(on)
    return jsonify({"ok": True})


@app.route("/api/admin/plugins/<pid>/enable", methods=["POST"])
@login_required
def admin_plugin_enable(pid):
    return _plugin_set_enabled(pid, True)


@app.route("/api/admin/plugins/<pid>/disable", methods=["POST"])
@login_required
def admin_plugin_disable(pid):
    return _plugin_set_enabled(pid, False)


@app.route("/api/admin/plugins/reload", methods=["POST"])
@login_required
def admin_plugin_reload():
    load_plugins()
    return jsonify({"ok": True, "count": len(_PLUGINS)})


@app.route("/api/admin/plugins/<pid>", methods=["DELETE"])
@login_required
def admin_plugin_delete(pid):
    pdir = os.path.join(PLUGINS_DIR, pid)
    if not _valid_id(pid) or not os.path.isdir(pdir):
        return jsonify({"ok": False, "error": "插件不存在"}), 404
    _shutil.rmtree(pdir)
    _PLUGINS.pop(pid, None)
    return jsonify({"ok": True})


# ---------------- main ----------------
if __name__ == "__main__":
    port = PORT
    for i, a in enumerate(sys.argv):
        if a == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
    # 启动时建库（含 v2/v3 迁移）
    with app.app_context():
        get_db()
        load_plugins()
    # v2 后台线程：拨测 + 告警（daemon，异常自保）
    # v5：拨测改由 agent 执行，服务端拨测线程已移除
    threading.Thread(target=alert_worker, daemon=True, name="alert").start()
    # v6.0：SSH 会话回收线程
    threading.Thread(target=_ssh_reaper, daemon=True, name="ssh-reaper").start()
    print(f"[MyProbe] 服务端启动: http://0.0.0.0:{port}  (DB: {DB_PATH})", flush=True)
    app.run(host="0.0.0.0", port=port, threaded=True)
