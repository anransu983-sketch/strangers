#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MyProbe Agent —— 单文件探针客户端
- 采集 CPU/内存/Swap/磁盘/网络速率/负载/运行时长，每 N 秒 POST 到服务端
- 只依赖 psutil；上报用标准库 urllib（零其他依赖）
- Linux / Windows 通用；断线自动重连退避

用法示例:
  python3 agent.py --server https://probe.example.com --token 你的密钥 --node-id uk-vps --name "英国9929"
  # 或用环境变量: MYPROBE_SERVER / MYPROBE_TOKEN / MYPROBE_NODE_ID / MYPROBE_NAME / MYPROBE_INTERVAL
"""
import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

try:
    import psutil
except ImportError:
    print("[FATAL] 需要安装 psutil: pip install psutil", file=sys.stderr)
    sys.exit(1)

# Windows 下磁盘根目录取法不同
DISK_ROOT = os.path.abspath(os.sep)


# ================= 流量采集（v6.3：累计计数器） =================
# 背景：旧版只上报全网卡的平均速率，服务端用 速率×间隔 反推总量，
# 上报失败/间隔过大整段丢失，累计流量必然少于商家面板。
# 新版按 Claude 复核方案改报「外网网卡累计计数器」，服务端做差分：
# - 只选默认路由网卡（无默认路由时退回疑似物理网卡），排除
#   lo/docker/桥/veth/tun/wg 等虚拟口，避免同一字节被重复计数；
# - 环境变量 PROBE_IFACES="eth0,eth1" 可强制指定（多网卡/策略路由时）；
# - 同时保留旧 rx/tx 速率字段（改按外网网卡差分算），老服务端仍可读。
_NET_EXCLUDE = re.compile(
    r'^(lo|docker\d*|br-.+|veth.+|virbr.+|vnet.+|tun\d*|tap.+|wg.+|'
    r'tailscale.+|zt.+|cni.+|flannel.+|cali.+|kube.+|dummy.+|ifb.+)$')
_net_prev = None  # (monotonic_ts, {iface: (rx_bytes, tx_bytes)})


def _default_route_ifaces():
    """从 /proc/net/route{,6} 读默认路由所在网卡名集合（非 Linux 返回空）。"""
    names = set()
    try:
        with open('/proc/net/route') as fh:
            next(fh, None)
            for line in fh:
                p = line.split()
                if len(p) >= 8 and p[1] == '00000000' and p[7] == '00000000' \
                        and int(p[3], 16) & 1:
                    names.add(p[0])
    except OSError:
        pass
    try:
        with open('/proc/net/ipv6_route') as fh:
            for line in fh:
                p = line.split()
                if len(p) >= 10 and p[0] == '0' * 32 and p[1] == '00':
                    fl = int(p[8], 16)
                    if fl & 1 and not fl & 0x200:  # UP 且非 REJECT
                        names.add(p[9])
    except OSError:
        pass
    return names


def _select_ifaces(pernic):
    forced = os.environ.get('PROBE_IFACES')  # 例 "eth0,eth1"，奇葩多网卡时用
    if forced:
        return [n.strip() for n in forced.split(',') if n.strip() in pernic]
    names = {n for n in _default_route_ifaces() if n in pernic and n != 'lo'}
    if not names:  # 无默认路由：退回看起来像物理网卡的
        names = {n for n in pernic if not _NET_EXCLUDE.match(n)
                 and not os.path.exists(f'/sys/class/net/{n}/master')}  # 跳过 bond/桥从口
    return sorted(names)


def _boot_id():
    try:
        with open('/proc/sys/kernel/random/boot_id') as fh:
            return fh.read().strip()
    except OSError:
        return None


def collect_net():
    """采集外网网卡流量。返回 dict：
    rx/tx        外网口速率 bytes/s（无基准时 0，兼容旧字段）；
    rx_total/tx_total  累计字节（服务端差分记账的依据）；
    ifaces       {网卡: {rx, tx}} 各自累计值；
    boot_id      本次开机标识（判计数器重置用，非 Linux 为 None）；
    counter_bits 计数器位宽（32 位回绕判断用）。
    """
    global _net_prev
    now = time.monotonic()
    try:
        pernic = psutil.net_io_counters(pernic=True, nowrap=True)
    except TypeError:  # 个别 psutil 版本不支持 nowrap
        pernic = psutil.net_io_counters(pernic=True)
    cur = {n: (pernic[n].bytes_recv, pernic[n].bytes_sent)
           for n in _select_ifaces(pernic)}
    rx_rate = tx_rate = 0
    if _net_prev:
        pt, pc = _net_prev
        dt = max(now - pt, 1e-3)
        rx_rate = round(sum(max(0, c[0] - pc[n][0])
                            for n, c in cur.items() if n in pc) / dt)
        tx_rate = round(sum(max(0, c[1] - pc[n][1])
                            for n, c in cur.items() if n in pc) / dt)
    _net_prev = (now, cur)
    return {
        'rx': rx_rate, 'tx': tx_rate,  # 旧字段仍发，值改为外网口速率
        'rx_total': sum(c[0] for c in cur.values()),
        'tx_total': sum(c[1] for c in cur.values()),
        'ifaces': {n: {'rx': c[0], 'tx': c[1]} for n, c in cur.items()},
        'boot_id': _boot_id(),
        'counter_bits': 64 if sys.maxsize > 2 ** 32 else 32,
    }


def reset_net_baseline():
    """清掉 collect_net 的速率基准（上报失败重连后调用）。

    累计值 rx_total/ifaces 仍随下一包发出，服务端靠差分能把断线期间
    的流量补回来；清基准只是避免本地速率按超长间隔算出失真值。
    """
    global _net_prev
    _net_prev = None


def parse_args():
    p = argparse.ArgumentParser(description="MyProbe Agent")
    p.add_argument("--server", default=os.environ.get("MYPROBE_SERVER", ""),
                   help="服务端地址，如 https://probe.example.com（末尾不要加斜杠）")
    p.add_argument("--token", default=os.environ.get("MYPROBE_TOKEN", ""),
                   help="上报密钥（需与服务端 MYPROBE_TOKEN 一致）")
    p.add_argument("--node-id", default=os.environ.get("MYPROBE_NODE_ID", ""),
                   help="节点唯一 ID（字母数字/_/-，如 uk-vps；留空则用主机名）")
    p.add_argument("--name", default=os.environ.get("MYPROBE_NAME", ""),
                   help="节点显示名称（留空则用主机名）")
    p.add_argument("--interval", type=int,
                   default=int(os.environ.get("MYPROBE_INTERVAL", "5")),
                   help="上报间隔秒数（默认 5）")
    p.add_argument("--insecure", action="store_true",
                   help="跳过 HTTPS 证书校验（仅自签证书调试用）")
    a = p.parse_args()
    if not a.server:
        p.error("必须指定 --server 或环境变量 MYPROBE_SERVER")
    if not a.token:
        p.error("必须指定 --token 或环境变量 MYPROBE_TOKEN")
    a.server = a.server.rstrip("/")
    host = socket.gethostname()
    if not a.node_id:
        # 主机名做一次清洗，保证符合服务端 node_id 规则
        a.node_id = "".join(c if (c.isalnum() or c in "-_") else "-" for c in host)[:64] or "node"
    if not a.name:
        a.name = host
    return a


def static_info():
    """只采集一次的静态信息。"""
    try:
        cpu_model = platform.processor() or ""
        if not cpu_model and os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name"):
                        cpu_model = line.split(":", 1)[1].strip()
                        break
    except Exception:
        cpu_model = ""
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}".strip(),
        "platform": platform.system(),
        "arch": platform.machine(),
        "cpu_model": cpu_model[:128],
        "cpu_cores": psutil.cpu_count(logical=True),
        "mem_total": psutil.virtual_memory().total,
        "disk_total": psutil.disk_usage(DISK_ROOT).total,
    }


def collect(prev_net, elapsed):
    """采集一次动态指标。返回 (metrics, new_net_counters)。

    prev_net/elapsed 仍是全网卡计数器（仅作 collect_net 异常时的回退），
    正常路径下 rx/tx 与累计字段由 collect_net() 按外网网卡给出。
    """
    net = psutil.net_io_counters()
    rx = tx = 0
    if prev_net is not None and elapsed > 0:
        rx = max(0, int((net.bytes_recv - prev_net.bytes_recv) / elapsed))
        tx = max(0, int((net.bytes_sent - prev_net.bytes_sent) / elapsed))

    load1 = None
    if hasattr(os, "getloadavg"):
        try:
            load1 = os.getloadavg()[0]
        except Exception:
            pass

    metrics = {
        "cpu": psutil.cpu_percent(interval=None),
        "mem": psutil.virtual_memory().percent,
        "swap": psutil.swap_memory().percent,
        "disk": psutil.disk_usage(DISK_ROOT).percent,
        "rx": rx,
        "tx": tx,
        "load1": load1,
        "uptime": int(time.time() - psutil.boot_time()),
    }
    try:
        metrics.update(collect_net())
    except Exception as e:
        print(f"[Agent] collect_net 失败，回退全网卡速率: {e}", flush=True)
    return metrics, net


def post_report(args, payload):
    req = urllib.request.Request(
        args.server + "/api/report",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Token": args.token},
        method="POST",
    )
    ctx = None
    if args.insecure:
        import ssl
        ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        if not body.get("ok"):
            raise RuntimeError("服务端返回失败: " + str(body))
        return body


# ================= v5：本机独立拨测 =================
# 服务端在 /api/report 响应里下发 probes 任务列表；老服务端没有该字段则跳过。
PROBE_INTERVAL = 60
_probe_tasks = []    # [{"id","name","type","host","port","path"}, ...]
_probe_cache = {}    # task_id(str) -> {"lat": ms|None, "loss": %}
_probe_lock = threading.Lock()


def _ping_parse(out):
    """解析 ping 输出，返回 (avg_ms|None, loss_%)。"""
    loss_m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    if loss_m:
        loss = float(loss_m.group(1))
    else:
        m2 = re.search(r"(\d+)% loss", out)          # Windows: (0% loss)
        loss = float(m2.group(1)) if m2 else 100.0
    avg = None
    for pat in (r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/",      # Linux
                r"round-trip min/avg/max/stddev = [\d.]+/([\d.]+)/",  # macOS
                r"Average = ([\d.]+)ms"):                            # Windows
        m = re.search(pat, out)
        if m:
            avg = float(m.group(1))
            break
    ok = loss < 100
    return (avg if ok else None, loss)


def run_probe_task(t):
    """执行单个拨测任务 3 次。返回 (avg_latency_ms 或 None, loss_%)。绝不抛异常。"""
    n = 3
    try:
        ttype = (t.get("type") or "").strip()
        host = (t.get("host") or "").strip()
        if not host or ttype not in ("ping", "tcp", "http"):
            return (None, 100.0)
        if ttype == "ping":
            if os.name == "nt":
                cmd = ["ping", "-n", str(n), "-w", "2000", host]
            else:
                cmd = ["ping", "-c", str(n), "-W", "2", host]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return _ping_parse(p.stdout or "")
        elif ttype == "tcp":
            port = int(t.get("port") or 80)
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
        elif ttype == "http":
            url = host if host.startswith("http") else "http://" + host
            if t.get("path"):
                url = url.rstrip("/") + t["path"]
            lat, fails = [], 0
            for _ in range(n):
                t0 = time.time()
                try:
                    with urllib.request.urlopen(url, timeout=6) as r:
                        r.read(1024)  # 读到响应头即可
                    lat.append((time.time() - t0) * 1000)
                except Exception:
                    fails += 1
            return (sum(lat) / len(lat) if lat else None, fails / n * 100.0)
    except Exception as e:
        print(f"[Agent] 拨测任务 {t.get('name')} 执行异常: {e}", flush=True)
    return (None, 100.0)


def probe_loop():
    """后台线程：每 60 秒跑一遍服务端下发的拨测任务，结果写入缓存。"""
    while True:
        try:
            with _probe_lock:
                tasks = [t for t in _probe_tasks
                         if isinstance(t, dict) and t.get("id") is not None]
            if tasks:
                res = {}
                for t in tasks:
                    try:
                        lat, loss = run_probe_task(t)
                        res[str(t["id"])] = {"lat": lat, "loss": loss}
                    except Exception as e:
                        print(f"[Agent] 拨测任务 {t.get('name')} 失败: {e}", flush=True)
                with _probe_lock:
                    _probe_cache.clear()
                    _probe_cache.update(res)
        except Exception as e:
            print(f"[Agent] 拨测线程异常: {e}", flush=True)
        time.sleep(PROBE_INTERVAL)


def probe_snapshot():
    with _probe_lock:
        return dict(_probe_cache)


def update_probe_tasks(body):
    """从上报响应更新任务列表（老服务端无 probes 字段则保持原样）。"""
    ps = body.get("probes")
    if isinstance(ps, list):
        with _probe_lock:
            _probe_tasks.clear()
            _probe_tasks.extend(ps)


def main():
    args = parse_args()
    host = static_info()
    print(f"[MyProbe Agent] 节点 {args.node_id} ({args.name}) -> {args.server}，"
          f"每 {args.interval}s 上报", flush=True)

    psutil.cpu_percent(interval=None)  # 初始化 CPU 计数器（第一次调用返回 0 无意义）
    prev_net = psutil.net_io_counters()
    fail_count = 0
    # v5：拨测线程（daemon），每 60 秒独立探测，结果随上报带回
    threading.Thread(target=probe_loop, daemon=True, name="probe").start()

    while True:
        start = time.time()
        metrics, prev_net = collect(prev_net, args.interval)
        payload = {"node_id": args.node_id, "name": args.name,
                   "host": host, "metrics": metrics,
                   "probes": probe_snapshot()}
        try:
            body = post_report(args, payload)
            update_probe_tasks(body)  # 老服务端无 probes 字段则跳过
            if fail_count:
                print(f"[Agent] 上报恢复（之前连续失败 {fail_count} 次）", flush=True)
            fail_count = 0
        except Exception as e:
            fail_count += 1
            wait = min(5 * fail_count, 60)
            print(f"[Agent] 上报失败({fail_count}次): {e}，{wait}s 后重试", flush=True)
            time.sleep(wait)
            prev_net = psutil.net_io_counters()  # 重置流量基准，避免重连后速率突增
            reset_net_baseline()  # 同步清 collect_net 基准（累计值不受影响，服务端差分补账）
            continue
        # 扣掉采集耗时，保持固定节拍
        spent = time.time() - start
        time.sleep(max(0.5, args.interval - spent))


if __name__ == "__main__":
    main()
