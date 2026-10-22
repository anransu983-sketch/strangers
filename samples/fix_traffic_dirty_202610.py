#!/usr/bin/env python3
"""MyProbe v6.4 脏数据订正（2026-10-21/22 v6.3 记账虚报）。

原理：metrics 表保留 30 天原始速率样本。用速率梯形积分重估候选日期的
真实用量；只有当已记值 > 估算×2 且差额 > 5GB（明确污染）时才替换
traffic_daily，并按差额同步修正 traffic_monthly（其余天/月不动）。
覆盖率（可积分时长/当天已过时长）不足 50% 时不动，避免拿残缺估算覆盖。

用法：python3 fix_traffic_dirty_202610.py [DB路径]
默认 DB：/opt/myprobe/data/myprobe.db
"""
import sqlite3
import sys
import time
from datetime import datetime, timedelta

DB_PATH = sys.argv[1] if len(sys.argv) > 1 else "/opt/myprobe/data/myprobe.db"
GB = 1024 ** 3
CANDIDATES = {
    "de-vps": ["2026-10-21", "2026-10-22"],
    "us-4837": ["2026-10-21", "2026-10-22"],
}
today = datetime.now().strftime("%Y-%m-%d")
for days in CANDIDATES.values():
    if today not in days:
        days.append(today)  # 部署当天也顺手核一遍（防拖到次日执行时漏掉）


def estimate(db, node_id, day):
    """梯形积分估算该日 rx/tx 字节与覆盖秒数。dt 上限 120s，超出视为断档。"""
    start = datetime.strptime(day, "%Y-%m-%d")
    end = start + timedelta(days=1)
    t0, t1 = int(start.timestamp()), int(end.timestamp())
    now = int(time.time())
    t1_eff = min(t1, now)
    if t1_eff <= t0:
        return 0, 0, 0, 0
    rows = db.execute(
        "SELECT ts, rx, tx FROM metrics WHERE node_id=? AND ts>=? AND ts<=? "
        "ORDER BY ts", (node_id, t0 - 180, t1_eff)).fetchall()
    erx = etx = 0.0
    covered = 0
    prev = None
    for ts, rx, tx in rows:
        rx = rx or 0
        tx = tx or 0
        if prev is not None:
            dt = ts - prev[0]
            if 0 < dt <= 120 and ts > t0:
                span = min(ts, t1_eff) - max(prev[0], t0)
                if span > 0:
                    f = span / dt
                    erx += (prev[1] + rx) / 2 * dt * f
                    etx += (prev[2] + tx) / 2 * dt * f
                    covered += span
        prev = (ts, rx, tx)
    return int(erx), int(etx), covered, t1_eff - t0


def main():
    db = sqlite3.connect(DB_PATH, timeout=30)
    changed = 0
    for node_id, days in CANDIDATES.items():
        for day in days:
            row = db.execute(
                "SELECT rx_bytes, tx_bytes FROM traffic_daily "
                "WHERE node_id=? AND day=?", (node_id, day)).fetchone()
            if not row:
                print(f"[skip] {node_id} {day}：无日桶记录")
                continue
            old_rx, old_tx = row[0] or 0, row[1] or 0
            old_total = old_rx + old_tx
            erx, etx, covered, elapsed = estimate(db, node_id, day)
            est_total = erx + etx
            cov = covered / elapsed if elapsed else 0
            print(f"[check] {node_id} {day}：已记 {(old_total/GB):.2f}GB，"
                  f"估算 {(est_total/GB):.2f}GB，覆盖率 {cov:.0%}")
            if cov < 0.5:
                print(f"[skip] {node_id} {day}：覆盖率不足，不动")
                continue
            if old_total > est_total * 2 and old_total - est_total > 5 * GB:
                db.execute(
                    "UPDATE traffic_daily SET rx_bytes=?, tx_bytes=? "
                    "WHERE node_id=? AND day=?", (erx, etx, node_id, day))
                month = day[:7]
                mrow = db.execute(
                    "SELECT rx_bytes, tx_bytes FROM traffic_monthly "
                    "WHERE node_id=? AND month=?", (node_id, month)).fetchone()
                if mrow:
                    nrx = max(0, (mrow[0] or 0) + erx - old_rx)
                    ntx = max(0, (mrow[1] or 0) + etx - old_tx)
                    db.execute(
                        "UPDATE traffic_monthly SET rx_bytes=?, tx_bytes=? "
                        "WHERE node_id=? AND month=?", (nrx, ntx, node_id, month))
                changed += 1
                print(f"[fixed] {node_id} {day}：{(old_total/GB):.2f}GB -> "
                      f"{(est_total/GB):.2f}GB（月桶已同步差额修正）")
            else:
                print(f"[keep] {node_id} {day}：未达污染阈值，不动")
    db.commit()
    db.close()
    print(f"订正完成：共修正 {changed} 条日桶。")


if __name__ == "__main__":
    main()
