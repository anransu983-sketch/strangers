#!/bin/bash
# ============================================================
# MyProbe Agent 一键安装（跑在「被监控」的机器上，root 执行）
# 用法：
#   curl -fsSL <本脚本下载链接> | sudo bash -s -- <看板地址> <Token> <节点ID> <显示名>
# 例子：
#   curl -fsSL <本脚本下载链接> | sudo bash -s -- https://probe.example.com abcdef123456 uk-vps "英国9929"
# 说明：看板地址/Token/密码 装服务端时脚本末尾会打印出来
# ============================================================
set -e

SERVER="$1"; TOKEN="$2"; NODE_ID="$3"; NAME="$4"
FILES_URL="https://muse.ai/files/1288897337648554/1437518415188904/3ufui7brf66bbup8sklksyf5/myprobe-v1.tar.gz"

if [ "$(id -u)" != "0" ]; then echo "请用 root 运行（前面加 sudo）"; exit 1; fi
if [ -z "$SERVER" ] || [ -z "$TOKEN" ] || [ -z "$NODE_ID" ] || [ -z "$NAME" ]; then
  echo "用法: curl -fsSL <脚本链接> | sudo bash -s -- <看板地址> <Token> <节点ID> <显示名>"
  echo '例子: curl -fsSL <脚本链接> | sudo bash -s -- https://probe.example.com 你的Token uk-vps "英国9929"'
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
curl -fsSL "$FILES_URL" -o /tmp/myprobe-v1.tar.gz
tar xzf /tmp/myprobe-v1.tar.gz -C /tmp agent.py
cp /tmp/agent.py /opt/myprobe/agent.py

echo "== 注册开机自启 =="
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
systemctl enable --now myprobe-agent >/dev/null 2>&1
sleep 4
if systemctl is-active --quiet myprobe-agent; then
  echo "🎉 Agent 已启动：$NAME（$NODE_ID），正在向 $SERVER 上报"
  echo "去看板 https:// 你的域名 看看节点亮了没（约 10 秒内上线）"
else
  echo "[ERROR] Agent 没起来，看日志：journalctl -u myprobe-agent -n 50"; exit 1
fi
