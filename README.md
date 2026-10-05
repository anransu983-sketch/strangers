# 🔭 MyProbe —— 自建服务器探针

轻量、零 CDN 依赖的服务器监控面板：**服务端**（Flask + SQLite，收数据、存历史、网页看板）＋
**Agent**（单文件 Python，装在被监控机器上，每 5 秒上报 CPU / 内存 / 磁盘 / 网络 / 负载）。

看板公开只读，深色卡片风；点节点进详情看历史曲线（1h / 6h / 24h / 7d / 30d）；
在线/离线按心跳自动判定（30 秒无上报判离线）；数据保留 30 天（1 小时内看原始 5 秒点，更长范围自动降采样）。

## ✨ 功能特性（v6.1）

- **📡 各节点独立拨测**：每台 agent 每 60 秒独立探测（ping / TCP / HTTP，每任务 3 次取平均），结果随上报带回；卡片上看各目标延迟、丢包和近 22 次小条形图，拨测页按节点分组
- **📊 流量统计**：按上报速率自动累计月流量（自然月分桶）；节点详情有近 30 天每日流量柱状图（canvas 手绘）；另有累计流量
- **📦 流量配额**：给节点设月配额（GB）+ 本月已用基准（对齐服务商面板），卡片显示进度条（超 80% 黄、超 100% 红）
- **⏰ 到期提醒**：填套餐价格、计费周期、购买/到期日期，卡片显示「余期 X 天」徽章（≤7 天红、≤30 天黄）和按剩余天数折算的「余值」
- **🚨 阈值告警**：CPU / 内存超阈值持续 N 分钟、节点离线超 N 分钟；通知渠道支持 Webhook / Telegram / 邮件 SMTP；同一事件只告警一次，恢复后发恢复通知
- **💻 内置 Web SSH 终端**：节点卡片「💻 终端」按钮，面板内直接开全屏终端（xterm.js 本地打包）；SSH 密码 Fernet 加密存库，也支持一次性密码不入库
- **↕️ 拖拽排序**：卡片表头 ⠿ 手柄纵向拖、芯片条横滑拖，顺序存服务端，多端同步
- **🎨 主题系统**：zip 包上传即用，缺模板自动回退内建默认主题；附带 4 套示例主题
- **🔌 插件系统**：`on_report` / `on_alert` / `dashboard_cards` / `admin_pages` 钩子，异常隔离
- **➕ 添加节点**：管理后台填 ID + 显示名，自动生成一键安装命令（含 Token）
- 前端零外部依赖：图表手写 canvas，xterm.js 本地打包，不加载任何 CDN

## 🚀 快速开始

### 服务端（以 Debian 为例）

```bash
# 1. 装依赖
sudo apt update && sudo apt install -y python3 python3-pip
pip install --break-system-packages -r requirements.txt

# 2. 放文件并配置
sudo mkdir -p /opt/myprobe/data
sudo cp server.py agent.py requirements.txt /opt/myprobe/
sudo cp .env.example /opt/myprobe/.env
sudo chmod 600 /opt/myprobe/.env
sudo nano /opt/myprobe/.env     # 把 MYPROBE_TOKEN / MYPROBE_ADMIN_PASS 改掉！

# 3. systemd 启动
sudo cp systemd/myprobe-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now myprobe-server
curl http://127.0.0.1:17234/health   # 应返回 {"ok":true,...}

# 4. nginx 反代 + HTTPS（示例）
# /etc/nginx/conf.d/myprobe.conf：
#
# server {
#     listen 80;
#     server_name probe.example.com;
#     location / {
#         proxy_pass http://127.0.0.1:17234;
#         proxy_set_header Host $host;
#         proxy_set_header X-Real-IP $remote_addr;
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#         proxy_set_header X-Forwarded-Proto $scheme;
#     }
# }
#
# sudo nginx -t && sudo systemctl reload nginx
# 如用 Cloudflare，建议 DNS 设为"仅 DNS"（灰云关掉），保证直连
# sudo certbot --nginx -d probe.example.com
```

打开 `https://probe.example.com` 即看板；右上角「管理员登录」后可管理节点、拨测、告警、主题、插件。

### 接入节点（每台被监控的机器）

```bash
pip install --break-system-packages psutil
# 下载 agent.py 到 /opt/myprobe/agent.py，然后二选一：

# 方式 A：命令行参数
python3 /opt/myprobe/agent.py \
  --server https://probe.example.com \
  --token 你的MYPROBE_TOKEN \
  --node-id node-01 --name "示例节点"

# 方式 B：systemd（推荐，开机自启）
sudo cp systemd/myprobe-agent.service /etc/systemd/system/
sudo nano /etc/systemd/system/myprobe-agent.service  # 改 MYPROBE_* 几个值
sudo systemctl daemon-reload && sudo systemctl enable --now myprobe-agent
```

更省事：管理后台「➕ 添加节点」填 ID + 显示名，直接复制生成好的一键安装命令。

Windows 节点：装 Python + `pip install psutil`，同样跑 `agent.py`（用任务计划程序开机启动，或 nssm 注册服务）。

### 升级

```bash
cd /opt/myprobe
cp data/myprobe.db "data/myprobe.db.bak.$(date +%Y%m%d%H%M%S)"  # 先备份
git pull   # 或覆盖 server.py / agent.py
sudo systemctl restart myprobe-server
```

数据库迁移全部幂等，老版本直接升 v6.1 不丢数据；升级不碰 `.env`、`themes/`、`plugins/`。

## 🛠 管理后台速览（⚙️管理，需管理员登录）

| 页签 | 能做的事 |
|---|---|
| 🖥 节点信息 | 套餐价格、货币、计费周期、购买/到期日期、月流量配额、本月已用基准、SSH 连接信息 |
| 📡 拨测任务 | 增删改 ping / tcp / http 探测任务 |
| 🚨 告警规则 | CPU% / 内存% 超阈值持续 N 分钟、节点离线；0 分钟 = 立即告警 |
| 🔔 通知渠道 | Webhook（POST JSON）、Telegram（bot token + chat id）、邮件（SMTP）；可点"测试"验证 |
| 📋 告警记录 | 最近 100 条触发 / 恢复记录 |
| 🎨 主题 | 上传 zip、启用、删除（使用中和内建的不能删） |
| 🔌 插件 | 上传 zip、启用/停用、删除、🔄重新加载（不重启服务） |

## 🎨 主题系统

- 主题放在 `themes/<id>/`：`theme.json`（id/名称/版本/作者/说明）＋ `templates/dashboard.html`（覆盖默认看板；缺文件自动回退内建默认模板）＋ `static/`（经 `/theme-static/<id>/...` 访问）。
- 内建 `default` 主题永远可用、不可删除；当前主题名存在 `settings` 表（`active_theme`）。
- 附带示例主题（`themes/` 下已解压好，管理后台直接启用）：
  - `bocchi-starlight` —— 波奇酱粉色 × 星空布局（背景图来自 [jujiunofly/komari-theme-Bocchi](https://github.com/jujiunofly/komari-theme-Bocchi)，MIT）
  - `bocchi` —— 粉色波奇风（背景图同上，MIT）
  - `starlight` —— 深空星野风
  - `minimal` —— 极简（纯 CSS，复用默认模板）
- zip 含路径穿越会被直接拒绝；模板渲染失败自动回退默认模板（看板不会 500）。

### 主题开发指南

1. 建目录 `mytheme/`，写 `theme.json`：
   ```json
   {"id": "mytheme", "name": "我的主题", "version": "1.0",
    "author": "我", "description": "说明文字"}
   ```
   `id` 限字母数字/`_`/`-`，64 字符内。
2. `templates/dashboard.html`：完整的看板 HTML（Jinja2 模板）。可以从默认模板改：把服务端 `DASHBOARD_HTML` 另存一份改 CSS 即可。看板数据都走 `/api/*` 接口，JS 一般不用动。
3. `static/` 下放 CSS/图片等，模板里用 `{{ theme_static }}` 引用：
   ```html
   <link rel="stylesheet" href="{{ theme_static }}/style.css">
   ```
4. 打包：`cd mytheme && zip -r ../mytheme.zip .`（zip 根下须有 theme.json，允许套一层文件夹），去管理后台 🎨主题 上传。
5. 模板可用变量：

   | 变量 | 说明 |
   |---|---|
   | `plugin_cards` | 插件注入的看板卡片 HTML（`{{ plugin_cards\|safe }}`，建议放看板顶部） |
   | `plugin_admin_tabs_json` | 插件管理页标签 JSON |
   | `theme.id` | 当前主题 id |
   | `theme_static` | 主题静态文件 URL 前缀（`/theme-static/<id>`） |
   | `version` | 服务端版本 |

## 🔌 插件系统

- 插件放在 `plugins/<id>/`：`plugin.json`（id/名称/版本/作者/说明/hooks 列表）＋ `plugin.py`。**插件以服务端代码运行**（和 server.py 同等权限），只装信任来源的。
- 支持的钩子（每个调用都有异常隔离，单个插件出错不会拖垮服务）：
  - `on_report(node_id, report)` —— 每次 agent 上报入库后调用
  - `on_alert(alert)` —— 告警触发时调用（alert 含 rule/node_id/message/time 等）
  - `dashboard_cards()` —— 返回 HTML 字符串，注入到看板顶部
  - `admin_pages()` —— 返回 `[(slug, title, html), ...]`，在 ⚙️管理 里渲染为额外页签
  - 钩子函数可声明 `ctx` 参数获得上下文：`ctx.db()`（新数据库连接，记得 close）、`ctx.setting(key, default)`、`ctx.log(msg)`（记到服务端 stderr）、`ctx.is_online(ts)`

### 插件开发最小示例

`plugin.json`：
```json
{"id": "myplugin", "name": "我的插件", "version": "1.0",
 "author": "我", "description": "说明文字",
 "hooks": ["dashboard_cards", "on_alert"]}
```

`plugin.py`：
```python
def dashboard_cards(ctx):
    return '<div class="card"><div class="top"><span class="name">👋 我的卡片</span></div></div>'

def on_report(ctx, node_id, report):
    ctx.log(f"{node_id} 上报了，cpu={report['metrics'].get('cpu')}")

def on_alert(ctx, alert):
    ctx.log(f"告警：{alert['message'][:50]}")

def admin_pages(ctx):
    return [("mystats", "我的统计", "<div class='frm'><h3>hello</h3></div>")]
```

钩子参数按需声明（`ctx` / `node_id` / `report` / `alert`），多余的不用写。
打包：`cd myplugin && zip -r ../myplugin.zip plugin.json plugin.py`，去管理后台 🔌插件 上传（自动加载并启用）。

## 📡 API 一览（看板 JS 直接 fetch，公开接口无需登录）

- `GET /api/nodes` —— 节点列表＋实时指标（cpu/mem/disk/rx/tx/online/余期/配额/拨测…）
- `GET /api/history/<node_id>?range=1h|6h|24h|7d|30d` —— 历史曲线
- `GET /api/probes` —— 拨测任务＋最近结果
- `GET /api/traffic/daily?node_id=<id>&days=30` —— 每日流量（老→新，缺失补 0）
- `GET /api/me` —— `{admin: true/false}`
- `GET /dl/agent.py` / `GET /dl/agent-install.sh` —— agent 源码 / 一键安装脚本（免登录）

## 📋 文件结构

```
myprobe/
├── server.py                 # 服务端（Flask + SQLite，单文件，含主题/插件/终端）
├── agent.py                  # Agent（单文件，只依赖 psutil，Linux/Windows 通用）
├── requirements.txt
├── .env.example              # 服务端配置模板（复制为 .env 后修改，.env 不进仓库）
├── systemd/
│   ├── myprobe-server.service
│   └── myprobe-agent.service
├── samples/
│   └── install-myprobe-agent.sh  # 一键安装脚本（服务端 /dl/agent-install.sh 即此文件）
├── themes/                   # 示例主题（bocchi-starlight / bocchi / starlight / minimal）
├── plugins/                  # 插件目录（空，运行时存放上传的插件）
├── LICENSE
└── README.md
```

服务端运行时还会在 `data/` 下建 `myprobe.db`（SQLite，git 不跟踪）。

## 🕘 版本历史

- **v6.1**：↕️ 拖拽排序节点（卡片手柄纵向拖＋芯片条横滑拖，`sort_order` 存服务端）
- **v6.0**：💻 内置 Web SSH 终端（paramiko；SSH 密码 Fernet 加密存库，一次性密码模式）
- **v5.0**：📡 各节点独立拨测（agent 每 60s 自测，tcp/http/ping，结果随上报带回）
- **v4.2**：➕ 添加节点（管理后台生成一键安装命令，Token 自动填入）
- **v4.1**：📊 本月已用基准（`quota_base_gb`，对齐服务商面板，跨月自动失效）
- **v4**：📊 每日流量（近 30 天柱状图）＋ 累计流量
- **v3**：🎨 主题系统 ＋ 🔌 插件系统
- **v2**：📡 服务端拨测（后被 v5 的独立拨测取代）＋ 📊 流量配额 ＋ ⏰ 到期提醒 ＋ 🚨 阈值告警
- **v1**：基础监控（5s 上报、30s 判离线、历史曲线、零 CDN 看板）

## ✅ 本地测试记录

每个版本发布前都在本机用临时端口做端到端实测（建库→上报→接口断言→删库），例如：

- v6.1：3 节点排序接口（正常/非法 id→400/未登录→401）、老库迁移回填、重启后顺序保留、新节点自动排末尾；卡片/芯片拖拽逻辑的 DOM-stub 单测；两主题 inline JS `node --check` 通过
- v6.0：SSH 连接/认证失败中文报错、会话回收、密码字段永不外泄；`pip install` 无新依赖问题
- v5.0：31 项断言（任务下发、agent 自测 3 次平均、历史保留、看板分组渲染）
- v2–v4：拨测延迟真实性、配额累计、到期折算、告警触发/恢复、主题上传（路径穿越拒绝、坏模板回退）、插件钩子隔离、老库幂等迁移

## 🗺 后续计划（按需）

- 拨测失败告警、超配额自动告警规则
- 多用户只读分享链接

## 📄 开源协议

MIT License，见 [LICENSE](LICENSE)。

第三方素材：主题 `bocchi-starlight` / `bocchi` 中的波奇酱背景图来自
[jujiunofly/komari-theme-Bocchi](https://github.com/jujiunofly/komari-theme-Bocchi)
（MIT License, Copyright (c) 2025 Tony Liu），已保留署名；终端前端 xterm.js 为其各自开源协议。
