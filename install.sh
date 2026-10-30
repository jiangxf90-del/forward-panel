#!/bin/bash
# 转发规则面板 · 安装脚本（在中转 VPS 上以 root 运行）
# 作用：检查 python3，把面板装到 /opt/forward-panel，注册 systemd 服务并启动。
# 面板默认端口 2080；换端口：PANEL_PORT=3080 bash install.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行，例如：sudo bash install.sh" >&2
  exit 1
fi

command -v python3 >/dev/null 2>&1 || {
  echo "未找到 python3，请先安装 Python 3.8 或更高版本。" >&2
  exit 1
}
python3 -c 'import sys; assert sys.version_info >= (3, 8)' 2>/dev/null || {
  echo "Python 版本过低，需要 3.8 或更高版本。" >&2
  exit 1
}

PANEL_PORT="${PANEL_PORT:-2080}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/forward-panel"
DATA_DIR="$INSTALL_DIR/data"

mkdir -p "$INSTALL_DIR/static" "$DATA_DIR"
cp "$SRC_DIR/panel.py" "$INSTALL_DIR/panel.py"
cp "$SRC_DIR/static/index.html" "$INSTALL_DIR/static/index.html"
chmod 644 "$INSTALL_DIR/panel.py" "$INSTALL_DIR/static/index.html"

# 管理员密码：静默读取（屏幕不回显），只存加盐哈希，绝不落盘明文。
if [ -f "$DATA_DIR/admin.json" ]; then
  read -r -p "管理员密码已存在，是否重置？[y/N] " RESET
  if [ "$RESET" != "y" ] && [ "$RESET" != "Y" ]; then
    SKIP_SET=1
  fi
fi
if [ -z "${SKIP_SET:-}" ]; then
  while true; do
    read -r -s -p "设置管理员密码： " PASS1; echo
    read -r -s -p "再次输入管理员密码： " PASS2; echo
    if [ -n "$PASS1" ] && [ "$PASS1" = "$PASS2" ]; then
      break
    fi
    echo "两次输入不一致或为空，请重试。"
  done
  # 密码经 stdin 传给 panel.py，只生成哈希文件，不进命令行、不写日志。
  printf '%s' "$PASS1" | PANEL_DATA_DIR="$DATA_DIR" python3 "$INSTALL_DIR/panel.py" --set-admin
  unset PASS1 PASS2
fi

cat > /etc/systemd/system/forward-panel.service <<EOF
[Unit]
Description=Forwarding rules panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=PANEL_PORT=$PANEL_PORT
Environment=PANEL_DATA_DIR=$DATA_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/panel.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable forward-panel
systemctl restart forward-panel
sleep 1

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "----------------------------------------"
echo "安装完成，面板地址：http://${SERVER_IP:-你的VPS_IP}:$PANEL_PORT"
echo "用刚才设置的管理员密码登录。"
echo "查看运行日志：journalctl -u forward-panel -f"
echo "----------------------------------------"
