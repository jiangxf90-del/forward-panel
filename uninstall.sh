#!/bin/bash
# 转发规则面板 · 卸载脚本（在中转 VPS 上以 root 运行）
# 作用：停掉服务、删除 systemd 单元和安装目录。
# 卸载前先把规则备份到 /tmp，文件名带时间戳。
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行，例如：sudo bash uninstall.sh" >&2
  exit 1
fi

INSTALL_DIR="/opt/forward-panel"
DATA_DIR="$INSTALL_DIR/data"
TS="$(date +%Y%m%d-%H%M%S)"

if [ -f "$DATA_DIR/rules.json" ]; then
  cp "$DATA_DIR/rules.json" "/tmp/forward-panel-rules-backup-$TS.json"
  echo "规则已备份到：/tmp/forward-panel-rules-backup-$TS.json"
else
  echo "没有找到规则文件，跳过备份。"
fi

systemctl stop forward-panel 2>/dev/null || true
systemctl disable forward-panel 2>/dev/null || true
rm -f /etc/systemd/system/forward-panel.service
systemctl daemon-reload 2>/dev/null || true
rm -rf "$INSTALL_DIR"

echo "已卸载。"
