#!/bin/bash

# =========================
# sing-box 安装脚本 - VLESS-Reality
# 适用于 Debian/Ubuntu/CentOS/Alpine 等主流 Linux 发行版
# 最后更新: 2026.02
# =========================

export LANG=en_US.UTF-8
# 定义颜色
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
skyblue="\e[1;36m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 定义常量
server_name="sing-box"
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
client_dir="${work_dir}/url.txt"
export vless_port=${PORT:-$(shuf -i 1000-65000 -n 1)}
# 当前脚本绝对路径（用于快捷指令；curl 管道运行时为空）
SCRIPT_PATH=""
_script_src="${BASH_SOURCE[0]:-$0}"
if [ -n "$_script_src" ]; then
  case "$_script_src" in
    /*) SCRIPT_PATH="$_script_src" ;;
    *) SCRIPT_PATH="$(cd "$(dirname "$_script_src")" 2>/dev/null && pwd)/$(basename "$_script_src")" ;;
  esac
  [ -n "$SCRIPT_PATH" ] && [ ! -f "$SCRIPT_PATH" ] && SCRIPT_PATH=""
fi 

# 检查是否为root下运行
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# 检查命令是否存在函数
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查服务状态通用函数
check_service() {
    local service_name=$1
    local service_file=$2
    
    [[ ! -f "${service_file}" ]] && { red "not installed"; return 2; }
        
    if command_exists apk; then
        rc-service "${service_name}" status | grep -q "started" && green "running" || yellow "not running"
    else
        systemctl is-active "${service_name}" | grep -q "^active$" && green "running" || yellow "not running"
    fi
    return $?
}

# 检查sing-box状态
check_singbox() {
    check_service "sing-box" "${work_dir}/${server_name}"
}

# 根据系统类型安装、卸载依赖
manage_packages() {
    if [ $# -lt 2 ]; then
        red "Unspecified package name or action" 
        return 1
    fi

    action=$1
    shift

    for package in "$@"; do
        if [ "$action" == "install" ]; then
            if command_exists "$package"; then
                green "${package} already installed"
                continue
            fi
            yellow "正在安装 ${package}..."
            if command_exists apt; then
                DEBIAN_FRONTEND=noninteractive apt install -y "$package"
            elif command_exists dnf; then
                dnf install -y "$package"
            elif command_exists yum; then
                yum install -y "$package"
            elif command_exists apk; then
                apk update
                apk add "$package"
            else
                red "Unknown system!"
                return 1
            fi
        elif [ "$action" == "uninstall" ]; then
            if ! command_exists "$package"; then
                yellow "${package} is not installed"
                continue
            fi
            yellow "正在卸载 ${package}..."
            if command_exists apt; then
                apt remove -y "$package" && apt autoremove -y
            elif command_exists dnf; then
                dnf remove -y "$package" && dnf autoremove -y
            elif command_exists yum; then
                yum remove -y "$package" && yum autoremove -y
            elif command_exists apk; then
                apk del "$package"
            else
                red "Unknown system!"
                return 1
            fi
        else
            red "Unknown action: $action"
            return 1
        fi
    done

    return 0
}

# 处理防火墙
allow_port() {
    has_ufw=0
    has_firewalld=0
    has_iptables=0
    has_ip6tables=0

    command_exists ufw && has_ufw=1
    command_exists firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1 && has_firewalld=1
    command_exists iptables && has_iptables=1
    command_exists ip6tables && has_ip6tables=1

    # 出站和基础规则
    [ "$has_ufw" -eq 1 ] && ufw --force default allow outgoing >/dev/null 2>&1
    [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --zone=public --set-target=ACCEPT >/dev/null 2>&1
    [ "$has_iptables" -eq 1 ] && {
        iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -i lo -j ACCEPT
        iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p icmp -j ACCEPT
        iptables -P FORWARD DROP 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
    }
    [ "$has_ip6tables" -eq 1 ] && {
        ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -I INPUT 3 -i lo -j ACCEPT
        ip6tables -C INPUT -p icmp -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p icmp -j ACCEPT
        ip6tables -P FORWARD DROP 2>/dev/null || true
        ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    }

    # 入站
    for rule in "$@"; do
        port=${rule%/*}
        proto=${rule#*/}
        [ "$has_ufw" -eq 1 ] && ufw allow in ${port}/${proto} >/dev/null 2>&1
        [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --add-port=${port}/${proto} >/dev/null 2>&1
        [ "$has_iptables" -eq 1 ] && (iptables -C INPUT -p ${proto} --dport ${port} -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p ${proto} --dport ${port} -j ACCEPT)
        [ "$has_ip6tables" -eq 1 ] && (ip6tables -C INPUT -p ${proto} --dport ${port} -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p ${proto} --dport ${port} -j ACCEPT)
    done

    [ "$has_firewalld" -eq 1 ] && firewall-cmd --reload >/dev/null 2>&1

    # 规则持久化
    if command_exists rc-service 2>/dev/null; then
        [ "$has_iptables" -eq 1 ] && iptables-save > /etc/iptables/rules.v4 2>/dev/null
        [ "$has_ip6tables" -eq 1 ] && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
    else
        if ! command_exists netfilter-persistent; then
            manage_packages install iptables-persistent || yellow "请手动安装netfilter-persistent或保存iptables规则" 
            netfilter-persistent save >/dev/null 2>&1
        elif command_exists service; then
            service iptables save 2>/dev/null
            service ip6tables save 2>/dev/null
        fi
    fi
}

# 下载并安装 sing-box
install_singbox() {
    clear
    purple "正在安装 sing-box，请稍后..."
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86' | 'i686' | 'i386') ARCH='386' ;;
        'aarch64' | 'arm64') ARCH='arm64' ;;
        'armv7l') ARCH='armv7' ;;
        's390x') ARCH='s390x' ;;
        *) red "不支持的架构: ${ARCH_RAW}"; exit 1 ;;
    esac

    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 755 "${work_dir}"
    # 官方最新版: https://github.com/SagerNet/sing-box/releases
    # 使用本项目的 releases
    latest_tag=$(curl -sL "https://api.github.com/repos/obkj/sing-box-onekey/releases/latest" | jq -r '.tag_name // empty')
    [ -z "$latest_tag" ] && { red "获取最新版本失败"; exit 1; }
    version="${latest_tag#v}"
    # Linux 包名架构: amd64/386/arm64/arm/s390x
    case "${ARCH}" in
        armv7) LINUX_ARCH="arm" ;;
        *) LINUX_ARCH="${ARCH}" ;;
    esac

    tarball="sing-box-${version}-linux-${LINUX_ARCH}.tar.gz"
    extract_dir="${work_dir}/sing-box-${version}-linux-${LINUX_ARCH}"
    download_url="https://github.com/obkj/sing-box-onekey/releases/download/${latest_tag}/${tarball}"
    yellow "正在下载 sing-box ${version} (${LINUX_ARCH}) ..."
    curl -sLo "${work_dir}/${tarball}" "$download_url" || { red "下载失败"; rm -f "${work_dir}/${tarball}"; exit 1; }
    
    if ! tar -xzf "${work_dir}/${tarball}" -C "${work_dir}"; then
        red "解压失败"; rm -rf "${work_dir}/${tarball}" "${extract_dir}"; exit 1
    fi
    
    if ! mv "${extract_dir}/sing-box" "${work_dir}/"; then
        red "程序移动失败"; rm -rf "${work_dir}/${tarball}" "${extract_dir}"; exit 1
    fi
    
    rm -rf "${work_dir}/${tarball}" "${extract_dir}"
    chown root:root "${work_dir}/${server_name}" && chmod +x "${work_dir}/${server_name}"

    uuid=$(cat /proc/sys/kernel/random/uuid)
    output=$(/etc/sing-box/sing-box generate reality-keypair)
    private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')

    allow_port $vless_port/tcp > /dev/null 2>&1

    dns_strategy=$(ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 && echo "prefer_ipv4" || (ping -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1 && echo "prefer_ipv6" || echo "prefer_ipv4"))

    cat > "${config_dir}" << EOF
{
  "log": {
    "disabled": false,
    "level": "error",
    "output": "$work_dir/sb.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "local",
        "strategy": "$dns_strategy"
      }
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": $vless_port,
      "users": [
        {
          "uuid": "$uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.iij.ad.jp",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.iij.ad.jp",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": [""]
        }
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": { "final": "direct" }
}
EOF
}
# systemd 守护进程
main_systemd_services() {
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    [ -f /etc/centos-release ] && { yum install -y chrony 2>/dev/null; systemctl start chronyd; systemctl enable chronyd; chronyc -a makestep 2>/dev/null; }
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
}

# Alpine OpenRC 守护进程
alpine_openrc_services() {
    cat > /etc/init.d/sing-box << 'EOF'
#!/sbin/openrc-run
description="sing-box service"
command="/etc/sing-box/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background=true
pidfile="/var/run/sing-box.pid"
EOF
    chmod +x /etc/init.d/sing-box
    rc-update add sing-box default > /dev/null 2>&1
}

# 生成节点信息
get_info() {
  yellow "\n正在获取 IP，请稍等...\n"
  local ipv4=$(curl -4 -s --max-time 2 ip.sb)
  local ipv6=$(curl -6 -s --max-time 2 ip.sb)

  clear
  isp=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" | tr -d '\n' | awk -F\" '{c="";i="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="isp")i=$(x+2)};if(c&&i)print c"-"i}' | sed 's/ /_/g' || curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://ipapi.co/json" | tr -d '\n' | awk -F\" '{c="";o="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="org")o=$(x+2)};if(c&&o)print c"-"o}' | sed 's/ /_/g' || echo "VPS")

  > "${work_dir}/url.txt"
  if [ -n "$ipv4" ]; then
    echo -e "vless://${uuid}@${ipv4}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=${public_key}&type=tcp&headerType=none#${isp}" >> "${work_dir}/url.txt"
  fi
  if [ -n "$ipv6" ]; then
    echo -e "vless://${uuid}@[${ipv6}]:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=${public_key}&type=tcp&headerType=none#${isp}_IPv6" >> "${work_dir}/url.txt"
  fi
  [ ! -s "${work_dir}/url.txt" ] && red "无法获取 IP 地址" && return

  base64 -w0 "${work_dir}/url.txt" > "${work_dir}/sub.txt"
  chmod 644 "${work_dir}/url.txt" "${work_dir}/sub.txt"

  green "\n========== 节点信息 ==========\n"
  purple "$(cat ${work_dir}/url.txt)\n"
  green "\n订阅文件路径: ${purple}${work_dir}/sub.txt${re}"
  green "可用任意 HTTP 或 base64 订阅转换器使用上述文件。\n"
}

# 通用服务管理函数
manage_service() {
    local service_name="$1"
    local action="$2"

    if [ -z "$service_name" ] || [ -z "$action" ]; then
        red "缺少服务名或操作参数\n"
        return 1
    fi
    
    local status=$(check_singbox)
    status=$(echo "$status" | sed "s/\x1b\[[0-9;]*m//g")

    case "$action" in
        "start")
            if [ "$status" == "running" ]; then 
                yellow "${service_name} 正在运行\n"
                return 0
            elif [ "$status" == "not installed" ]; then 
                yellow "${service_name} 尚未安装!\n"
                return 1
            else 
                yellow "正在启动 ${service_name} 服务\n"
                if command_exists rc-service; then
                    rc-service "$service_name" start
                elif command_exists systemctl; then
                    systemctl daemon-reload
                    systemctl start "$service_name"
                fi
                
                if [ $? -eq 0 ]; then
                    green "${service_name} 服务已成功启动\n"
                    return 0
                else
                    red "${service_name} 服务启动失败\n"
                    return 1
                fi
            fi
            ;;
            
        "stop")
            if [ "$status" == "not installed" ]; then 
                yellow "${service_name} 尚未安装！\n"
                return 2
            elif [ "$status" == "not running" ]; then
                yellow "${service_name} 未运行\n"
                return 1
            else
                yellow "正在停止 ${service_name} 服务\n"
                if command_exists rc-service; then
                    rc-service "$service_name" stop
                elif command_exists systemctl; then
                    systemctl stop "$service_name"
                fi
                
                if [ $? -eq 0 ]; then
                    green "${service_name} 服务已成功停止\n"
                    return 0
                else
                    red "${service_name} 服务停止失败\n"
                    return 1
                fi
            fi
            ;;
            
        "restart")
            if [ "$status" == "not installed" ]; then
                yellow "${service_name} 尚未安装！\n"
                return 1
            else
                yellow "正在重启 ${service_name} 服务\n"
                if command_exists rc-service; then
                    rc-service "$service_name" restart
                elif command_exists systemctl; then
                    systemctl daemon-reload
                    systemctl restart "$service_name"
                fi
                
                if [ $? -eq 0 ]; then
                    green "${service_name} 服务已成功重启\n"
                    return 0
                else
                    red "${service_name} 服务重启失败\n"
                    return 1
                fi
            fi
            ;;
            
        *)
            red "无效的操作: $action\n"
            red "可用操作: start, stop, restart\n"
            return 1
            ;;
    esac
}

# 启动 sing-box
start_singbox() {
    manage_service "sing-box" "start"
}

# 停止 sing-box
stop_singbox() {
    manage_service "sing-box" "stop"
}

# 重启 sing-box
restart_singbox() {
    manage_service "sing-box" "restart"
}

# 卸载 sing-box
uninstall_singbox() {
   reading "确定要卸载 sing-box 吗? (y/n): " choice
   case "${choice}" in
       y|Y)
           yellow "正在卸载 sing-box..."
           if command_exists rc-service; then
                rc-service sing-box stop 2>/dev/null
                rm -f /etc/init.d/sing-box
                rc-update del sing-box default 2>/dev/null
           else
                systemctl stop "${server_name}" 2>/dev/null
                systemctl disable "${server_name}" 2>/dev/null
                systemctl daemon-reload 2>/dev/null || true
           fi
           rm -rf "${work_dir}" /etc/systemd/system/sing-box.service 2>/dev/null
           rm -f /usr/bin/sb
           green "\nsing-box 卸载成功\n" && exit 0
           ;;
       *)
           purple "已取消卸载\n"
           ;;
   esac
}

# 创建快捷指令（使用当前脚本路径）
create_shortcut() {
  rm -f /usr/bin/sb
  local target_path="$work_dir/sing-box.sh"
  if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
    cp -f "$SCRIPT_PATH" "$target_path"
    chmod +x "$target_path"
  fi
  if [ ! -f "$target_path" ]; then
    yellow "\n检测到管道安装，正在下载脚本到本地..."
    if command_exists curl; then
      curl -sLo "$target_path" "https://raw.githubusercontent.com/obkj/sing-box-onekey/refs/heads/main/sing-box.sh"
    elif command_exists wget; then
      wget -qO "$target_path" "https://raw.githubusercontent.com/obkj/sing-box-onekey/refs/heads/main/sing-box.sh"
    fi
    chmod +x "$target_path" 2>/dev/null
  fi
  if [ -f "$target_path" ]; then
    cat > "$work_dir/sb.sh" << EOF
#!/usr/bin/env bash
exec bash "$target_path" "\$@"
EOF
    chmod +x "$work_dir/sb.sh"
    ln -sf "$work_dir/sb.sh" /usr/bin/sb 2>/dev/null && green "\n快捷指令 sb 已创建\n" || yellow "\n需 root 才能创建 /usr/bin/sb\n"
  else
    yellow "\n未找到脚本文件，跳过创建快捷指令 sb\n"
    yellow "请手动将脚本保存到 $target_path\n"
  fi
}

# 适配 Alpine
change_hosts() {
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
    sed -i '2s/.*/::1         localhost/' /etc/hosts
}

# 变更配置
change_config() {
    local singbox_status=$(check_singbox 2>/dev/null)
    local singbox_installed=$?
    [ $singbox_installed -eq 2 ] && { yellow "sing-box 尚未安装！"; sleep 1; menu; return; }
    [ $singbox_installed -eq 2 ] && { yellow "sing-box 尚未安装！"; sleep 1; return; }
    clear
    echo ""
    green "=== 修改节点配置 ===\n"
    green "sing-box 状态: $singbox_status\n"
    green "1. 修改 vless-reality 端口"
    green "2. 修改 UUID"
    green "3. 修改 Reality 伪装域名 (SNI)"
    purple "0. 返回主菜单"
    echo ""
    reading "请选择: " choice
    case "${choice}" in
        1)
            reading "\n请输入新端口 (回车随机): " new_port
            [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
            sed -i '/"type": "vless"/,/listen_port/ s/"listen_port": [0-9]\+/"listen_port": '"$new_port"'/' $config_dir
            allow_port $new_port/tcp > /dev/null 2>&1
            restart_singbox
            sed -i 's/\(vless:\/\/[^@]*@[^:]*:\)[0-9]\{1,\}/\1'"$new_port"'/' $client_dir
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            green "\n端口已改为：${purple}$new_port${re}\n"
            ;;
        2)
            reading "\n请输入新 UUID (回车随机): " new_uuid
            [ -z "$new_uuid" ] && new_uuid=$(cat /proc/sys/kernel/random/uuid)
            sed -i 's/"uuid": "[a-f0-9-]*"/"uuid": "'"$new_uuid"'"/' $config_dir
            restart_singbox
            sed -i -E 's/(vless:\/\/)[^@]*(@.*)/\1'"$new_uuid"'\2/' $client_dir
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            green "\nUUID 已改为：${purple}${new_uuid}${re}\n"
            ;;
        3)
            green "\n示例: www.joom.com / www.iij.ad.jp (可自定义)\n"
            reading "请输入新 SNI (回车默认 www.iij.ad.jp): " new_sni
            [ -z "$new_sni" ] && new_sni="www.iij.ad.jp"
            jq --arg s "$new_sni" '(.inbounds[]|select(.type=="vless")|.tls.server_name)=$s | (.inbounds[]|select(.type=="vless")|.tls.reality.handshake.server)=$s' "$config_dir" > "${config_dir}.tmp" && mv "${config_dir}.tmp" "$config_dir" || rm -f "${config_dir}.tmp"
            restart_singbox
            sed -i "s/\(vless:\/\/[^\?]*\?\([^\&]*\&\)*sni=\)[^&]*/\1$new_sni/" $client_dir
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            green "\nReality SNI 已改为：${purple}${new_sni}${re}\n"
            ;;
        0) return ;;
        *) red "无效选项" ;;
    esac
}

# sing-box 管理
manage_singbox() {
    # 检查sing-box状态
    local singbox_status=$(check_singbox "sing-box" 2>/dev/null)
    local singbox_installed=$?
    
    clear
    echo ""
    green "=== sing-box 管理 ===\n"
    green "sing-box当前状态: $singbox_status\n"
    green "1. 启动sing-box服务"
    skyblue "-------------------"
    green "2. 停止sing-box服务"
    skyblue "-------------------"
    green "3. 重启sing-box服务"
    skyblue "-------------------"
    purple "0. 返回主菜单"
    skyblue "------------"
    reading "\n请输入选择: " choice
    case "${choice}" in
        1) start_singbox ;;  
        2) stop_singbox ;;
        3) restart_singbox ;;
        0) return ;;
        *) red "无效的选项！" && sleep 1 ;;
    esac
}

# 查看节点信息
check_nodes() {
    [ ! -f "${work_dir}/url.txt" ] && { yellow "未安装或节点文件不存在"; return; }
    green "\n========== 节点信息 ==========\n"
    while IFS= read -r line; do purple "$line"; done < "${work_dir}/url.txt"
    green "\n订阅文件: ${purple}${work_dir}/sub.txt${re}\n"
}

# 主菜单
menu() {
   singbox_status=$(check_singbox 2>/dev/null)
   clear
   echo ""
   purple "=== sing-box 一键脚本 ===\n"
   green "sing-box 状态: ${singbox_status}\n"
   green "1. 安装 sing-box"
   red "2. 卸载 sing-box"
   green "3. sing-box 管理"
   green "4. 查看节点信息"
   green "5. 修改节点配置"
   red "0. 退出"
   echo ""
   reading "请选择 (0-5): " choice
   echo ""
}

# 捕获 Ctrl+C 退出信号
trap 'red "已取消操作"; exit' INT

# 主循环
while true; do
   menu
   case "${choice}" in
        1)
            check_singbox &>/dev/null; r=$?
            if [ $r -eq 0 ]; then
                yellow "sing-box 已安装\n"
            else
                manage_packages install jq coreutils lsof tar
                install_singbox
                if command_exists systemctl; then
                    main_systemd_services
                elif command_exists rc-update; then
                    alpine_openrc_services
                    change_hosts
                    rc-service sing-box restart
                else
                    red "不支持的 init 系统"; exit 1
                fi
                sleep 3
                get_info
                create_shortcut
            fi
            ;;
        2) uninstall_singbox ;;
        3) manage_singbox ;;
        4) check_nodes ;;
        5) change_config ;;
        0) exit 0 ;;
        *) red "请输入 0-5" ;;
   esac
   read -n 1 -s -r -p $'\033[1;91m按任意键返回...\033[0m'
done
