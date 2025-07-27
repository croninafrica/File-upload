#!/bin/bash

# 文件上传系统 自动部署脚本
# 作者: 自动生成
# 日期: $(date)

echo "开始自动部署检测..."

# 设置变量
FRONTEND_ZIP="/tmp/update.zip"
BACKEND_ZIP="/tmp/backend.zip"
NGINX_HTML_DIR="/root/nginx/html"
BACKEND_DIR="/root/java/update_api"
BACKEND_JAR="file-upload-server-1.0.0.jar"
SERVICE_NAME="file-upload-server"

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    echo "请以root权限运行此脚本"
    exit 1
fi

# 创建必要目录
echo "创建必要目录..."
mkdir -p ${NGINX_HTML_DIR}/update
mkdir -p ${BACKEND_DIR}
mkdir -p /tmp/backup
mkdir -p /tmp/uploads

# 检测并部署前端
if [ -f "${FRONTEND_ZIP}" ]; then
    echo "检测到前端包: ${FRONTEND_ZIP}"
    
    # 备份现有前端文件
    if [ -d "${NGINX_HTML_DIR}/update" ] && [ "$(ls -A ${NGINX_HTML_DIR}/update)" ]; then
        echo "备份现有前端文件..."
        BACKUP_DIR="/tmp/backup/frontend_$(date +%Y%m%d_%H%M%S)"
        mkdir -p ${BACKUP_DIR}
        cp -r ${NGINX_HTML_DIR}/update/* ${BACKUP_DIR}/
        echo "前端文件已备份到: ${BACKUP_DIR}"
    fi
    
    # 清空update目录
    rm -rf ${NGINX_HTML_DIR}/update/*
    
    # 解压前端包到update目录
    echo "部署前端文件..."
    cd ${NGINX_HTML_DIR}/update
    unzip -o ${FRONTEND_ZIP}
    
    # 设置权限
    chown -R root:root ${NGINX_HTML_DIR}/update
    chmod -R 644 ${NGINX_HTML_DIR}/update/*.html
    
    echo "✅ 前端部署完成!"
    echo "访问地址: http://your-server/update/"
    
    # 删除已处理的前端包
    rm -f ${FRONTEND_ZIP}
else
    echo "未检测到前端包: ${FRONTEND_ZIP}"
fi

# 检测并部署后端
if [ -f "${BACKEND_ZIP}" ]; then
    echo "检测到后端包: ${BACKEND_ZIP}"
    
    # 停止现有服务
    echo "停止现有后端服务..."
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        systemctl stop ${SERVICE_NAME}
        echo "后端服务已停止"
    fi
    
    # 备份现有后端文件
    if [ -f "${BACKEND_DIR}/${BACKEND_JAR}" ]; then
        echo "备份现有后端文件..."
        BACKUP_DIR="/tmp/backup/backend_$(date +%Y%m%d_%H%M%S)"
        mkdir -p ${BACKUP_DIR}
        cp ${BACKEND_DIR}/${BACKEND_JAR} ${BACKUP_DIR}/
        echo "后端文件已备份到: ${BACKUP_DIR}"
    fi
    
    # 解压后端包
    echo "部署后端文件..."
    cd ${BACKEND_DIR}
    unzip -o ${BACKEND_ZIP}
    
    # 设置权限
    chown -R root:root ${BACKEND_DIR}
    chmod 755 ${BACKEND_DIR}
    chmod 644 ${BACKEND_DIR}/${BACKEND_JAR}
    
    # 创建或更新systemd服务文件
    echo "创建systemd服务..."
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=File Upload Server
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${BACKEND_DIR}
ExecStart=/usr/bin/java -jar ${BACKEND_DIR}/${BACKEND_JAR}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# 环境变量
Environment=JAVA_OPTS="-Xms512m -Xmx1024m"
Environment=SPRING_PROFILES_ACTIVE=prod

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载systemd并启动服务
    echo "启动后端服务..."
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    
    # 检查服务状态
    sleep 3
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        echo "✅ 后端服务启动成功!"
        echo "后端路径: ${BACKEND_DIR}"
        echo "服务状态: systemctl status ${SERVICE_NAME}"
        echo "查看日志: journalctl -u ${SERVICE_NAME} -f"
    else
        echo "❌ 后端服务启动失败!"
        echo "查看错误日志: journalctl -u ${SERVICE_NAME} -n 50"
    fi
    
    # 删除已处理的后端包
    rm -f ${BACKEND_ZIP}
else
    echo "未检测到后端包: ${BACKEND_ZIP}"
fi

# 重新加载nginx配置
echo "重新加载nginx配置..."
if [ -f "/root/nginx/sbin/nginx" ]; then
    /root/nginx/sbin/nginx -s reload
    echo "nginx配置已重新加载"
else
    echo "警告: 未找到nginx可执行文件"
fi

echo "自动部署检测完成!"
echo "前端访问: http://your-server/update/"
echo "后端API: http://your-server/api/"
echo "备份文件位置: /tmp/backup/"