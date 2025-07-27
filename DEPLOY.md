# 文件上传系统 Linux 部署指南

本指南将帮助您在 Linux 服务器上部署文件上传系统，包括前端（Nginx）和后端（Spring Boot）的完整配置。

## 系统要求

- **操作系统**: CentOS 7+, Ubuntu 18.04+, RHEL 7+ 或其他 Linux 发行版
- **Java**: OpenJDK 8 或更高版本
- **Nginx**: 1.14 或更高版本
- **Maven**: 3.6 或更高版本（用于构建）
- **内存**: 至少 1GB RAM
- **磁盘**: 至少 2GB 可用空间

## 部署步骤

### 1. 环境准备

#### 安装 Java
```bash
# CentOS/RHEL
sudo yum install -y java-1.8.0-openjdk java-1.8.0-openjdk-devel

# Ubuntu/Debian
sudo apt update
sudo apt install -y openjdk-8-jdk

# 验证安装
java -version
```

#### 安装 Nginx
```bash
# CentOS/RHEL
sudo yum install -y nginx

# Ubuntu/Debian
sudo apt install -y nginx

# 启动并设置开机自启
sudo systemctl start nginx
sudo systemctl enable nginx
```

#### 安装 Maven（如果需要重新构建）
```bash
# CentOS/RHEL
sudo yum install -y maven

# Ubuntu/Debian
sudo apt install -y maven
```

### 2. 构建应用

在项目根目录执行：
```bash
# 清理并打包
mvn clean package -DskipTests

# 验证JAR文件生成
ls -la target/file-upload-server-1.0.0.jar
```

### 3. 自动部署

使用提供的部署脚本：
```bash
# 给脚本执行权限
chmod +x deploy.sh

# 以root权限运行部署脚本
sudo ./deploy.sh
```

### 4. 手动部署（可选）

如果自动部署脚本失败，可以手动执行以下步骤：

#### 4.1 创建应用目录
```bash
sudo mkdir -p /opt/fileupload/{uploads,logs}
sudo mkdir -p /tmp/fileupload
```

#### 4.2 创建服务用户
```bash
sudo useradd -r -s /bin/false -d /opt/fileupload fileupload
```

#### 4.3 复制文件
```bash
# 复制JAR文件
sudo cp target/file-upload-server-1.0.0.jar /opt/fileupload/

# 创建nginx目录结构
sudo mkdir -p /root/nginx/html
sudo mkdir -p /root/nginx/logs
sudo mkdir -p /root/nginx/conf

# 复制前端文件
sudo cp src/main/resources/static/*.html /root/nginx/html/
```

#### 4.4 设置权限
```bash
sudo chown -R fileupload:fileupload /opt/fileupload
sudo chmod -R 755 /opt/fileupload
sudo chown -R root:root /root/nginx/html/*.html
sudo chmod -R 755 /root/nginx
```

### 5. 配置 Nginx

#### 方法1: 使用完整配置文件
```bash
# 使用新配置
sudo cp nginx.conf /root/nginx/conf/nginx.conf

# 测试配置
/root/nginx/sbin/nginx -t -c /root/nginx/conf/nginx.conf

# 启动nginx
/root/nginx/sbin/nginx -c /root/nginx/conf/nginx.conf
```

#### 方法2: 使用自定义nginx安装
```bash
# 复制配置文件
sudo cp nginx.conf /root/nginx/conf/nginx.conf

# 测试配置
/root/nginx/sbin/nginx -t -c /root/nginx/conf/nginx.conf

# 启动nginx
/root/nginx/sbin/nginx -c /root/nginx/conf/nginx.conf

# 停止nginx（如果需要）
/root/nginx/sbin/nginx -s stop

# 重新加载配置
/root/nginx/sbin/nginx -s reload
```

### 6. 配置防火墙

```bash
# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload

# Ubuntu (ufw)
sudo ufw allow 80/tcp
sudo ufw allow 8080/tcp
sudo ufw enable

# 或者使用iptables
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

## 服务管理

### 启动/停止/重启服务
```bash
# 启动服务
sudo systemctl start file-upload-server

# 停止服务
sudo systemctl stop file-upload-server

# 重启服务
sudo systemctl restart file-upload-server

# 查看服务状态
sudo systemctl status file-upload-server

# 设置开机自启
sudo systemctl enable file-upload-server
```

### 查看日志
```bash
# 查看应用日志
sudo journalctl -u file-upload-server -f

# 查看nginx日志
sudo tail -f /var/log/nginx/fileupload_access.log
sudo tail -f /var/log/nginx/fileupload_error.log
```

## 配置说明

### 应用配置

主要配置文件：`/opt/fileupload/application.properties`

```properties
# 服务端口
server.port=8080

# 文件上传路径
file.upload.path=/opt/fileupload/uploads

# 临时文件位置
spring.servlet.multipart.location=/tmp/fileupload

# 文件大小限制
spring.servlet.multipart.max-file-size=50MB
spring.servlet.multipart.max-request-size=100MB
```

### Nginx 配置要点

1. **反向代理**: 将 `/api/` 请求代理到后端 `http://127.0.0.1:8080`
2. **静态文件**: 前端文件放在 `/root/nginx/html/`
3. **文件上传**: 设置 `client_max_body_size 100M`
4. **缓存**: 静态资源设置1小时缓存

## 访问应用

部署完成后，可以通过以下方式访问：

- **前端页面**: `http://your-server-ip/`
- **上传页面**: `http://your-server-ip/upload.html`
- **API接口**: `http://your-server-ip/api/`
- **健康检查**: `http://your-server-ip/health`

## 故障排除

### 常见问题

1. **服务启动失败**
   ```bash
   # 检查Java版本
   java -version
   
   # 检查端口占用
   sudo netstat -tlnp | grep 8080
   
   # 查看详细错误日志
   sudo journalctl -u file-upload-server -n 50
   ```

2. **文件上传失败**
   ```bash
   # 检查目录权限
   ls -la /opt/fileupload/uploads
   
   # 检查磁盘空间
   df -h
   
   # 检查nginx配置
   sudo nginx -t
   ```

3. **前端页面无法访问**
   ```bash
   # 检查nginx状态
   sudo systemctl status nginx
   
   # 检查文件是否存在
   ls -la /root/nginx/html/
   
   # 检查nginx错误日志
   sudo tail -f /var/log/nginx/error.log
   ```

### 性能优化

1. **JVM 参数调优**
   ```bash
   # 编辑服务文件
   sudo systemctl edit file-upload-server
   
   # 添加以下内容
   [Service]
   Environment="JAVA_OPTS=-Xms1g -Xmx2g -XX:+UseG1GC"
   ```

2. **Nginx 优化**
   - 调整 `worker_processes` 为 CPU 核心数
   - 增加 `worker_connections`
   - 启用 gzip 压缩
   - 配置适当的缓存策略

## 安全建议

1. **更改默认访问代码**
   - 修改前端页面中的验证逻辑
   - 当前访问代码已设置为: `lay@9527`

2. **启用 HTTPS**
   - 获取 SSL 证书
   - 配置 nginx HTTPS
   - 强制重定向 HTTP 到 HTTPS

3. **限制访问**
   - 配置防火墙规则
   - 使用 nginx 访问控制
   - 定期更新系统和软件

4. **监控和日志**
   - 定期检查日志文件
   - 设置磁盘空间监控
   - 配置日志轮转

## 备份和恢复

### 备份
```bash
# 备份应用文件
sudo tar -czf fileupload-backup-$(date +%Y%m%d).tar.gz /opt/fileupload

# 备份nginx配置
sudo cp /etc/nginx/sites-available/fileupload /backup/
```

### 恢复
```bash
# 恢复应用文件
sudo tar -xzf fileupload-backup-YYYYMMDD.tar.gz -C /

# 恢复nginx配置
sudo cp /backup/fileupload /etc/nginx/sites-available/
```

---

**部署完成后，请记得：**
1. 修改默认访问代码
2. 配置定期备份
3. 监控系统资源使用情况
4. 定期更新系统和应用