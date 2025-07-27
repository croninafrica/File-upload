# 文件上传系统

一个基于Spring Boot的文件上传系统，具有美观的Web界面和完整的后端API。

## 功能特性

- 🔐 **访问控制**: 需要输入访问代码才能进入上传页面
- 📁 **多文件上传**: 支持同时选择和上传多个文件
- 🎨 **美观界面**: 现代化的卡片样式设计，支持拖拽上传
- 📊 **实时进度**: 显示上传进度和状态
- 🛡️ **安全验证**: 文件大小限制、文件名验证等
- 📱 **响应式设计**: 适配不同屏幕尺寸

## 技术栈

### 前端
- HTML5 + CSS3 + JavaScript
- 现代化UI设计
- 拖拽上传功能
- 响应式布局

### 后端
- Spring Boot 2.7.14
- Spring Web MVC
- Apache Commons IO
- Maven构建工具

## 快速开始

### 环境要求
- Java 8 或更高版本
- Maven 3.6 或更高版本

### 运行步骤

1. **编译项目**
   ```bash
   mvn clean compile
   ```

2. **启动应用**
   ```bash
   mvn spring-boot:run
   ```

3. **访问应用**
   - 打开浏览器访问: http://localhost:8080
   - 输入访问代码: `lay@9527`
   - 进入文件上传页面

### 配置说明

#### 文件上传目录
默认上传目录为 `D:/file_test`，可以通过以下方式修改：

1. 修改 `src/main/resources/application.properties` 文件中的 `file.upload.path` 配置
2. 或者通过启动参数指定：
   ```bash
   mvn spring-boot:run -Dspring-boot.run.arguments="--file.upload.path=/your/custom/path"
   ```

#### 访问代码
当前支持的访问代码：
- `lay@9527`

可以在 `src/main/resources/static/index.html` 中修改验证逻辑。

#### 文件大小限制
- 单个文件最大: 50MB
- 总上传大小: 100MB

可以在 `application.properties` 中修改这些限制。

## API接口

### 文件上传
- **URL**: `POST /api/upload`
- **参数**: `file` (multipart/form-data)
- **返回**: JSON格式的上传结果

### 系统信息
- **URL**: `GET /api/info`
- **返回**: 上传目录信息

### 健康检查
- **URL**: `GET /api/health`
- **返回**: 服务状态信息

## 项目结构

```
file-upload-server/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/fileupload/
│   │   │       ├── FileUploadApplication.java     # 主应用类
│   │   │       ├── config/
│   │   │       │   └── WebConfig.java            # Web配置
│   │   │       └── controller/
│   │   │           └── FileUploadController.java # 文件上传控制器
│   │   └── resources/
│   │       ├── static/
│   │       │   ├── index.html                    # 登录页面
│   │       │   └── upload.html                   # 上传页面
│   │       └── application.properties            # 应用配置
├── pom.xml                                       # Maven配置
└── README.md                                     # 项目说明
```

## 使用说明

1. **启动服务**: 运行 `mvn spring-boot:run`
2. **访问首页**: 浏览器打开 http://localhost:8080
3. **输入代码**: 在首页输入访问代码（lay@9527）
4. **上传文件**: 
   - 可以点击"选择文件"按钮选择文件
   - 也可以直接拖拽文件到上传区域
   - 支持多文件同时上传
5. **查看结果**: 上传完成后会显示成功信息，文件保存在配置的目录中

## 注意事项

- 确保上传目录有写入权限
- 文件名会自动添加时间戳前缀以避免重名
- 上传的文件会保存在服务器的指定目录中
- 建议在生产环境中修改访问代码验证逻辑

## 扩展功能

可以根据需要添加以下功能：
- 用户认证和权限管理
- 文件类型限制
- 文件预览功能
- 上传历史记录
- 文件下载功能
- 数据库存储文件信息