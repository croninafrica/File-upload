package com.fileupload.controller;

import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.security.MessageDigest;
import java.util.regex.Pattern;
import java.util.List;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Controller
public class FileUploadController {

    // 上传目录配置，可以通过application.properties配置
    @Value("${file.upload.path:D:/file_test}")
    private String uploadPath;
    
    // 目标目录配置，与上传目录保持一致
    @Value("${file.target.path:${file.upload.path}}")
    private String targetPath;

    // 最大文件大小 (500MB)
    private static final long MAX_FILE_SIZE = 500 * 1024 * 1024;
    
    // 分片大小 (2MB)
    private static final long CHUNK_SIZE = 2 * 1024 * 1024;
    
    // 上传会话超时时间 (30分钟)
    private static final long UPLOAD_TIMEOUT = 30 * 60 * 1000;
    
    // 允许的文件扩展名（安全白名单 - 仅允许ZIP格式）
    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<String>() {
        private static final long serialVersionUID = 1L;
        {
            add(".zip");
        }
    };

    // 访问代码配置，可以通过application.properties配置
    @Value("${app.access.code:lay@9527}")
    private String accessCode;
    
    // 访问代码验证会话管理
    private final Map<String, AuthSession> authSessionMap = new ConcurrentHashMap<>();
    
    // 认证会话超时时间（24小时）
    private static final long AUTH_SESSION_TIMEOUT = 24 * 60 * 60 * 1000L;
    
    // 认证会话信息类
    private static class AuthSession {
        private final String sessionId;
        private final long createTime;
        private long lastAccessTime;
        private final String clientInfo;
        
        public AuthSession(String sessionId, String clientInfo) {
            this.sessionId = sessionId;
            this.clientInfo = clientInfo;
            this.createTime = System.currentTimeMillis();
            this.lastAccessTime = this.createTime;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() - createTime > AUTH_SESSION_TIMEOUT;
        }
        
        public void updateAccessTime() {
            this.lastAccessTime = System.currentTimeMillis();
        }
        
        // getters
        public String getSessionId() { return sessionId; }
        public long getCreateTime() { return createTime; }
        public long getLastAccessTime() { return lastAccessTime; }
        public String getClientInfo() { return clientInfo; }
    }

    /**
     * 验证访问代码
     */
    @PostMapping("/api/auth/verify")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifyAccessCode(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            String inputCode = request.get("accessCode");
            String clientInfo = request.get("clientInfo"); // 可选的客户端信息
            
            if (inputCode == null || inputCode.trim().isEmpty()) {
                response.put("success", false);
                response.put("message", "访问代码不能为空");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 验证访问代码
            if (!accessCode.equals(inputCode.trim())) {
                // 记录失败尝试（生产环境中应该有更严格的限制）
                System.out.println("访问代码验证失败 - 输入: " + inputCode + ", 时间: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
                
                response.put("success", false);
                response.put("message", "访问代码不正确");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            
            // 创建认证会话
            String authSessionId = UUID.randomUUID().toString();
            AuthSession authSession = new AuthSession(authSessionId, clientInfo != null ? clientInfo : "unknown");
            authSessionMap.put(authSessionId, authSession);
            
            // 记录成功认证
            System.out.println("访问代码验证成功 - 会话ID: " + authSessionId + ", 时间: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
            
            response.put("success", true);
            response.put("authSessionId", authSessionId);
            response.put("message", "验证成功");
            response.put("timeout", AUTH_SESSION_TIMEOUT);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            System.err.println("访问代码验证异常: " + e.getMessage());
            response.put("success", false);
            response.put("message", "验证失败，请重试");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
    
    /**
     * 验证认证会话
     */
    private boolean isValidAuthSession(String authSessionId) {
        if (authSessionId == null || authSessionId.trim().isEmpty()) {
            return false;
        }
        
        AuthSession authSession = authSessionMap.get(authSessionId);
        if (authSession == null) {
            return false;
        }
        
        if (authSession.isExpired()) {
            authSessionMap.remove(authSessionId);
            return false;
        }
        
        // 更新最后访问时间
        authSession.updateAccessTime();
        return true;
    }

    /**
     * 创建会话（需要先通过访问代码验证）
     */
    @PostMapping("/api/session/create")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> createSession(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            String authSessionId = request.get("authSessionId");
            
            // 验证认证会话
            if (!isValidAuthSession(authSessionId)) {
                response.put("success", false);
                response.put("message", "认证会话无效或已过期，请重新验证访问代码");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            
            String sessionId = UUID.randomUUID().toString();
            sessionMap.put(sessionId, System.currentTimeMillis());
            
            response.put("success", true);
            response.put("sessionId", sessionId);
            response.put("timeout", SESSION_TIMEOUT);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "创建会话失败: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
    
    /**
     * 验证会话
     */
    private boolean isValidSession(String sessionId) {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            return false;
        }
        
        Long lastActivity = sessionMap.get(sessionId);
        if (lastActivity == null) {
            return false;
        }
        
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastActivity > SESSION_TIMEOUT) {
            sessionMap.remove(sessionId);
            return false;
        }
        
        // 更新最后活动时间
        sessionMap.put(sessionId, currentTime);
        return true;
    }
    
    /**
     * 脚本执行接口（仅供部署功能内部调用）
     */
    @PostMapping("/api/execute-script")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> executeScript(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        String sessionId = request.get("sessionId");
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("error", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        String command = request.get("command");
        if (command == null || command.trim().isEmpty()) {
            response.put("success", false);
            response.put("error", "命令不能为空");
            return ResponseEntity.badRequest().body(response);
        }
        
        try {
            // 安全检查：禁止危险命令（严格模式）
            String lowerCommand = command.toLowerCase().trim();
            String[] dangerousCommands = {
                // 文件系统操作
                "rm ", "del ", "delete", "erase", "format", "fdisk", "mkfs", "dd if=", "rmdir",
                // 系统控制
                "shutdown", "reboot", "halt", "poweroff", "init 0", "init 6", "systemctl", "service",
                // 权限操作
                "chmod", "chown", "passwd", "su ", "sudo ", "runas", "icacls", "takeown",
                // 网络操作
                "wget", "curl", "nc ", "netcat", "telnet", "ssh", "scp", "ftp", "tftp",
                // 代码执行
                "python -c", "perl -e", "ruby -e", "node -e", "powershell", "cmd /c", "bash -c",
                // 进程操作
                "kill", "killall", "taskkill", "pkill", "pgrep",
                // 注册表操作
                "reg add", "reg delete", "regedit",
                // 环境变量
                "set ", "export ", "setx",
                // 文件传输
                "copy", "move", "xcopy", "robocopy", "cp ", "mv ",
                // 压缩解压（防止zip炸弹）
                "unzip", "tar -x", "7z x", "winrar"
            };
            
            for (String dangerous : dangerousCommands) {
                if (lowerCommand.contains(dangerous)) {
                    response.put("success", false);
                    response.put("error", "检测到危险命令，执行被拒绝: " + dangerous.trim());
                    return ResponseEntity.badRequest().body(response);
                }
            }
            
            // 执行命令
            ProcessBuilder processBuilder = new ProcessBuilder();
            
            // 根据操作系统设置命令
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                processBuilder.command("cmd", "/c", command);
            } else {
                processBuilder.command("sh", "-c", command);
            }
            
            // 设置工作目录为上传目录
            processBuilder.directory(new File(uploadPath));
            
            // 合并标准输出和错误输出
            processBuilder.redirectErrorStream(true);
            
            Process process = processBuilder.start();
            
            // 读取输出
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            
            // 等待进程完成（最多等待30秒）
            boolean finished = process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            
            if (!finished) {
                process.destroyForcibly();
                response.put("success", false);
                response.put("error", "命令执行超时（30秒），已强制终止");
                return ResponseEntity.ok(response);
            }
            
            int exitCode = process.exitValue();
            
            response.put("success", exitCode == 0);
            response.put("output", output.toString());
            response.put("exitCode", exitCode);
            
            if (exitCode != 0) {
                response.put("error", "命令执行失败，退出码: " + exitCode);
            }
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", "执行异常: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
    
    // 存储分片上传信息的Map
    private final Map<String, ChunkUploadInfo> chunkUploadMap = new ConcurrentHashMap<>();
    
    // 会话管理映射
    private final Map<String, Long> sessionMap = new ConcurrentHashMap<>();
    
    // 会话超时时间（10分钟）
    private static final long SESSION_TIMEOUT = 10 * 60 * 1000L;
    
    // 定期清理过期上传会话
    private final Timer cleanupTimer = new Timer(true);
    
    // 构造函数中启动清理任务
    public FileUploadController() {
        // 初始化临时文件目录
        initTempDirectory();
        
        // 每5分钟清理一次过期会话
        cleanupTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                cleanupExpiredUploads();
            }
        }, 5 * 60 * 1000, 5 * 60 * 1000);
    }
    
    /**
     * 初始化临时文件目录
     */
    private void initTempDirectory() {
        try {
            File tempDir = new File("./temp");
            if (!tempDir.exists()) {
                tempDir.mkdirs();
                System.out.println("创建临时文件目录: " + tempDir.getAbsolutePath());
            }
        } catch (Exception e) {
            System.err.println("初始化临时文件目录失败: " + e.getMessage());
        }
    }
    
    // 分片上传信息类
    private static class ChunkUploadInfo {
        private String fileName;
        private String originalName;
        private int totalChunks;
        private Set<Integer> uploadedChunks;
        private long fileSize;
        private long lastUpdateTime;
        
        public ChunkUploadInfo(String fileName, String originalName, int totalChunks, long fileSize) {
            this.fileName = fileName;
            this.originalName = originalName;
            this.totalChunks = totalChunks;
            this.fileSize = fileSize;
            this.uploadedChunks = new HashSet<>();
            this.lastUpdateTime = System.currentTimeMillis();
        }
        
        // getters and setters
        public String getFileName() { return fileName; }
        public String getOriginalName() { return originalName; }
        public int getTotalChunks() { return totalChunks; }
        public Set<Integer> getUploadedChunks() { return uploadedChunks; }
        public long getFileSize() { return fileSize; }
        public long getLastUpdateTime() { return lastUpdateTime; }
        public void setLastUpdateTime(long time) { this.lastUpdateTime = time; }
        
        public boolean isComplete() {
            return uploadedChunks.size() == totalChunks;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() - lastUpdateTime > UPLOAD_TIMEOUT;
        }
    }
    
    /**
     * 清理过期的上传会话
     */
    private void cleanupExpiredUploads() {
        try {
            List<String> expiredIds = new ArrayList<>();
            
            for (Map.Entry<String, ChunkUploadInfo> entry : chunkUploadMap.entrySet()) {
                if (entry.getValue().isExpired()) {
                    expiredIds.add(entry.getKey());
                }
            }
            
            for (String uploadId : expiredIds) {
                ChunkUploadInfo info = chunkUploadMap.remove(uploadId);
                if (info != null) {
                    // 清理临时文件
                    String tempDir = uploadPath + "/temp/" + uploadId;
                    try {
                        FileUtils.deleteDirectory(new File(tempDir));
                        System.out.println("清理过期上传会话: " + uploadId + ", 文件: " + info.getOriginalName());
                    } catch (Exception e) {
                        System.err.println("清理临时文件失败: " + e.getMessage());
                    }
                }
            }
            
            // 清理过期会话
            List<String> expiredSessions = new ArrayList<>();
            long currentTime = System.currentTimeMillis();
            
            for (Map.Entry<String, Long> entry : sessionMap.entrySet()) {
                if (currentTime - entry.getValue() > SESSION_TIMEOUT) {
                    expiredSessions.add(entry.getKey());
                }
            }
            
            for (String sessionId : expiredSessions) {
                sessionMap.remove(sessionId);
            }
            
            // 清理过期认证会话
            List<String> expiredAuthSessions = new ArrayList<>();
            for (Map.Entry<String, AuthSession> entry : authSessionMap.entrySet()) {
                if (entry.getValue().isExpired()) {
                    expiredAuthSessions.add(entry.getKey());
                }
            }
            
            for (String authSessionId : expiredAuthSessions) {
                authSessionMap.remove(authSessionId);
            }
            
            if (!expiredSessions.isEmpty()) {
                System.out.println("清理了 " + expiredSessions.size() + " 个过期文件上传会话");
            }
            
            if (!expiredAuthSessions.isEmpty()) {
                System.out.println("清理了 " + expiredAuthSessions.size() + " 个过期认证会话");
            }
            
            if (!expiredIds.isEmpty()) {
                System.out.println("清理了 " + expiredIds.size() + " 个过期上传会话");
            }
            
        } catch (Exception e) {
            System.err.println("清理过期上传会话时发生错误: " + e.getMessage());
        }
    }
    
    /**
     * 验证文件名安全性
     */
    private boolean isValidFileName(String fileName) {
        if (fileName == null || fileName.trim().isEmpty()) {
            return false;
        }
        
        // 检查文件名长度
        if (fileName.length() > 255) {
            return false;
        }
        
        // 检查是否包含非法字符
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\") ||
            fileName.contains(":") || fileName.contains("*") || fileName.contains("?") ||
            fileName.contains("\"") || fileName.contains("<") || fileName.contains(">") ||
            fileName.contains("|")) {
            return false;
        }
        
        // 检查文件扩展名是否在白名单中
        String lowerFileName = fileName.toLowerCase();
        boolean hasValidExtension = ALLOWED_EXTENSIONS.stream()
            .anyMatch(ext -> lowerFileName.endsWith(ext));
        
        return hasValidExtension;
    }
    
    /**
     * 计算文件MD5校验和（用于完整性验证）
     */
    private String calculateMD5(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                md.update(buffer, 0, bytesRead);
            }
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }
    }

    /**
     * 首页路由
     */
    @GetMapping("/")
    public String index() {
        return "redirect:/index.html";
    }

    /**
     * 初始化分片上传
     */
    @PostMapping("/api/upload/init")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> initChunkUpload(
            @RequestParam("fileName") String originalFileName,
            @RequestParam("fileSize") long fileSize,
            @RequestParam("sessionId") String sessionId) {
        
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("message", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        try {
            // 验证参数
            if (!isValidFileName(originalFileName)) {
                response.put("success", false);
                response.put("message", "文件名无效或包含非法字符，仅支持常见文档、图片、音视频和压缩文件格式");
                return ResponseEntity.badRequest().body(response);
            }
            
            if (fileSize <= 0 || fileSize > MAX_FILE_SIZE) {
                response.put("success", false);
                response.put("message", "文件大小无效或超过限制（最大500MB）");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 创建上传目录
            File uploadDir = new File(uploadPath);
            if (!uploadDir.exists()) {
                uploadDir.mkdirs();
            }
            
            // 生成唯一的上传ID
            String uploadId = UUID.randomUUID().toString();
            
            // 计算总分片数
            int totalChunks = (int) Math.ceil((double) fileSize / CHUNK_SIZE);
            
            // 保存上传信息
            ChunkUploadInfo uploadInfo = new ChunkUploadInfo(originalFileName, originalFileName, totalChunks, fileSize);
            chunkUploadMap.put(uploadId, uploadInfo);
            
            response.put("success", true);
            response.put("uploadId", uploadId);
            response.put("chunkSize", CHUNK_SIZE);
            response.put("totalChunks", totalChunks);
            
            System.out.println("初始化分片上传: " + originalFileName + ", 总分片数: " + totalChunks);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "初始化上传失败: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
    
    /**
     * 分片上传
     */
    @PostMapping("/api/upload/chunk")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> uploadChunk(
            @RequestParam("uploadId") String uploadId,
            @RequestParam("chunkIndex") int chunkIndex,
            @RequestParam("chunk") MultipartFile chunk,
            @RequestParam("sessionId") String sessionId) {
        
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("message", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        try {
            // 获取上传信息
            ChunkUploadInfo uploadInfo = chunkUploadMap.get(uploadId);
            if (uploadInfo == null) {
                response.put("success", false);
                response.put("message", "无效的上传ID");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 验证分片
            if (chunk.isEmpty()) {
                response.put("success", false);
                response.put("message", "分片不能为空");
                return ResponseEntity.badRequest().body(response);
            }
            
            if (chunkIndex < 0 || chunkIndex >= uploadInfo.getTotalChunks()) {
                response.put("success", false);
                response.put("message", "无效的分片索引");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 验证分片大小
            if (chunk.getSize() > CHUNK_SIZE + 1024) { // 允许1KB的误差
                response.put("success", false);
                response.put("message", "分片大小超过限制");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 检查是否重复上传
            if (uploadInfo.getUploadedChunks().contains(chunkIndex)) {
                response.put("success", true);
                response.put("message", "分片已存在，跳过上传");
                response.put("chunkIndex", chunkIndex);
                response.put("uploadedChunks", uploadInfo.getUploadedChunks().size());
                response.put("totalChunks", uploadInfo.getTotalChunks());
                response.put("isComplete", uploadInfo.isComplete());
                return ResponseEntity.ok(response);
            }
            
            // 保存分片到临时目录
            String tempDir = uploadPath + "/temp/" + uploadId;
            File tempDirFile = new File(tempDir);
            if (!tempDirFile.exists()) {
                tempDirFile.mkdirs();
            }
            
            String chunkFileName = "chunk_" + chunkIndex;
            Path chunkPath = Paths.get(tempDir, chunkFileName);
            
            // 写入分片数据 - 确保InputStream被正确关闭
            try (InputStream inputStream = chunk.getInputStream()) {
                Files.copy(inputStream, chunkPath, StandardCopyOption.REPLACE_EXISTING);
            }
            
            // 记录已上传的分片
            uploadInfo.getUploadedChunks().add(chunkIndex);
            uploadInfo.setLastUpdateTime(System.currentTimeMillis());
            
            response.put("success", true);
            response.put("chunkIndex", chunkIndex);
            response.put("uploadedChunks", uploadInfo.getUploadedChunks().size());
            response.put("totalChunks", uploadInfo.getTotalChunks());
            response.put("isComplete", uploadInfo.isComplete());
            
            System.out.println("分片上传成功: " + uploadId + ", 分片: " + chunkIndex + "/" + uploadInfo.getTotalChunks());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "分片上传失败: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
    
    /**
     * 合并分片
     */
    @PostMapping("/api/upload/merge")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> mergeChunks(
            @RequestParam("uploadId") String uploadId,
            @RequestParam("sessionId") String sessionId) {
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("message", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        try {
            // 获取上传信息
            ChunkUploadInfo uploadInfo = chunkUploadMap.get(uploadId);
            if (uploadInfo == null) {
                response.put("success", false);
                response.put("message", "无效的上传ID");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 检查是否所有分片都已上传
            if (!uploadInfo.isComplete()) {
                response.put("success", false);
                response.put("message", "还有分片未上传完成");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 合并文件
            String tempDir = uploadPath + "/temp/" + uploadId;
            String finalFileName = uploadInfo.getOriginalName();
            Path finalFilePath = Paths.get(uploadPath, finalFileName);
            
            // 如果文件已存在，添加序号
            int counter = 1;
            while (Files.exists(finalFilePath)) {
                String nameWithoutExt = getFileNameWithoutExtension(uploadInfo.getOriginalName());
                String extension = getFileExtension(uploadInfo.getOriginalName());
                finalFileName = nameWithoutExt + "_" + counter + extension;
                finalFilePath = Paths.get(uploadPath, finalFileName);
                counter++;
            }
            
            // 验证所有分片文件是否存在
            for (int i = 0; i < uploadInfo.getTotalChunks(); i++) {
                Path chunkPath = Paths.get(tempDir, "chunk_" + i);
                if (!Files.exists(chunkPath)) {
                    response.put("success", false);
                    response.put("message", "分片文件缺失: chunk_" + i);
                    return ResponseEntity.badRequest().body(response);
                }
            }
            
            // 创建最终文件并验证大小
            long totalWritten = 0;
            try (FileOutputStream fos = new FileOutputStream(finalFilePath.toFile())) {
                for (int i = 0; i < uploadInfo.getTotalChunks(); i++) {
                    Path chunkPath = Paths.get(tempDir, "chunk_" + i);
                    try (FileInputStream fis = new FileInputStream(chunkPath.toFile())) {
                        byte[] buffer = new byte[8192];
                        int bytesRead;
                        while ((bytesRead = fis.read(buffer)) != -1) {
                            fos.write(buffer, 0, bytesRead);
                            totalWritten += bytesRead;
                        }
                    }
                }
            }
            
            // 验证文件大小
            if (totalWritten != uploadInfo.getFileSize()) {
                // 删除不完整的文件
                Files.deleteIfExists(finalFilePath);
                response.put("success", false);
                response.put("message", "文件大小不匹配，预期: " + uploadInfo.getFileSize() + ", 实际: " + totalWritten);
                return ResponseEntity.badRequest().body(response);
            }
            
            // 计算文件MD5校验和
            String fileMD5 = calculateMD5(finalFilePath.toFile());
            
            // 清理临时文件
            FileUtils.deleteDirectory(new File(tempDir));
            
            // 清理上传信息
            chunkUploadMap.remove(uploadId);
            
            // 记录上传信息
            System.out.println("文件合并成功:");
            System.out.println("  原文件名: " + uploadInfo.getOriginalName());
            System.out.println("  保存文件名: " + finalFileName);
            System.out.println("  文件大小: " + formatFileSize(uploadInfo.getFileSize()));
            System.out.println("  保存路径: " + finalFilePath.toString());
            System.out.println("  上传时间: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
            System.out.println("----------------------------------------");
            
            response.put("success", true);
            response.put("message", "文件上传成功");
            response.put("fileName", finalFileName);
            response.put("originalName", uploadInfo.getOriginalName());
            response.put("fileSize", uploadInfo.getFileSize());
            response.put("filePath", finalFilePath.toString());
            response.put("md5", fileMD5);
            response.put("uploadTime", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "文件合并失败: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
    
    /**
     * 获取上传进度（支持断点续传）
     */
    @GetMapping("/api/upload/progress/{uploadId}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getUploadProgress(
            @PathVariable String uploadId,
            @RequestParam("sessionId") String sessionId) {
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("message", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        ChunkUploadInfo uploadInfo = chunkUploadMap.get(uploadId);
        if (uploadInfo == null) {
            response.put("success", false);
            response.put("message", "无效的上传ID或会话已过期");
            return ResponseEntity.badRequest().body(response);
        }
        
        // 检查会话是否过期
        if (uploadInfo.isExpired()) {
            chunkUploadMap.remove(uploadId);
            response.put("success", false);
            response.put("message", "上传会话已过期，请重新开始上传");
            return ResponseEntity.badRequest().body(response);
        }
        
        double progress = (double) uploadInfo.getUploadedChunks().size() / uploadInfo.getTotalChunks() * 100;
        
        response.put("success", true);
        response.put("uploadedChunks", uploadInfo.getUploadedChunks().size());
        response.put("totalChunks", uploadInfo.getTotalChunks());
        response.put("progress", Math.round(progress * 100.0) / 100.0);
        response.put("isComplete", uploadInfo.isComplete());
        response.put("uploadedChunksList", new ArrayList<>(uploadInfo.getUploadedChunks()));
        response.put("fileName", uploadInfo.getOriginalName());
        response.put("fileSize", uploadInfo.getFileSize());
        response.put("lastUpdateTime", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(uploadInfo.getLastUpdateTime())));
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * 取消上传并清理资源
     */
    @DeleteMapping("/api/upload/cancel/{uploadId}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> cancelUpload(
            @PathVariable String uploadId,
            @RequestParam("sessionId") String sessionId) {
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("message", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        ChunkUploadInfo uploadInfo = chunkUploadMap.remove(uploadId);
        if (uploadInfo == null) {
            response.put("success", false);
            response.put("message", "无效的上传ID");
            return ResponseEntity.badRequest().body(response);
        }
        
        // 清理临时文件
        String tempDir = uploadPath + "/temp/" + uploadId;
        try {
            FileUtils.deleteDirectory(new File(tempDir));
            System.out.println("取消上传并清理临时文件: " + uploadId + ", 文件: " + uploadInfo.getOriginalName());
        } catch (Exception e) {
            System.err.println("清理临时文件失败: " + e.getMessage());
        }
        
        response.put("success", true);
        response.put("message", "上传已取消");
        response.put("fileName", uploadInfo.getOriginalName());
        
        return ResponseEntity.ok(response);
    }

    /**
     * 部署相关接口 - 搜索文件
     */
    @PostMapping("/api/deploy/search-files")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> searchFiles(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        String sessionId = request.get("sessionId");
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("error", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        String sourceDir = request.get("sourceDir");
        String frontendPattern = request.get("frontendPattern");
        String backendPattern = request.get("backendPattern");
        
        if (sourceDir == null || sourceDir.trim().isEmpty()) {
            response.put("success", false);
            response.put("error", "源目录不能为空");
            return ResponseEntity.badRequest().body(response);
        }
        
        if ((frontendPattern == null || frontendPattern.trim().isEmpty()) && 
            (backendPattern == null || backendPattern.trim().isEmpty())) {
            response.put("success", false);
            response.put("error", "前端或后端文件匹配模式至少需要填写一个");
            return ResponseEntity.badRequest().body(response);
        }
        
        try {
            File dir = new File(sourceDir);
            if (!dir.exists() || !dir.isDirectory()) {
                response.put("success", false);
                response.put("error", "源目录不存在或不是有效目录");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 当前时间
            long currentTime = System.currentTimeMillis();
            long tenMinutesAgo = currentTime - (10 * 60 * 1000); // 10分钟前
            
            // 分别处理前端和后端文件
            File apiFile = null; // 后端文件
            File webFile = null; // 前端文件
            List<String> messages = new ArrayList<>();
            
            File[] files = dir.listFiles();
            if (files != null) {
                // 处理后端文件
                if (backendPattern != null && !backendPattern.trim().isEmpty()) {
                    String[] backendPatterns = backendPattern.split(",");
                    for (String pattern : backendPatterns) {
                        String trimmedPattern = pattern.trim();
                        if (trimmedPattern.isEmpty()) continue;
                        
                        // 转换通配符为正则表达式
                        String regex = trimmedPattern.replace("*", ".*").replace("?", ".");
                        java.util.regex.Pattern compiledPattern = java.util.regex.Pattern.compile(regex, java.util.regex.Pattern.CASE_INSENSITIVE);
                        
                        // 查找匹配的文件
                        List<File> matchedFiles = new ArrayList<>();
                        for (File file : files) {
                            if (file.isFile() && compiledPattern.matcher(file.getName()).matches()) {
                                // 检查文件是否在10分钟内
                                if (file.lastModified() >= tenMinutesAgo) {
                                    matchedFiles.add(file);
                                }
                            }
                        }
                        
                        if (matchedFiles.isEmpty()) {
                            // 检查是否有匹配的文件但不在10分钟内
                            boolean hasOldFiles = false;
                            for (File file : files) {
                                if (file.isFile() && compiledPattern.matcher(file.getName()).matches()) {
                                    hasOldFiles = true;
                                    break;
                                }
                            }
                            
                            if (hasOldFiles) {
                                messages.add("后端文件存在但不在10分钟内，未找到最新的后端文件");
                            } else {
                                messages.add("未找到后端文件");
                            }
                            continue;
                        }
                        
                        // 找到最新的文件
                        File latestFile = matchedFiles.get(0);
                        for (File file : matchedFiles) {
                            if (file.lastModified() > latestFile.lastModified()) {
                                latestFile = file;
                            }
                        }
                        
                        // 设置后端文件
                        if (apiFile == null) {
                            // 检查是否为jar文件，如果是则压缩成zip包
                            if (latestFile.getName().toLowerCase().endsWith(".jar")) {
                                try {
                                    File zipFile = compressJarToZip(latestFile);
                                    apiFile = zipFile;
                                    messages.add("找到最新后端文件: " + latestFile.getName() + "，已压缩为: " + zipFile.getName());
                                } catch (Exception e) {
                                    messages.add("压缩jar文件失败: " + e.getMessage());
                                    apiFile = latestFile;
                                    messages.add("找到最新后端文件: " + latestFile.getName());
                                }
                            } else {
                                apiFile = latestFile;
                                messages.add("找到最新后端文件: " + latestFile.getName());
                            }
                        }
                    }
                }
                
                // 处理前端文件
                if (frontendPattern != null && !frontendPattern.trim().isEmpty()) {
                    String[] frontendPatterns = frontendPattern.split(",");
                    for (String pattern : frontendPatterns) {
                        String trimmedPattern = pattern.trim();
                        if (trimmedPattern.isEmpty()) continue;
                        
                        // 转换通配符为正则表达式
                        String regex = trimmedPattern.replace("*", ".*").replace("?", ".");
                        java.util.regex.Pattern compiledPattern = java.util.regex.Pattern.compile(regex, java.util.regex.Pattern.CASE_INSENSITIVE);
                        
                        // 查找匹配的文件
                        List<File> matchedFiles = new ArrayList<>();
                        for (File file : files) {
                            if (file.isFile() && compiledPattern.matcher(file.getName()).matches()) {
                                // 检查文件是否在10分钟内
                                if (file.lastModified() >= tenMinutesAgo) {
                                    matchedFiles.add(file);
                                }
                            }
                        }
                        
                        if (matchedFiles.isEmpty()) {
                            // 检查是否有匹配的文件但不在10分钟内
                            boolean hasOldFiles = false;
                            for (File file : files) {
                                if (file.isFile() && compiledPattern.matcher(file.getName()).matches()) {
                                    hasOldFiles = true;
                                    break;
                                }
                            }
                            
                            if (hasOldFiles) {
                                messages.add("前端文件存在但不在10分钟内，未找到最新的前端文件");
                            } else {
                                messages.add("未找到前端文件");
                            }
                            continue;
                        }
                        
                        // 找到最新的文件
                        File latestFile = matchedFiles.get(0);
                        for (File file : matchedFiles) {
                            if (file.lastModified() > latestFile.lastModified()) {
                                latestFile = file;
                            }
                        }
                        
                        // 设置前端文件
                        if (webFile == null) {
                            webFile = latestFile;
                            messages.add("找到最新前端文件: " + latestFile.getName());
                        }
                    }
                }
            }
            
            // 构建最终结果
            List<String> finalFiles = new ArrayList<>();
            if (apiFile != null) {
                finalFiles.add(apiFile.getAbsolutePath());
            }
            if (webFile != null) {
                finalFiles.add(webFile.getAbsolutePath());
            }
            
            response.put("success", true);
            response.put("files", finalFiles);
            response.put("messages", messages);
            response.put("count", finalFiles.size());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", "搜索文件时发生异常: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
    
    /**
     * 部署相关接口 - 从路径上传文件（使用分片上传）
     */
    @PostMapping("/api/deploy/upload-file")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> uploadFileFromPath(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        String sessionId = request.get("sessionId");
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("error", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        String filePath = request.get("filePath");
        
        if (filePath == null || filePath.trim().isEmpty()) {
            response.put("success", false);
            response.put("error", "文件路径不能为空");
            return ResponseEntity.badRequest().body(response);
        }
        
        try {
            File sourceFile = new File(filePath);
            if (!sourceFile.exists() || !sourceFile.isFile()) {
                response.put("success", false);
                response.put("error", "源文件不存在或不是有效文件");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 检查文件扩展名
            String fileName = sourceFile.getName();
            if (!isValidFileName(fileName)) {
                response.put("success", false);
                response.put("error", "不支持的文件类型");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 检查文件大小
            long fileSize = sourceFile.length();
            if (fileSize > MAX_FILE_SIZE) {
                response.put("success", false);
                response.put("error", "文件大小超过限制 (" + (MAX_FILE_SIZE / 1024 / 1024) + "MB)");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 使用分片上传机制
            String uploadId = UUID.randomUUID().toString();
            int totalChunks = (int) Math.ceil((double) fileSize / CHUNK_SIZE);
            
            // 创建上传信息
            ChunkUploadInfo uploadInfo = new ChunkUploadInfo(fileName, fileName, totalChunks, fileSize);
            chunkUploadMap.put(uploadId, uploadInfo);
            
            // 创建临时目录
            String tempDir = uploadPath + "/temp/" + uploadId;
            File tempDirFile = new File(tempDir);
            if (!tempDirFile.exists()) {
                tempDirFile.mkdirs();
            }
            
            // 分片读取并保存文件
            try (FileInputStream fis = new FileInputStream(sourceFile)) {
                byte[] buffer = new byte[(int) CHUNK_SIZE];
                int chunkIndex = 0;
                int bytesRead;
                
                while ((bytesRead = fis.read(buffer)) > 0) {
                    // 保存分片
                    File chunkFile = new File(tempDir, "chunk_" + chunkIndex);
                    try (FileOutputStream fos = new FileOutputStream(chunkFile)) {
                        fos.write(buffer, 0, bytesRead);
                    }
                    
                    // 标记分片已上传
                    uploadInfo.getUploadedChunks().add(chunkIndex);
                    chunkIndex++;
                }
            }
            
            // 合并文件
            String safeFileName = fileName;
            Path targetPath = Paths.get(uploadPath, safeFileName);
            
            // 如果文件已存在，添加时间戳
            if (Files.exists(targetPath)) {
                String nameWithoutExt = getFileNameWithoutExtension(fileName);
                String ext = getFileExtension(fileName);
                String timestamp = String.valueOf(System.currentTimeMillis());
                safeFileName = nameWithoutExt + "_" + timestamp + ext;
                targetPath = Paths.get(uploadPath, safeFileName);
            }
            
            // 合并分片
            try (FileOutputStream fos = new FileOutputStream(targetPath.toFile())) {
                for (int i = 0; i < totalChunks; i++) {
                    File chunkFile = new File(tempDir, "chunk_" + i);
                    if (chunkFile.exists()) {
                        try (FileInputStream fis = new FileInputStream(chunkFile)) {
                            byte[] buffer = new byte[8192];
                            int bytesRead;
                            while ((bytesRead = fis.read(buffer)) > 0) {
                                fos.write(buffer, 0, bytesRead);
                            }
                        }
                    }
                }
            }
            
            // 清理临时文件
            try {
                FileUtils.deleteDirectory(tempDirFile);
            } catch (Exception e) {
                System.err.println("清理临时文件失败: " + e.getMessage());
            }
            
            // 清理上传信息
            chunkUploadMap.remove(uploadId);
            
            // 计算MD5
            String md5 = calculateMD5(targetPath.toFile());
            
            response.put("success", true);
            response.put("fileName", safeFileName);
            response.put("originalName", fileName);
            response.put("size", fileSize);
            response.put("md5", md5);
            response.put("uploadId", uploadId);
            response.put("totalChunks", totalChunks);
            response.put("message", "文件通过分片上传成功");
            
            System.out.println("部署文件上传成功 (分片): " + safeFileName + ", 分片数: " + totalChunks);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", "上传文件时发生异常: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }



    /**
     * 删除文件
     */
    @DeleteMapping("/api/files/{fileName}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> deleteFile(
            @PathVariable String fileName,
            @RequestParam("sessionId") String sessionId) {
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("message", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        try {
            // 验证文件名
            if (fileName == null || fileName.trim().isEmpty()) {
                response.put("success", false);
                response.put("message", "文件名不能为空");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 防止路径遍历攻击
            if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
                response.put("success", false);
                response.put("message", "无效的文件名");
                return ResponseEntity.badRequest().body(response);
            }
            
            File uploadDir = new File(uploadPath);
            File fileToDelete = new File(uploadDir, fileName);
            
            // 检查文件是否存在
            if (!fileToDelete.exists()) {
                response.put("success", false);
                response.put("message", "文件不存在");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 检查文件是否在上传目录内（安全检查）
            if (!fileToDelete.getCanonicalPath().startsWith(uploadDir.getCanonicalPath())) {
                response.put("success", false);
                response.put("message", "无效的文件路径");
                return ResponseEntity.badRequest().body(response);
            }
            
            // 删除文件
            boolean deleted = fileToDelete.delete();
            
            if (deleted) {
                System.out.println("文件删除成功: " + fileName);
                response.put("success", true);
                response.put("message", "文件删除成功");
                response.put("fileName", fileName);
                return ResponseEntity.ok(response);
            } else {
                response.put("success", false);
                response.put("message", "文件删除失败");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
            }
            
        } catch (Exception e) {
            System.err.println("删除文件异常: " + e.getMessage());
            response.put("success", false);
            response.put("message", "删除文件失败: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 健康检查
     */
    @GetMapping("/api/info")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getUploadInfo() {
        Map<String, Object> info = new HashMap<>();
        
        File uploadDir = new File(uploadPath);
        info.put("uploadPath", uploadPath);
        info.put("exists", uploadDir.exists());
        info.put("canWrite", uploadDir.canWrite());
        
        if (uploadDir.exists()) {
            File[] files = uploadDir.listFiles();
            info.put("fileCount", files != null ? files.length : 0);
        } else {
            info.put("fileCount", 0);
        }
        
        return ResponseEntity.ok(info);
    }
    
    /**
     * 获取上传目录文件列表
     */
    @GetMapping("/api/files")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFileList(
            @RequestParam("sessionId") String sessionId) {
        Map<String, Object> response = new HashMap<>();
        
        // 验证会话
        if (!isValidSession(sessionId)) {
            response.put("success", false);
            response.put("message", "会话无效或已过期");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        
        try {
            File uploadDir = new File(uploadPath);
            
            if (!uploadDir.exists()) {
                response.put("success", false);
                response.put("message", "上传目录不存在");
                response.put("files", new ArrayList<>());
                return ResponseEntity.ok(response);
            }
            
            File[] files = uploadDir.listFiles();
            List<Map<String, Object>> fileList = new ArrayList<>();
            
            if (files != null) {
                for (File file : files) {
                    if (file.isFile()) {
                        Map<String, Object> fileInfo = new HashMap<>();
                        fileInfo.put("name", file.getName());
                        fileInfo.put("size", file.length());
                        fileInfo.put("sizeFormatted", formatFileSize(file.length()));
                        fileInfo.put("lastModified", file.lastModified());
                        fileInfo.put("lastModifiedFormatted", 
                            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(file.lastModified())));
                        fileList.add(fileInfo);
                    }
                }
                
                // 按修改时间倒序排列
                fileList.sort((a, b) -> Long.compare((Long)b.get("lastModified"), (Long)a.get("lastModified")));
            }
            
            response.put("success", true);
            response.put("files", fileList);
            response.put("totalFiles", fileList.size());
            response.put("uploadPath", uploadPath);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "获取文件列表失败: " + e.getMessage());
            response.put("files", new ArrayList<>());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 分片下载文件（支持Range请求）
     */
    @GetMapping("/api/files/{fileName}/download")
    public ResponseEntity<Resource> downloadFile(
            @PathVariable String fileName,
            @RequestHeader(value = "Range", required = false) String rangeHeader,
            @RequestParam("sessionId") String sessionId) {
        try {
            // 验证会话
            if (sessionId == null || !isValidSession(sessionId)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            // 验证文件名
            if (fileName == null || fileName.trim().isEmpty()) {
                return ResponseEntity.badRequest().build();
            }
            
            // 防止路径遍历攻击
            if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
                return ResponseEntity.badRequest().build();
            }
            
            // 安全检查：只允许下载zip文件
            if (!fileName.toLowerCase().endsWith(".zip")) {
                return ResponseEntity.badRequest().build();
            }
            
            File uploadDir = new File(uploadPath);
            File file = new File(uploadDir, fileName);
            
            // 检查文件是否存在
            if (!file.exists() || !file.isFile()) {
                return ResponseEntity.notFound().build();
            }
            
            // 检查文件是否在上传目录内（安全检查）
            if (!file.getCanonicalPath().startsWith(uploadDir.getCanonicalPath())) {
                return ResponseEntity.badRequest().build();
            }
            
            long fileLength = file.length();
            
            // 处理Range请求（分片下载）
            if (rangeHeader != null && rangeHeader.startsWith("bytes=")) {
                return handleRangeRequest(file, rangeHeader, fileName);
            }
            
            // 普通下载
            Resource resource = new FileSystemResource(file);
            
            System.out.println("文件下载: " + fileName + ", 大小: " + fileLength + " bytes");
            
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                    .header(HttpHeaders.ACCEPT_RANGES, "bytes")
                    .contentLength(fileLength)
                    .body(resource);
                    
        } catch (Exception e) {
            System.err.println("下载文件异常: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * 处理Range请求（分片下载）
     */
    private ResponseEntity<Resource> handleRangeRequest(File file, String rangeHeader, String fileName) {
        try {
            long fileLength = file.length();
            
            // 解析Range头
            String range = rangeHeader.substring(6); // 移除"bytes="
            String[] ranges = range.split("-");
            
            long start = 0;
            long end = fileLength - 1;
            
            if (ranges.length >= 1 && !ranges[0].isEmpty()) {
                start = Long.parseLong(ranges[0]);
            }
            
            if (ranges.length >= 2 && !ranges[1].isEmpty()) {
                end = Long.parseLong(ranges[1]);
            }
            
            // 验证范围
            if (start < 0 || end >= fileLength || start > end) {
                return ResponseEntity.status(HttpStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                        .header(HttpHeaders.CONTENT_RANGE, "bytes */" + fileLength)
                        .build();
            }
            
            final long contentLength = end - start + 1;
            final long finalStart = start;
            
            // 创建分片资源
            Resource resource = new FileSystemResource(file) {
                private static final long serialVersionUID = 1L;
                
                @Override
                public InputStream getInputStream() throws IOException {
                    FileInputStream fis = new FileInputStream(file);
                    try {
                        // 使用更可靠的方式跳过字节
                        long skipped = 0;
                        while (skipped < finalStart) {
                            long n = fis.skip(finalStart - skipped);
                            if (n == 0) {
                                // 如果skip返回0，使用read方法跳过
                                if (fis.read() == -1) {
                                    break;
                                }
                                skipped++;
                            } else {
                                skipped += n;
                            }
                        }
                        return new BoundedInputStream(fis, contentLength);
                    } catch (IOException e) {
                        fis.close();
                        throw e;
                    }
                }
            };
            
            System.out.println("分片下载: " + fileName + ", 范围: " + start + "-" + end + "/" + fileLength);
            
            return ResponseEntity.status(HttpStatus.PARTIAL_CONTENT)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                    .header(HttpHeaders.ACCEPT_RANGES, "bytes")
                    .header(HttpHeaders.CONTENT_RANGE, "bytes " + start + "-" + end + "/" + fileLength)
                    .contentLength(contentLength)
                    .body(resource);
                    
        } catch (Exception e) {
            System.err.println("分片下载异常: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * 限制输入流读取字节数的包装类
     */
    private static class BoundedInputStream extends InputStream {
        private final InputStream inputStream;
        private long remaining;
        
        public BoundedInputStream(InputStream inputStream, long maxBytes) {
            this.inputStream = inputStream;
            this.remaining = maxBytes;
        }
        
        @Override
        public int read() throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            int result = inputStream.read();
            if (result != -1) {
                remaining--;
            }
            return result;
        }
        
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            int toRead = (int) Math.min(len, remaining);
            int result = inputStream.read(b, off, toRead);
            if (result > 0) {
                remaining -= result;
            }
            return result;
        }
        
        @Override
        public void close() throws IOException {
            inputStream.close();
        }
    }

    /**
     * 健康检查
     */
    @GetMapping("/api/health")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("timestamp", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        health.put("service", "File Upload Service");
        return ResponseEntity.ok(health);
    }

    /**
     * 获取目标目录路径
     */
    @GetMapping("/api/target-directory")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getTargetDirectory() {
        Map<String, Object> response = new HashMap<>();
        response.put("targetPath", targetPath);
        response.put("uploadPath", uploadPath);
        return ResponseEntity.ok(response);
    }

    /**
     * 格式化文件大小
     */
    private String formatFileSize(long bytes) {
        if (bytes == 0) return "0 B";
        
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        int unitIndex = 0;
        double size = bytes;
        
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        
        return String.format("%.2f %s", size, units[unitIndex]);
    }
    
    /**
     * 获取文件名（不含扩展名）
     */
    private String getFileNameWithoutExtension(String fileName) {
        int lastDotIndex = fileName.lastIndexOf('.');
        if (lastDotIndex > 0) {
            return fileName.substring(0, lastDotIndex);
        }
        return fileName;
    }
    
    /**
     * 获取文件扩展名
     */
    private String getFileExtension(String fileName) {
        int lastDotIndex = fileName.lastIndexOf('.');
        if (lastDotIndex > 0 && lastDotIndex < fileName.length() - 1) {
            return fileName.substring(lastDotIndex);
        }
        return "";
    }

    /**
     * 将jar文件压缩成zip包
     */
    private File compressJarToZip(File jarFile) throws IOException {
        // 生成zip文件名
        String jarFileName = jarFile.getName();
        String zipFileName = jarFileName.substring(0, jarFileName.lastIndexOf('.')) + ".zip";
        File zipFile = new File(jarFile.getParent(), zipFileName);
        
        // 如果zip文件已存在，先删除
        if (zipFile.exists()) {
            zipFile.delete();
        }
        
        // 创建zip文件
        try (FileOutputStream fos = new FileOutputStream(zipFile);
             ZipOutputStream zos = new ZipOutputStream(fos);
             FileInputStream fis = new FileInputStream(jarFile)) {
            
            // 添加jar文件到zip中
            ZipEntry zipEntry = new ZipEntry(jarFileName);
            zos.putNextEntry(zipEntry);
            
            // 复制文件内容
            byte[] buffer = new byte[1024];
            int length;
            while ((length = fis.read(buffer)) > 0) {
                zos.write(buffer, 0, length);
            }
            
            zos.closeEntry();
        }
        
        return zipFile;
    }

    /**
     * 全局异常处理
     */
    @ExceptionHandler(Exception.class)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> handleException(Exception e) {
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("message", "服务器内部错误: " + e.getMessage());
        
        System.err.println("服务器异常: " + e.getMessage());
        e.printStackTrace();
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}