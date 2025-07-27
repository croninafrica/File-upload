package com.fileupload;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class FileUploadApplication {

    public static void main(String[] args) {
        SpringApplication.run(FileUploadApplication.class, args);
        System.out.println("\n============================================");
        System.out.println("文件上传服务已启动！");
        System.out.println("访问地址: http://localhost:8080");
        System.out.println("上传API: http://localhost:8080/api/upload");
        System.out.println("===========================================\n");
    }
}