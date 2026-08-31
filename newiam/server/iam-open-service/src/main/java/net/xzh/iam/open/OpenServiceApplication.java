package net.xzh.iam.open;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 开放平台 (iam-open-service).
 * <p>
 * 定位: 对外卖的能力目录 (iam_api_capability) + 订阅 (iam_capability_subscription),
 * 独占 iam_open 库。token 签发复用认证中心, API 实现由各业务方提供。
 */
@SpringBootApplication
public class OpenServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(OpenServiceApplication.class, args);
    }
}
