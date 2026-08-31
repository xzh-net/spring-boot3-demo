package net.xzh.iam.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * API 网关 (iam-gateway).
 * <p>
 * 外部流量的唯一受控入口。本期仅挂开放路由组 (/api/open/** → iam-open-service),
 * 后续验签、限流、计量埋点、审计均挂载于此。内部流量 (BFF ↔ 服务) 暂不走网关,
 * 由信任内网直连 (见迁移评估报告"内外分流"章节)。
 */
@SpringBootApplication
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
