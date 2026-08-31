package net.xzh.iam.access.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.access.service.EndpointPolicyService;

/**
 * 接口准入点扫描播种初始化器 (幂等, 表结构由基线 SQL / 迁移脚本就绪).
 * <p>
 * 按 controller 分包 + RequestMapping 推导每个端点的默认准入规则补种进 iam_endpoint_policy
 * (source=coded), 已存在的行 (含管理端 override) 不覆盖; 完成后刷新准入路由内存快照。
 * </p>
 * <p>
 * 说明: 这是全平台唯一保留的 ApplicationRunner 初始化器——它不产生"业务数据", 而是把
 * 活代码的 controller 分包/映射实时推导成准入目录 (deny-by-default 依赖它保持与代码同步)。
 * </p>
 */
@Slf4j
@Order(3)
@Component
public class EndpointPolicyScanInitializer implements ApplicationRunner {

    private final EndpointPolicyService endpointPolicyService;

    public EndpointPolicyScanInitializer(EndpointPolicyService endpointPolicyService) {
        this.endpointPolicyService = endpointPolicyService;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            endpointPolicyService.rescan();
            log.info("[EndpointPolicyScan] 准入点扫描播种初始化完成");
        } catch (Exception e) {
            log.error("[EndpointPolicyScan] 扫描播种失败: {}", e.getMessage(), e);
        }
    }
}