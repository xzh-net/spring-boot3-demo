package net.xzh.iam.resource.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.service.EndpointPolicyService;

/**
 * 接口准入配置漂移告警初始化器 (表结构由基线 SQL / 迁移脚本就绪).
 * <p>
 * 启动时推导白名单域接口清单与 iam_endpoint 资源行比对, 打印缺行 / 幽灵行 / 绑定缺失 / 权限不可解析告警。
 * <b>只告警不拦截</b> (D1 裁定: 配置完整性属运维职责, 程序不以拒绝启动强制; 运行期规则每请求直查 DB,
 * 本初始化器不加载、不驻留任何内存态)。
 * </p>
 * <p>
 * 说明: 这是全平台唯一保留的 ApplicationRunner 初始化器——它不产生"业务数据", 只做启动一致性
 * 可见性提示 (端点即权限, 与代码同步依赖它)。
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
        // 不抛异常: 配置漂移仅告警, 不影响启动 (Fail-Closed 由每请求准入路由器兜底)
        endpointPolicyService.warnConfigDrift();
        log.info("[EndpointPolicyScan] 启动配置漂移检查完成 (仅告警, 不影响启动)");
    }
}
