package net.xzh.iam.access.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 资源接口准入策略实体 (iam_authorization.iam_endpoint_policy).
 * <p>
 * 取代 ResourceServerConfig 中写死的 security 规则: 启动时按 controller 分包扫描 RequestMapping
 * 播种 (source=coded, 默认规则), 管理端可覆盖为 override; 准入路由器读内存快照裁决,
 * 未登记路径按默认拒绝 (deny-by-default).
 * </p>
 */
@Data
@TableName("iam_endpoint_policy")
public class IamEndpointPolicy {

    /** 能力域: admin=管理端/portal=门户/capability=开放能力/internal=服务间内部/other=其他 */
    public static final String DOMAIN_ADMIN = "admin";
    public static final String DOMAIN_PORTAL = "portal";
    public static final String DOMAIN_CAPABILITY = "capability";
    public static final String DOMAIN_INTERNAL = "internal";
    public static final String DOMAIN_OTHER = "other";

    /** 准入要求常量 (令牌类别: ADMIN_SERVICE_TOKEN=管理服务凭证 / PORTAL_SERVICE_TOKEN=门户服务凭证) */
    public static final String AUTH_PERMIT_ALL = "PERMIT_ALL";
    public static final String AUTH_AUTHENTICATED = "AUTHENTICATED";
    public static final String AUTH_CAPABILITY = "CAPABILITY";
    public static final String AUTH_ADMIN_SERVICE_TOKEN = "ADMIN_SERVICE_TOKEN";
    public static final String AUTH_PORTAL_SERVICE_TOKEN = "PORTAL_SERVICE_TOKEN";

    /** 来源: coded=启动扫描默认 / override=管理端覆盖 */
    public static final String SOURCE_CODED = "coded";
    public static final String SOURCE_OVERRIDE = "override";

    @TableId(type = IdType.AUTO)
    private Long id;

    private String domain;

    /** HTTP 方法: GET/POST/PUT/DELETE (ANY=全部) */
    private String method;

    /** 路径模式 (Spring 注册模式, 如 /api/admin/permissions/{id}) */
    private String path;

    /** 准入要求: PERMIT_ALL / AUTHENTICATED / ADMIN_SERVICE_TOKEN 管理服务凭证 / PORTAL_SERVICE_TOKEN 门户服务凭证 / CAPABILITY */
    private String requiredAuthority;

    /** 来源: coded / override */
    private String source;

    /** 状态: 1=启用, 0=禁用 */
    private Integer status;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}