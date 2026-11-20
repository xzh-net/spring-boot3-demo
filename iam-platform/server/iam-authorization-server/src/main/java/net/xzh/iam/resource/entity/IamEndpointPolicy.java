package net.xzh.iam.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 资源接口准入策略实体 (iam_endpoint, 纯资源行).
 * <p>
 * 每行 = 一个资源接口准入点: (service_key, method, path) 唯一 (uk_endpoint)。
 * <p>P0-2 演进: policy_type 显式声明裁决档 —— PERMISSION 行的具体权限码在绑定表
 * iam_endpoint_permission (1..N, 组合语义 permission_logic: ALL=同时具备 / ANY=任一即可);
 * 档位行 (AUTHENTICATED / PERMIT_ALL) 无绑定。service_key = 服务命名空间 (多服务共表预留,
 * 单体固定 iam-authorization-server)。</p>
 * status=0 表示停用, 准入裁决直接拒绝 (deny)。
 * 写入通道: 种子初始化 + 管理页面维护 (资源与绑定两表同一事务提交)。
 */
@Data
@TableName("iam_endpoint")
public class IamEndpointPolicy {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** HTTP 方法: GET/POST/PUT/DELETE (ANY=全部) */
    private String method;

    /** 路径模式 (Spring 注册模式, 如 /admin/users/{id}) */
    private String path;

    /** 服务命名空间 (多服务共表预留, 单体固定 iam-authorization-server) */
    private String serviceKey;

    /** 策略类型: PERMISSION=需要权限码(见绑定表) / AUTHENTICATED=持有效令牌即可 / PERMIT_ALL=全放行 */
    private String policyType;

    /** 组合语义: ALL=全部满足 / ANY=任一满足 (仅 PERMISSION 行有意义, 默认 ALL) */
    private String permissionLogic;

    /** 状态: 1=启用, 0=停用(准入拒绝) */
    private Integer status;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;

    /**
     * 所需权限码 id 集合 (非表字段, 随新增/编辑请求传输, 保存时事务写入绑定表)。
     * PERMISSION 行必填 ≥1; 档位行忽略。
     */
    @TableField(exist = false)
    private List<Long> permissionIds;
}
