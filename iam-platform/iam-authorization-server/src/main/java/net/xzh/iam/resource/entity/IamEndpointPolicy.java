package net.xzh.iam.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 资源接口准入策略实体 (iam_endpoint_policy).
 * <p>
 * 每行 = 一个资源接口准入点: (method, path) 唯一 (uk_endpoint)。
 * required_authority: 粗档常量 (AUTHENTICATED / ADMIN_SERVICE_TOKEN / PORTAL_SERVICE_TOKEN)
 * 或权限码 (如 user:read, 与 sys_permission.code 字典联动, 按码强控制)。
 * 来源 coded=启动扫描播种 (rescan 对齐/剪除) / override=管理端覆盖 (rescan 跳过)。
 * status=0 表示停用, 准入裁决直接拒绝 (deny)。
 * </p>
 */
@Data
@TableName("iam_endpoint_policy")
public class IamEndpointPolicy {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 能力域: admin=管理端 / portal=门户 (permitall 走链层放行, 不入表) */
    private String domain;

    /** HTTP 方法: GET/POST/PUT/DELETE (ANY=全部) */
    private String method;

    /** 路径模式 (Spring 注册模式, 如 /api/admin/permissions/{id}) */
    private String path;

    /** 准入要求: 权限码(如 user:read)或粗档(AUTHENTICATED/ADMIN_SERVICE_TOKEN/PORTAL_SERVICE_TOKEN) */
    private String requiredAuthority;

    /** 来源: coded=启动扫描播种 / override=管理端覆盖 */
    private String source;

    /** 状态: 1=启用, 0=停用(准入拒绝) */
    private Integer status;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
