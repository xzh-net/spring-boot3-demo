package net.xzh.iam.access.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * 用户-角色关联实体 (iam_authorization.sys_user_role).
 * <p>V6.2: user_id → user_code (业务用户编码), 不再依赖影子用户表 sys_user。</p>
 */
@Data
@TableName("sys_user_role")
public class SysUserRole {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 业务用户编码 (关联 iam_identity.sys_user.user_code, 权威在认证中心) */
    private String userCode;

    private Long roleId;
}