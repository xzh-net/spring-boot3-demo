package net.xzh.iam.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * scope ↔ 权限码 N:N 映射实体 (sys_scope_permission).
 * <p>
 * 对标用户维度的 sys_role_permission: 粗组 (scope) 展开为细码 (sys_permission)。
 * 只读字典, 增删改走 SQL 种子。
 * </p>
 */
@Data
@TableName("sys_scope_permission")
public class SysScopePermission {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** → sys_scope.id */
    private Long scopeId;

    /** → sys_permission.id */
    private Long permissionId;
}
