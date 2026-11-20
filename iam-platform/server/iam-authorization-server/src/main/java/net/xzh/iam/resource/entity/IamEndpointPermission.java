package net.xzh.iam.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * 端点↔权限绑定实体 (iam_endpoint_permission).
 * <p>
 * 仅 policy_type=PERMISSION 的资源行产生绑定 (一端点可绑 1..N 个权限码, 组合语义见
 * iam_endpoint.permission_logic: ALL=同时具备 / ANY=任一即可); 档位行 (AUTHENTICATED/PERMIT_ALL)
 * 无绑定。endpoint_id ON DELETE CASCADE (删资源行自动清绑定), permission_id ON DELETE RESTRICT。
 * </p>
 */
@Data
@TableName("iam_endpoint_permission")
public class IamEndpointPermission {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** → iam_endpoint.id (资源行) */
    private Long endpointId;

    /** → sys_permission.id (所需权限码) */
    private Long permissionId;
}
