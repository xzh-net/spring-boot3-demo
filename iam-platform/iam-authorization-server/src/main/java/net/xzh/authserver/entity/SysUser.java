package net.xzh.authserver.entity;

import java.time.LocalDateTime;
import java.util.List;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

@Data
@TableName("sys_user")
public class SysUser {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 业务用户编码 (对外/下放引用, 内部主键不下放) */
    private String userCode;

    private String username;

    private String password;

    private String nickname;

    private String email;

    private String phone;

    private String avatar;

    /** 业务标签 (仅展示/审计, 不参与准入判定): admin=管理端, client=客户端, wechat=微信端 */
    private String userLabel;

    private Boolean enabled;

    private Boolean accountNonExpired;

    private Boolean accountNonLocked;

    private Boolean credentialsNonExpired;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;

    /** 非表字段: 创建/编辑时选中的租户 ID 列表 (写 iam_tenant_user) */
    @TableField(exist = false)
    private List<Long> tenantIds;
}
