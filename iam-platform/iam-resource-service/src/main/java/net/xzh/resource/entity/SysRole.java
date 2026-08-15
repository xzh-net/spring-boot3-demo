package net.xzh.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 角色实体 (iam_authorization.sys_role).
 */
@Data
@TableName("sys_role")
public class SysRole {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String code;

    private String name;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;

    /** 非表字段: 角色绑定的权限 ID 集合 (更新/展示用) */
    @TableField(exist = false)
    private List<Long> permissionIds;
}