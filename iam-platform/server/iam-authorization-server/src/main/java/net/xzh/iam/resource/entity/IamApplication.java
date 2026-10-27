package net.xzh.iam.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 应用实体 (iam_application).
 * <p>门户展示单元, 1 个应用 → N 个渠道。</p>
 */
@Data
@TableName("iam_application")
public class IamApplication {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String appCode;

    private String appName;

    private String icon;

    private String description;

    private Integer sort;

    /** 门户可见性: 1=全部可见(无需授权), 0=仅授权可见 */
    private Integer visible;

    /** 状态: 1=启用, 0=禁用 */
    private Integer status;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;

    /** 非表字段: 应用下的渠道集合 (展示用) */
    @TableField(exist = false)
    private List<IamApplicationChannel> channels;
}
