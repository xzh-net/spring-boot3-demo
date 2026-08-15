package net.xzh.authserver.vo;

import java.util.List;

import lombok.Data;

/**
 * 统一在线用户视图 (User → SSO Session → Client Session 层级模型的最外层).
 */
@Data
public class OnlineUserVO {

    /** 用户 ID (sys_user.id) */
    private Long userId;
    /** 用户名 */
    private String username;
    /** 昵称 */
    private String nickname;
    /** 业务标签: admin=管理端, client=客户端, wechat=微信端 (仅展示/审计) */
    private String userLabel;
    /** 是否启用 */
    private Boolean enabled;
    /** SSO 会话数 (HttpSession) */
    private int ssoSessionCount;
    /** 客户端会话数 (OAuth2Authorization) */
    private int clientSessionCount;
    /** 最近访问时间 */
    private String lastAccessTime;
    /** 涉及的客户端名称列表 */
    private List<String> clients;
}
