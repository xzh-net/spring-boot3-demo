package net.xzh.iam.auth.vo;

import java.util.List;

import lombok.Data;

/**
 * 统一在线用户视图 (User → SSO Session → Client Session 层级模型的最外层).
 */
@Data
public class OnlineUserVO {

    /** 用户 ID (sys_user.id) */
    private Long userId;
    /** 登录账号 (sys_user.username, 如 admin/user — 前端展示用) */
    private String username;
    /** 业务用户编码 user_code (u_xxx — 会话/令牌撤销类 API 的 principal 参数) */
    private String userCode;
    /** 昵称 */
    private String nickname;
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
