package net.xzh.iam.auth.vo;

import java.util.List;

import lombok.Data;

/**
 * SSO 会话视图 (层级模型的中间层).
 * <p>
 * 一个 SSO 会话对应认证中心的一个 HttpSession, 其下可挂载多个 ClientSession.
 */
@Data
public class SsoSessionVO {

    /** SSO HttpSession ID */
    private String sessionId;
    /** 用户名 */
    private String principalName;
    /** 登录时间 */
    private String loginTime;
    /** 最近访问时间 */
    private String lastAccessTime;
    /** 是否已过期 (被管理员标记踢下线) */
    private boolean expired;
    /** 该 SSO 会话下的客户端会话列表 */
    private List<ClientSessionVO> clientSessions;
}
