package net.xzh.iam.auth.security.web;

import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * OIDC 动态客户端注册 (DCR, RFC 7591/7592) 端点拒绝过滤器.
 *
 * <p>平台客户端注册唯一通道 = 管理端「客户端管理」页（有人审、有准入表联动），
 * 不提供任何自助注册 —— 这是「未配置即拒绝」allow-list 哲学在客户端维度的落地。</p>
 *
 * <p>本过滤器挂在<b>协议链最前</b>（SecurityContextHolderFilter 之前），对配置路径
 * {@code /oauth2/connect/register} 的任意 HTTP 方法直接返回 404。</p>
 *
 * <p><b>关于框架默认路径 {@code /connect/register}：</b>该路径不在任何安全链的
 * securityMatcher 范围内（协议链仅覆盖 {@code /oauth2/**} 等），请求不会进入本过滤器；
 * 当前它返回 404 的原因是「无安全链匹配 + 无 MVC 路由」，属自然结果而非本过滤器拦截。
 * 下方 {@code DEFAULT_PATH} 判断保留为<b>未来协议链 securityMatcher 扩展时的保险</b>：
 * 一旦协议链开始覆盖该路径，本过滤器即可立即生效（其他链覆盖不经过本过滤器）。</p>
 *
 * <p><b>为什么不能只删 permitAll：</b> SAS 端点过滤器注册在 {@code AuthorizationFilter}
 * <b>之后</b>（字节码 {@code addFilterAfter(AuthorizationFilter)}，注册/令牌/内省/撤销端点
 * 均如此）。删 permitAll 后匿名请求在授权层即被挡下、到不了端点过滤器——这一步有效；
 * 但<b>已登录会话</b>仍能通过 {@code authenticated()} 穿过授权层进入注册过滤器。
 * 本过滤器位于 {@code SecurityContextHolderFilter} 之前，早于 CSRF、授权判定与
 * 全部 SAS 端点过滤器，无论装配状态与会话状态一律拦截。</p>
 *
 * <p>装配状态由框架决定（未来任何一行代码即可启用），删除配置属依赖"某物不存在"的
 * 负向防御，会随时间失效；本过滤器是持续的正向拒绝。</p>
 *
 * <p>404 响应体模仿 Spring Boot 默认错误格式，使端点在探测下不可区分于"从未存在"。</p>
 */
@Slf4j
public final class ClientRegistrationDenyFilter extends OncePerRequestFilter {

    /** 配置路径 + 框架默认路径 —— 双路径判断; 后者当前不在本链 securityMatcher 内, 作未来扩展保险 */
    private static final String CONFIGURED_PATH = "/oauth2/connect/register";
    private static final String DEFAULT_PATH = "/connect/register";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 剥离 context-path 后比较 (本服务 context-path 为 /, 但保持通用)
        String path = request.getRequestURI();
        String ctx = request.getContextPath();
        if (ctx != null && !ctx.isEmpty() && path.startsWith(ctx)) {
            path = path.substring(ctx.length());
        }
        if (CONFIGURED_PATH.equals(path) || DEFAULT_PATH.equals(path)) {
            log.debug("[DCR拒绝] 动态客户端注册端点已关闭: {} {} -> 404", request.getMethod(), path);
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            // 模仿 Spring Boot 默认 404 错误体，探测者无法区分「被拒绝」与「不存在」
            response.getWriter().write(
                    "{\"timestamp\":\"" + java.time.Instant.now() + "\",\"status\":404,"
                            + "\"error\":\"Not Found\",\"path\":\"" + path + "\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
