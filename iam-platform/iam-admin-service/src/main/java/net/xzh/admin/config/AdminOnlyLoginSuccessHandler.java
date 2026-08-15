package net.xzh.admin.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * 管理后台登录成功处理器（单纯跳转）。
 * <p>
 * 管理后台的"仅管理员可登录"准入已前移到认证中心：令牌签发准入策略
 * （{@code authserver.client-identity-policy.admin-app: [1]}）只允许管理端
 * (identity_type=1, ROLE_ADMIN) 用户在 admin-app 客户端换取令牌，非管理端在
 * 换 token 阶段即被拒绝（与密码错误一致的登录报错）。因此本服务到达此处理器
 * 的一定是管理端账号，此处仅负责登录成功跳转到 iam-admin-web 首页。
 * <p>
 * 原基于 roles 的准入判断与认证中心策略重复且不可达，已移除；登出流程见
 * {@link net.xzh.admin.controller.AuthLogoutController}。
 */
@Slf4j
@Component
public class AdminOnlyLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final String adminWebUrl;

    public AdminOnlyLoginSuccessHandler(@Value("${iam.admin-web-url}") String adminWebUrl) {
        this.adminWebUrl = adminWebUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException {
        log.debug("[login] 管理端账号 {} 登录成功", authentication.getName());
        response.sendRedirect(adminWebUrl + "/");
    }
}