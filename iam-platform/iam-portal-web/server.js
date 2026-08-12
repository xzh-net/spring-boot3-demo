/**
 * 门户前端应用 (iam-portal-web)
 * ------------------------------------
 * 纯前端服务, 不持有 client_secret, 通过调用 iam-portal-service (8080) 后端 API 获取:
 *   1. 用户登录状态和用户信息  → GET /api/user/me  (代理到 8080)
 *   2. 可用客户端列表          → GET /api/clients  (代理到 8080)
 *   3. 登录跳转               → 302 到 8080 的 OAuth2 登录
 *   4. 登出                   → 302 到 8080 的 OAuth2 登出
 *
 * 启动: node server.js
 * 端口: 8000  (零依赖, 仅用 Node.js 内置 http 模块)
 */

const http = require('http');
const url = require('url');

const PORT = 8000;
const PORTAL_SERVER = 'http://localhost:8080';
const AUTH_SERVER = 'http://localhost:9000';

// ============================================================
// 工具函数
// ============================================================

function esc(str) {
    return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** 发起 HTTP 请求 (Promise) */
function request(options, body, timeoutMs) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ statusCode: res.statusCode, body: data, headers: res.headers }));
        });
        req.on('error', reject);
        if (timeoutMs && timeoutMs > 0) {
            const timer = setTimeout(() => req.destroy(new Error(`请求超时 (${timeoutMs}ms)`)), timeoutMs);
            req.on('close', () => clearTimeout(timer));
        }
        if (body) req.write(body);
        req.end();
    });
}

/** 从请求中提取 Cookie 值 */
function getCookie(req, name) {
    const cookies = req.headers.cookie;
    if (!cookies) return null;
    const match = cookies.match(new RegExp(`${name}=([^;]+)`));
    return match ? match[1] : null;
}

/** 代理请求到 iam-portal-service (8080), 透传 Cookie */
async function proxyToPortalServer(pathname, req, method = 'GET') {
    const sessionId = getCookie(req, 'PORTAL_SERVER_SESSION');
    const options = {
        hostname: 'localhost',
        port: 8080,
        path: pathname,
        method: method,
        headers: { 'Content-Type': 'application/json' }
    };
    if (sessionId) {
        options.headers['Cookie'] = `PORTAL_SERVER_SESSION=${sessionId}`;
    }
    return await request(options, null, 5000);
}

// ============================================================
// 页面布局
// ============================================================

function layout(title, content, isLoggedIn = false) {
    const logoutBtn = isLoggedIn
        ? '<a href="/logout" style="background:rgba(255,255,255,0.2);color:#fff;border:1px solid rgba(255,255,255,0.35);padding:6px 16px;border-radius:6px;text-decoration:none;font-size:13px;">退出登录</a>'
        : '';
    const loginBtn = !isLoggedIn
        ? '<a href="/login" style="background:rgba(255,255,255,0.2);color:#fff;border:1px solid rgba(255,255,255,0.35);padding:6px 16px;border-radius:6px;text-decoration:none;font-size:13px;">登录</a>'
        : '';
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${esc(title)}</title>
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; background: #f1f5f9; color: #0f172a; min-height: 100vh; }
        .navbar { background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); color: #fff; padding: 0 32px; height: 60px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 2px 12px rgba(37,99,235,0.2); position: sticky; top: 0; z-index: 100; }
        .navbar .brand { font-size: 18px; font-weight: 700; }
        .navbar .nav-right { display: flex; align-items: center; gap: 16px; font-size: 14px; }
        .navbar .user-info { opacity: 0.9; }
        .container { max-width: 1100px; margin: 0 auto; padding: 40px 24px 60px; }
        .page-title { margin-bottom: 32px; }
        .page-title h2 { font-size: 24px; margin-bottom: 6px; }
        .page-title p { color: #64748b; font-size: 14px; }
        .client-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
        .client-card { background: #fff; border-radius: 12px; padding: 28px 24px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); transition: transform 0.2s, box-shadow 0.2s; cursor: pointer; text-decoration: none; color: inherit; display: block; }
        .client-card:hover { transform: translateY(-3px); box-shadow: 0 6px 24px rgba(0,0,0,0.12); }
        .client-card .icon { font-size: 36px; margin-bottom: 12px; }
        .client-card h3 { font-size: 16px; margin-bottom: 6px; }
        .client-card p { color: #64748b; font-size: 13px; line-height: 1.6; }
        .client-card .meta { margin-top: 12px; font-size: 12px; color: #94a3b8; }
        .login-card { background: #fff; border-radius: 12px; padding: 48px 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); text-align: center; max-width: 420px; margin: 80px auto; }
        .login-card h2 { font-size: 22px; margin-bottom: 12px; }
        .login-card p { color: #64748b; margin-bottom: 24px; }
        .login-card .btn { display: inline-block; background: linear-gradient(135deg, #2563eb, #1d4ed8); color: #fff; padding: 12px 36px; border-radius: 8px; text-decoration: none; font-size: 15px; font-weight: 500; }
        .login-card .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 14px rgba(37,99,235,0.35); }
        .empty { text-align: center; padding: 60px 20px; color: #94a3b8; }
        .loading { text-align: center; padding: 40px; color: #64748b; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="brand">🔐 统一认证门户</div>
        <div class="nav-right">
            ${isLoggedIn ? '<span class="user-info" id="userInfo"></span>' : ''}
            ${loginBtn}${logoutBtn}
        </div>
    </div>
    <div class="container">${content}</div>
    <script>
        // 异步加载用户信息
        (async () => {
            try {
                const res = await fetch('/api/user/me', { credentials: 'include' });
                if (res.ok) {
                    const data = await res.json();
                    if (data.authenticated) {
                        const el = document.getElementById('userInfo');
                        if (el) el.textContent = '👤 ' + (data.username || data.subject);
                    }
                }
            } catch (e) { console.warn('获取用户信息失败:', e); }
        })();
    </script>
</body>
</html>`;
}

// ============================================================
// 路由处理
// ============================================================

/** 首页 / 门户主页 */
async function renderHome(req, res) {
    // 先检查登录状态
    const meResp = await proxyToPortalServer('/api/user/me', req);
    const isLoggedIn = meResp.statusCode === 200 && JSON.parse(meResp.body || '{}').authenticated;

    if (!isLoggedIn) {
        // 未登录, 显示登录卡片
        const content = `
            <div class="login-card">
                <h2>🔐 统一认证门户</h2>
                <p>请登录后访问应用中心</p>
                <a href="/login" class="btn">前往登录</a>
            </div>`;
        return layout('统一认证门户', content, false);
    }

    // 已登录, 加载客户端列表
    let clientsHtml = '<div class="loading">正在加载应用列表...</div>';
    try {
        const clientsResp = await proxyToPortalServer('/api/clients', req);
        if (clientsResp.statusCode === 200) {
            const data = JSON.parse(clientsResp.body);
            if (data.success && data.clients && data.clients.length > 0) {
                clientsHtml = '<div class="client-grid">' + data.clients.map(c => {
                    const icon = c.type === 'device' ? '📺' : '📋';
                    const link = c.authorizationUrl || c.verificationUri || '#';
                    return `<a href="${esc(link)}" class="client-card">
                        <div class="icon">${icon}</div>
                        <h3>${esc(c.clientName || c.clientId)}</h3>
                        <p>${esc(c.description || (c.type === 'device' ? '设备码授权应用' : 'Web应用 (SSO)'))}</p>
                        <div class="meta">client_id: ${esc(c.clientId)} · ${esc(c.type || 'web')}</div>
                    </a>`;
                }).join('') + '</div>';
            } else {
                clientsHtml = '<div class="empty">暂无可用的客户端应用</div>';
            }
        }
    } catch (e) {
        clientsHtml = `<div class="empty">加载客户端列表失败: ${esc(e.message)}</div>`;
    }

    const content = `
        <div class="page-title">
            <h2>应用中心</h2>
            <p>点击下方应用卡片, 自动通过 SSO 单点登录访问</p>
        </div>
        ${clientsHtml}`;

    return layout('应用中心', content, true);
}

// ============================================================
// HTTP 服务器
// ============================================================

const server = http.createServer(async (req, res) => {
    const pathname = url.parse(req.url).pathname;

    // 静态资源放行
    if (pathname === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
    }

    // API 代理: 将 /api/* 请求转发到 iam-portal-service (8080)
    if (pathname.startsWith('/api/')) {
        try {
            const proxyResp = await proxyToPortalServer(pathname, req, req.method);
            res.writeHead(proxyResp.statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(proxyResp.body);
        } catch (e) {
            res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: 'iam-portal-service 不可达: ' + e.message }));
        }
        return;
    }

    // 登录: 重定向到 iam-portal-service 的 OAuth2 登录
    if (pathname === '/login') {
        res.writeHead(302, {
            'Location': `${PORTAL_SERVER}/oauth2/authorization/portal-app-oidc`,
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    // 登出: 重定向到 iam-portal-service 的 OAuth2 登出
    if (pathname === '/logout') {
        res.writeHead(302, {
            'Location': `${PORTAL_SERVER}/api/auth/logout`,
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    // 登出完成页: OIDC RP-Initiated Logout 完成后, 认证中心直接重定向到这里
    if (pathname === '/logged-out') {
        const content = `
            <div class="login-card">
                <h2>已安全退出</h2>
                <p>您已成功退出门户登录</p>
                <a href="/login" class="btn">重新登录</a>
            </div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(layout('已退出登录', content, false));
        return;
    }

    // 首页和门户页面
    if (pathname === '/' || pathname === '/portal.html' || pathname === '/index.html') {
        try {
            const html = await renderHome(req, res);
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(`<h1>服务器错误</h1><pre>${esc(e.message)}</pre>`);
        }
        return;
    }

    // 404
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<h1>404 Not Found</h1><p>${esc(pathname)}</p>`);
});

server.listen(PORT, () => {
    console.log(`[iam-portal-web] 门户前端已启动: http://localhost:${PORT}`);
    console.log(`[iam-portal-web] 后端服务地址: ${PORTAL_SERVER}`);
    console.log(`[iam-portal-web] 认证中心地址: ${AUTH_SERVER}`);
});
