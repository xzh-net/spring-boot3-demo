/**
 * 门户前端应用 (iam-portal-web)
 * ------------------------------------
 * 纯前端服务, 不持有 client_secret, 通过调用 iam-portal-bff (8080) 后端 API 获取:
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

/** 代理请求到 iam-portal-bff (8080), 透传 Cookie */
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
    // 右侧区与管理后台导航栏保持一致: 登录/退出为纯文字链接, 登录态显示「👤 用户名」
    const logoutBtn = isLoggedIn
        ? '<a href="#" class="logout" id="logoutLink">退出登录</a>'
        : '';
    const loginBtn = !isLoggedIn
        ? '<a href="/login" class="logout">登录</a>'
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
        .navbar .user-info { color: #dbeafe; font-size: 13px; white-space: nowrap; }
        .navbar .logout { color: #dbeafe; font-size: 13px; cursor: pointer; text-decoration: none; }
        .navbar .logout:hover { background: rgba(255,255,255,0.15); color: #ffffff; border-radius: 6px; }
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
        .login-card { background: #fff; border-radius: 12px; padding: 40px 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); text-align: center; max-width: 420px; margin: 48px auto 32px; }
        .login-card h2 { font-size: 22px; margin-bottom: 12px; }
        .login-card p { color: #64748b; margin-bottom: 24px; }
        .login-card .btn { display: inline-block; background: linear-gradient(135deg, #2563eb, #1d4ed8); color: #fff; padding: 12px 36px; border-radius: 8px; text-decoration: none; font-size: 15px; font-weight: 500; }
        .login-card .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 14px rgba(37,99,235,0.35); }
        .empty { text-align: center; padding: 60px 20px; color: #94a3b8; }
        .loading { text-align: center; padding: 40px; color: #64748b; }
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; max-width: 860px; margin: 0 auto; }
        @media (max-width: 720px) { .info-grid { grid-template-columns: 1fr; } }
        .info-panel { background: #fff; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); overflow: hidden; }
        .info-panel-header { padding: 14px 20px; font-size: 15px; font-weight: 600; border-bottom: 1px solid #e2e8f0; background: #f8fafc; }
        .info-list { list-style: none; padding: 6px 0; }
        .info-list li { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 9px 20px; font-size: 13px; border-bottom: 1px dashed #f1f5f9; }
        .info-list li:last-child { border-bottom: none; }
        .info-list li a { color: #334155; text-decoration: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .info-list li a:hover { color: #2563eb; }
        .info-list .date { color: #94a3b8; font-size: 12px; flex-shrink: 0; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="brand">🔐 员工门户</div>
        <div class="nav-right">
            ${isLoggedIn ? '<span class="user-info" id="userInfo"></span>' : ''}
            ${loginBtn}${logoutBtn}
        </div>
    </div>
    <div class="container">${content}</div>
    <script>
        // 异步加载用户信息 (与管理后台一致: 👤 用户名 + title=邮箱)
        (async () => {
            try {
                const res = await fetch('/api/user/me', { credentials: 'include' });
                if (res.ok) {
                    const data = await res.json();
                    if (data.authenticated) {
                        const el = document.getElementById('userInfo');
                        if (el) {
                            el.textContent = '👤 ' + (data.nickname || data.username || data.subject);
                            if (data.email) el.title = data.email;
                        }
                    }
                }
            } catch (e) { console.warn('获取用户信息失败:', e); }
        })();
        // 退出登录: 与管理后台一致, 二次确认后跳转
        const logoutLink = document.getElementById('logoutLink');
        if (logoutLink) {
            logoutLink.addEventListener('click', function (e) {
                e.preventDefault();
                if (confirm('确认退出登录？')) location.href = '/logout';
            });
        }
    </script>
</body>
</html>`;
}

// ============================================================
// 未登录首页演示数据 (纯前端静态, 仅用于门户未登录态展示)
// ============================================================

const DEMO_NEWS = [
    { title: '统一认证平台 2.0 正式发布：单服务单库 + 双维权限模型', date: '2026-10-28' },
    { title: '平台新增设备码授权流程，支持物联网设备便捷接入', date: '2026-10-20' },
    { title: 'PKCE 强制校验已覆盖全部授权码客户端', date: '2026-10-15' },
    { title: '门户应用中心上线，支持按角色自动授权应用', date: '2026-10-08' },
    { title: '管理后台改版：新增授权范围与资源准入只读视图', date: '2026-09-30' }
];

const DEMO_NOTICES = [
    { title: '关于开展季度账号权限核查工作的通知', date: '2026-10-27' },
    { title: '关于启用双因素认证的预通知', date: '2026-10-22' },
    { title: '关于密码策略升级（历史口令不可复用）的通知', date: '2026-10-12' },
    { title: '关于统一认证平台例行维护窗口安排的通知', date: '2026-10-05' },
    { title: '关于第三方应用接入申请流程调整的通知', date: '2026-09-26' }
];

function demoListHtml(items) {
    return '<ul class="info-list">' + items.map(it =>
        `<li><a href="javascript:void(0)" title="${esc(it.title)}">${esc(it.title)}</a><span class="date">${esc(it.date)}</span></li>`
    ).join('') + '</ul>';
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
        // 未登录, 仅展示新闻动态/通知公告演示数据 (左右两栏);
        // 登录入口 = 导航栏右上角「登录」按钮
        const content = `
            <div class="info-grid" style="margin-top: 16px;">
                <div class="info-panel">
                    <div class="info-panel-header">📰 新闻动态</div>
                    ${demoListHtml(DEMO_NEWS)}
                </div>
                <div class="info-panel">
                    <div class="info-panel-header">📢 通知公告</div>
                    ${demoListHtml(DEMO_NOTICES)}
                </div>
            </div>`;
        return layout('员工门户', content, false);
    }

    // 已登录, 加载当前人员可见客户端列表
    let clientsHtml = '<div class="loading">正在加载应用列表...</div>';
    try {
        const clientsResp = await proxyToPortalServer('/api/clients', req);
        if (clientsResp.statusCode === 200) {
            const data = JSON.parse(clientsResp.body);
            if (data.success && data.clients && data.clients.length > 0) {
                clientsHtml = '<div class="client-grid">' + data.clients.map(c => {
                    const typeEmoji = { WEB: '🖥️', MOBILE: '📱', H5: '📲', MINI: '📦', DEVICE: '📺' };
                    const iconHtml = c.icon
                        ? `<img src="${esc(c.icon)}" style="width:36px;height:36px;border-radius:8px;object-fit:contain;margin-bottom:12px;" alt="">`
                        : `<div class="icon">${typeEmoji[c.type] || '📋'}</div>`;
                    const link = c.ssoUrl || '#';
                    const metaParts = [];
                    if (c.channelName) metaParts.push(`渠道: ${esc(c.channelName)}`);
                    if (c.isDefault === 1) metaParts.push('默认');
                    if (c.clientId) metaParts.push(`client_id: ${esc(c.clientId)}`);
                    return `<a href="${esc(link)}" class="client-card">
                        ${iconHtml}
                        <h3>${esc(c.name || c.appCode || '未命名应用')}</h3>
                        <p>${esc(c.description || '')}</p>
                        <div class="meta">${metaParts.join(' · ') || esc(c.type || 'web')}</div>
                    </a>`;
                }).join('') + '</div>';
            } else {
                clientsHtml = '<div class="empty">暂无可见应用 (请联系管理员进行应用授权)</div>';
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

    // API 代理: 将 /api/* 请求转发到 iam-portal-bff (8080)
    if (pathname.startsWith('/api/')) {
        try {
            const proxyResp = await proxyToPortalServer(pathname, req, req.method);
            res.writeHead(proxyResp.statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(proxyResp.body);
        } catch (e) {
            res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: 'iam-portal-bff 不可达: ' + e.message }));
        }
        return;
    }

    // 登录: 重定向到 iam-portal-bff 的 OAuth2 登录
    if (pathname === '/login') {
        res.writeHead(302, {
            'Location': `${PORTAL_SERVER}/oauth2/authorization/portal-app-oidc`,
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    // 登出: 重定向到 iam-portal-bff 的 OAuth2 登出
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
