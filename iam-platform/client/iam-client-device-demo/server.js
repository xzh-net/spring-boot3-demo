/**
 * OAuth2 设备码授权演示
 * ------------------------------------
 * 设备码流程 (RFC 8628), 适合无浏览器或输入受限的设备:
 *   1. 设备请求 /oauth2/device_authorization → 获取 device_code + user_code
 *   2. 用户在另一设备浏览器访问 /activate, 输入 user_code, 登录并授权
 *   3. 设备轮询 /oauth2/token (grant_type=device_code) → 获取 access_token + id_token
 *   4. 展示 id_token 解码的身份信息 + 调用资源 API
 *
 * 启动: node server.js
 * 端口: 8082  (零依赖)
 */

const http = require('http');
const url = require('url');

const PORT = 8082;
const AUTH_SERVER = 'http://localhost:9000';
const PORTAL_URL = 'http://localhost:8000';
const CLIENT_ID = 'device-app';
const SCOPE = 'openid profile email';
// 说明: 设备码流程现在携带 openid scope, 以获取 OIDC id_token (JWT).
// 自定义 DeviceCodeGrantAuthenticationProvider 模拟授权码 OIDC 上下文
// (生成一次性 OAuth2AuthorizationCode + nonce + id_token), 使 refresh_token 时
// JwtGenerator 能正确读取已存储的 idToken claims + nonce 重新生成 id_token, 不再 NPE.
// refreshAccessToken() 不发送 scope 参数, SAS 从已存储的 authorizedScopes 推导.
const DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

// ============================================================
// 简易会话管理 (存储设备码授权状态和 token)
// ============================================================
const sessions = new Map();

function generateSessionId() {
    return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}

function getSessionIdFromCookie(req) {
    const cookies = req.headers.cookie;
    if (!cookies) return null;
    const match = cookies.match(/sessionId=([^;]+)/);
    return match ? match[1] : null;
}

function setSessionCookie(res, sessionId) {
    res.setHeader('Set-Cookie', `sessionId=${sessionId}; Path=/; HttpOnly; SameSite=Lax`);
}

function clearSessionCookie(res) {
    res.setHeader('Set-Cookie', `sessionId=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax`);
}

function getSessionTokens(req) {
    const sessionId = getSessionIdFromCookie(req);
    if (!sessionId) return null;
    const session = sessions.get(sessionId);
    if (!session) return null;
    return { sessionId, ...session };
}

function decodeJwt(jwt) {
    try {
        const payload = jwt.split('.')[1];
        return JSON.parse(Buffer.from(payload, 'base64').toString());
    } catch { return null; }
}

// ============================================================
// 工具函数
// ============================================================

function esc(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function request(options, body, timeoutMs) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
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

/** 请求设备码 — POST /oauth2/device_authorization */
async function requestDeviceAuthorization() {
    const body = `client_id=${encodeURIComponent(CLIENT_ID)}&scope=${encodeURIComponent(SCOPE)}`;
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/device_authorization', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, body);
    return { status: res.statusCode, data: JSON.parse(res.body) };
}

/** 轮询 token — POST /oauth2/token (grant_type=device_code) */
async function pollForToken(deviceCode) {
    const body = `grant_type=${encodeURIComponent(DEVICE_CODE_GRANT_TYPE)}&device_code=${encodeURIComponent(deviceCode)}&client_id=${encodeURIComponent(CLIENT_ID)}&scope=${encodeURIComponent(SCOPE)}`;
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/token', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, body);
    let data;
    try { data = JSON.parse(res.body); } catch { data = { raw: res.body }; }
    return { status: res.statusCode, data };
}

/** 调用业务 API
 *  合并后单服务 (9000) 同时提供授权端点与 /api/** 业务接口 */
async function callResourceServer(path, accessToken) {
    const port = 9000;
    const res = await request({
        hostname: 'localhost', port: port, path: path, method: 'GET',
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return { status: res.statusCode, body: res.body };
}

/** Token 内省 — POST /oauth2/introspect (RFC 7662) */
async function introspectToken(token, tokenTypeHint) {
    const body = `token=${encodeURIComponent(token)}&token_type_hint=${tokenTypeHint || 'access_token'}&client_id=${encodeURIComponent(CLIENT_ID)}`;
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/introspect', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, body);
    return { status: res.statusCode, data: JSON.parse(res.body) };
}

/** 用 refresh_token 换新 token */
async function refreshAccessToken(refreshToken) {
    const body = `grant_type=refresh_token&refresh_token=${encodeURIComponent(refreshToken)}&client_id=${encodeURIComponent(CLIENT_ID)}`;
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/token', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, body);
    return { status: res.statusCode, data: JSON.parse(res.body) };
}

/** 吊销 token */
async function revokeToken(token, tokenTypeHint) {
    if (!token) return { ok: false, skipped: true };
    const body = `token=${encodeURIComponent(token)}&token_type_hint=${tokenTypeHint}&client_id=${encodeURIComponent(CLIENT_ID)}`;
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/revoke', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, body, 3000);
    return { ok: res.statusCode === 200 };
}

// ============================================================
// 轮询管理
// ============================================================
const pollTimers = new Map();

function startPolling(sessionId, deviceCode, interval) {
    stopPolling(sessionId);
    const timer = setInterval(async () => {
        const session = sessions.get(sessionId);
        if (!session || session.status !== 'pending') {
            stopPolling(sessionId);
            return;
        }
        if (Date.now() > session.expiresAt) {
            session.status = 'expired';
            session.errorMsg = '设备码已过期，请重新发起授权';
            stopPolling(sessionId);
            return;
        }
        try {
            const result = await pollForToken(deviceCode);
            if (result.status === 200 && result.data.access_token) {
                session.status = 'success';
                session.tokens = result.data;
                stopPolling(sessionId);
            } else {
                const err = result.data.error;
                if (err === 'authorization_pending') {
                    // continue polling
                } else if (err === 'slow_down') {
                    session.interval += 5;
                    stopPolling(sessionId);
                    startPolling(sessionId, deviceCode, session.interval);
                } else if (err === 'expired_token') {
                    session.status = 'expired';
                    session.errorMsg = '设备码已过期，请重新发起授权';
                    stopPolling(sessionId);
                } else if (err === 'access_denied') {
                    session.status = 'denied';
                    session.errorMsg = '用户拒绝了授权请求';
                    stopPolling(sessionId);
                } else {
                    session.status = 'error';
                    session.errorMsg = result.data.error_description || err || '未知错误';
                    stopPolling(sessionId);
                }
            }
        } catch (e) {
            console.warn(`[poll] 轮询异常:`, e);
        }
    }, interval * 1000);
    pollTimers.set(sessionId, timer);
}

function stopPolling(sessionId) {
    const timer = pollTimers.get(sessionId);
    if (timer) {
        clearInterval(timer);
        pollTimers.delete(sessionId);
    }
}

// ============================================================
// 页面渲染 (与授权码 Demo 一致的样式)
// ============================================================

/** 从会话 id_token 解当前登录账号 (preferred_username, 兜底 sub) */
function sessUser(session) {
    if (!session || !session.tokens || !session.tokens.id_token) return null;
    try {
        const p = JSON.parse(Buffer.from(session.tokens.id_token.split('.')[1], 'base64').toString());
        return p.preferred_username || p.sub || null;
    } catch { return null; }
}

function layout(title, content, isLoggedIn = false, user = null, active = '') {
    // 顶栏: 与 8000 门户 / 8081 演示对齐 (纯文字 13px gap16, hover 淡底)
    const portalBtn = isLoggedIn
        ? `<a href="${PORTAL_URL}">🏠 返回门户</a>`
        : '';
    const logoutBtn = isLoggedIn
        ? '<a href="/logout" class="logout">⊗ 退出登录</a>'
        : '';
    const userChip = user
        ? `<span class="userchip">👤 ${esc(user)}</span>`
        : '';
    // 全局功能标签栏: 每页一致的四个入口, 当前页高亮 (替代各页差异化底部大按钮)
    const TABS = [
        ['/userinfo-demo', '👤 查询用户信息', 'userinfo'],
        ['/api-demo', '📋 调用应用列表(三方受限)', 'api'],
        ['/refresh-demo', '🔄 刷新 Token', 'refresh'],
        ['/introspect-demo', '🔍 验证 Token', 'introspect'],
        ['/start', '🔁 重新授权', 'restart']
    ];
    const tabbar = `<div class="tabbar">` + TABS.map(t =>
        `<a href="${t[0]}" class="tab${active === t[2] ? ' on' : ''}">${t[1]}</a>`).join('') + `</div>`;
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${esc(title)}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, "Segoe UI", sans-serif; background: #f0f2f5; color: #1e293b; min-height: 100vh; }
        .nav { background: linear-gradient(135deg, #1e3a5f, #2563eb); color: #fff; padding: 0 24px; height: 56px; display: flex; align-items: center; position: sticky; top: 0; z-index: 30; }
        .nav .brand { font-weight: 700; font-size: 16px; }
        .nav a { color: #dbeafe; text-decoration: none; margin-left: 24px; font-size: 14px; }
        /* 右侧组: 与 8000 门户顶栏对齐 (gap 16px, 13px, hover 淡底圆角) */
        .nav .right { margin-left: auto; display: flex; align-items: center; gap: 16px; }
        .nav .right a { margin-left: 0; color: #dbeafe; font-size: 13px; white-space: nowrap; padding: 0; border-radius: 6px; }
        .nav .right a:hover { background: rgba(255,255,255,0.15); color: #ffffff; }
        .nav .userchip { color: #dbeafe; font-size: 13px; white-space: nowrap; }
        /* 全局功能标签栏 (置顶第二行, 所有页面一致) */
        .tabbar { position: sticky; top: 56px; z-index: 20; background: #ffffff; border-bottom: 1px solid #e2e8f0;
                  display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; padding: 10px 24px;
                  box-shadow: 0 2px 8px rgba(15,23,42,0.06); }
        .tab { font-size: 13px; color: #475569; background: #f1f5f9; border: 1px solid #e2e8f0; padding: 7px 18px;
               border-radius: 999px; text-decoration: none; transition: all 0.15s; white-space: nowrap; }
        .tab:hover { color: #2563eb; border-color: #bfdbfe; background: #eff6ff; }
        .tab.on { background: linear-gradient(135deg, #2563eb, #1d4ed8); color: #fff; border-color: transparent;
                  box-shadow: 0 4px 10px rgba(37,99,235,0.3); font-weight: 500; }
        .container { max-width: 860px; margin: 24px auto; padding: 0 24px; }
        .card { background: #fff; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); padding: 28px; margin-bottom: 18px; }
        h1 { font-size: 22px; color: #1e3a5f; margin-bottom: 6px; }
        h2 { font-size: 15px; color: #1e3a5f; margin-bottom: 12px; font-weight: 600; padding-left: 9px; border-left: 3px solid #2563eb; }
        .sub { color: #64748b; font-size: 13px; margin-bottom: 20px; }
        .btn { display: inline-block; padding: 10px 28px; border-radius: 8px; border: none; cursor: pointer; font-size: 14px; font-weight: 500; text-decoration: none; transition: all 0.2s; }
        .btn-primary { background: linear-gradient(135deg, #2563eb, #1d4ed8); color: #fff; }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 4px 14px rgba(37,99,235,0.35); }
        .btn-outline { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }
        .btn-outline:hover { border-color: #2563eb; color: #2563eb; }
        pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 8px; font-size: 12px; line-height: 1.6; overflow-x: auto; font-family: "Cascadia Code", Consolas, monospace; }
        .flow { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin: 16px 0; }
        .flow-step { padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 500; }
        .flow-step.done { background: #dcfce7; color: #16a34a; }
        .flow-step.current { background: #dbeafe; color: #2563eb; border: 2px solid #2563eb; }
        .flow-step.todo { background: #f1f5f9; color: #94a3b8; }
        .flow-arrow { color: #cbd5e1; font-size: 18px; }
        .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }
        /* 页内情境按钮: 位置不变, 大小与顶部功能栏胶囊对齐 */
        .actions .btn { padding: 7px 18px; border-radius: 999px; font-size: 13px; font-weight: 400;
                        background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; box-shadow: none; transform: none; }
        .actions .btn:hover { border-color: #2563eb; color: #2563eb; transform: none; box-shadow: none; }
        .actions .btn-primary { background: linear-gradient(135deg, #2563eb, #1d4ed8); color: #fff; border-color: transparent; }
        .actions .btn-primary:hover { color: #fff; border-color: transparent; transform: none; box-shadow: 0 4px 10px rgba(37,99,235,0.3); }
        .info-table { width: 100%; font-size: 13px; }
        .info-table td { padding: 6px 0; }
        .info-table td:first-child { color: #94a3b8; width: 150px; }
        .code-display { text-align: center; padding: 28px; background: linear-gradient(135deg, #eff6ff, #dbeafe); border-radius: 12px; margin: 16px 0; border: 1px solid #bfdbfe; }
        .code-display .label { font-size: 13px; color: #64748b; margin-bottom: 8px; }
        .code-display .code { font-size: 42px; font-weight: 800; letter-spacing: 12px; color: #1e3a5f; font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
        .status-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 13px; font-weight: 500; }
        .status-pending { background: #fef3c7; color: #92400e; }
        .status-expired { background: #fee2e2; color: #991b1b; }
        .status-denied { background: #fee2e2; color: #991b1b; }
        .status-error { background: #fee2e2; color: #991b1b; }
        .hint-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px 18px; margin: 16px 0; font-size: 13px; color: #475569; line-height: 1.8; }
        .hint-box .hint-label { color: #94a3b8; font-size: 12px; margin-bottom: 4px; }
        .hint-box a { color: #2563eb; font-weight: 600; text-decoration: none; }
        .hint-box a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="nav">
        <div class="brand">📱 OAuth2 设备码演示</div>
        <a href="/">首页</a>
        <div class="right">
            ${portalBtn}
            ${userChip}
            ${logoutBtn}
        </div>
    </div>
    ${tabbar}
    <div class="container">${content}</div>
</body>
</html>`;
}

// ============================================================
// 路由页面
// ============================================================

/** 首页 */
async function renderHome(req, res) {
    const session = getSessionTokens(req);

    // 已拿到 token → 显示功能按钮
    if (session && session.tokens && session.tokens.access_token) {
        const tokens = session.tokens;
        const idTokenPayload = tokens.id_token ? decodeJwt(tokens.id_token) : null;
        const content = `
            <div class="card">
                <h1>🎉 已授权</h1>
                <div class="sub">设备码已授权成功,可以继续操作。</div>

                ${idTokenPayload ? `
                <h2 style="margin-top:12px;">用户身份信息 (id_token 解码)</h2>
                <div class="sub" style="font-size:12px;color:#94a3b8;margin-bottom:8px;">id_token 用于客户端识别用户身份, access_token 仅用于调用资源 API</div>
                <table class="info-table">
                    <tr><td>sub (用户唯一标识)</td><td>${esc(idTokenPayload.sub)}</td></tr>
                    <tr><td>preferred_username</td><td>${esc(idTokenPayload.preferred_username)}</td></tr>
                    <tr><td>iss (签发者)</td><td>${esc(idTokenPayload.iss)}</td></tr>
                    <tr><td>aud (受众)</td><td>${esc(idTokenPayload.aud)}</td></tr>
                    <tr><td>exp (过期)</td><td>${esc(new Date(idTokenPayload.exp * 1000).toLocaleString())}</td></tr>
                </table>` : `
                <div class="sub" style="color:#94a3b8;margin:12px 0;">
                    ⚠️ 当前 Token 响应中未包含 id_token<br>
                    <span style="font-size:12px;">
                        可能原因: 1. 客户端未注册 openid scope; 2. 授权请求未携带 openid scope; 3. grant_type 不支持 OIDC。
                        当前客户端: device-app, grant_type: device_code
                    </span>
                </div>
                <h2>Token 响应</h2>
                <pre>${esc(JSON.stringify(tokens, null, 2))}</pre>`}

            </div>
        `;
        return layout('OAuth2 设备码演示', content, true, idTokenPayload ? (idTokenPayload.preferred_username || idTokenPayload.sub) : null, 'restart');
    }

    // 未登录 / session 失效 → 直接发起设备码授权, 跳转到等待授权页
    if (session) {
        sessions.delete(session.sessionId);
        clearSessionCookie(res);
    }
    res.writeHead(302, {
        'Location': '/start',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    res.end();
}

/** Token 内省演示 (设备码版) */
async function renderIntrospectDemo(req, res) {
    const session = getSessionTokens(req);
    if (!session || !session.tokens) {
        // 设备码进行中 (pending 尚无 token) → 回设备页继续等待, 不重置授权流程
        const dest = session && session.status === 'pending' ? '/device' : '/start';
        res.writeHead(302, {
            'Location': dest,
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    let result;
    try {
        result = await introspectToken(session.tokens.access_token, 'access_token');
    } catch (e) {
        return layout('请求失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre><div class="actions"><a href="/" class="btn btn-outline">返回</a></div></div>`, true, sessUser(session), 'introspect');
    }

    // RFC 7662: introspect 端点在 token 无效时返回 200 + active=false (而非 401)
    // 但我们仍需要清除本地 session 并跳转到授权服务器，保持与其他按钮行为一致
    if (result.status === 401 || (result.status === 200 && result.data.active === false)) {
        sessions.delete(session.sessionId);
        clearSessionCookie(res);
        res.writeHead(302, {
            'Location': '/start',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const ok = result.status === 200;
    let bodyDisplay = JSON.stringify(result.data, null, 2);

    return layout('Token 内省', `
        <div class="card">
            <h1>${ok ? '✅' : '❌'} Token 内省 — HTTP ${result.status}</h1>
            <div class="sub">调用 /oauth2/introspect 获取 access_token 元数据 (RFC 7662)</div>
            <pre>${esc(bodyDisplay)}</pre>
        </div>
    `, true, sessUser(session), 'introspect');
}

/** 设备码展示 + 轮询状态页 */
function renderDevicePage(session) {
    if (session.status === 'success') {
        const idTokenPayload = session.tokens.id_token ? decodeJwt(session.tokens.id_token) : null;
        return layout('授权成功', `
            <div class="card">
                <h1>✅ 授权成功</h1>
                <div class="sub">设备已通过用户授权, 成功获取 Token</div>
                <div class="flow">
                    <div class="flow-step done">① 请求设备码</div>
                    <span class="flow-arrow">→</span>
                    <div class="flow-step done">② 用户授权</div>
                    <span class="flow-arrow">→</span>
                    <div class="flow-step done">③ 轮询取 Token</div>
                    <span class="flow-arrow">→</span>
                    <div class="flow-step current">④ 访问资源</div>
                </div>

                <h2>Token 响应</h2>
                <pre>${esc(JSON.stringify(session.tokens, null, 2))}</pre>

                ${idTokenPayload ? `
                <h2 style="margin-top:20px;">用户身份信息 (id_token 解码)</h2>
                <div class="sub" style="font-size:12px;color:#94a3b8;margin-bottom:8px;">id_token 用于客户端识别用户身份, access_token 仅用于调用资源 API</div>
                <table class="info-table">
                    <tr><td>sub (用户唯一标识)</td><td>${esc(idTokenPayload.sub)}</td></tr>
                    <tr><td>preferred_username</td><td>${esc(idTokenPayload.preferred_username)}</td></tr>
                    <tr><td>iss (签发者)</td><td>${esc(idTokenPayload.iss)}</td></tr>
                    <tr><td>aud (受众)</td><td>${esc(idTokenPayload.aud)}</td></tr>
                    <tr><td>exp (过期)</td><td>${esc(new Date(idTokenPayload.exp * 1000).toLocaleString())}</td></tr>
                </table>` : ''}

            </div>
        `, true, idTokenPayload ? (idTokenPayload.preferred_username || idTokenPayload.sub) : null, 'restart');
    }

    let statusBadge = '';
    let statusMsg = '';
    if (session.status === 'pending') {
        statusBadge = '<span class="status-badge status-pending">⏳ 等待用户授权</span>';
        const expireSeconds = Math.max(0, Math.round((session.expiresAt - Date.now()) / 1000));
        const verifyUri = session.verificationUri || 'http://localhost:9000/activate';
        // 判断 verificationUri 是否已包含 user_code (即 verification_uri_complete),
        // 若已包含则直接使用, 否则拼接 user_code 参数用于方式一
        const hasUserCode = verifyUri.includes('user_code=');
        const verifyUriWithCode = hasUserCode
                ? verifyUri
                : verifyUri + (verifyUri.includes('?') ? '&' : '?') + 'user_code=' + encodeURIComponent(session.userCode);
        // 方式二使用不带参数的纯 URL, 让用户手动粘贴输入
        const verifyUriClean = hasUserCode
                ? verifyUri.substring(0, verifyUri.indexOf('?'))
                : verifyUri;
        statusMsg = `<div class="hint-box">
            <div class="hint-label">📌 操作指引 (二选一)</div>
            <div>过期时间: <strong>${expireSeconds}</strong> 秒后 · 每 <strong>${session.interval || 5}</strong> 秒自动轮询刷新, 授权成功后自动完成</div>
            <div style="margin-top:8px;">方式一: 点击完整链接 (自动填入用户码)</div>
            <div><a href="${esc(verifyUriWithCode)}" target="_blank" style="color:#2563eb;font-weight:600;text-decoration:none;word-break:break-all;">${esc(verifyUriWithCode)}</a></div>
            <div style="margin-top:8px;">方式二: 访问链接后手动输入用户码</div>
            <div><a href="${esc(verifyUriClean)}" target="_blank">${esc(verifyUriClean)}</a></div>
        </div>`;
    } else if (session.status === 'expired') {
        statusBadge = '<span class="status-badge status-expired">⏰ 设备码已过期</span>';
        statusMsg = `<div class="hint-box" style="border-color:#fecaca;background:#fef2f2;color:#991b1b;">${esc(session.errorMsg || '设备码已过期')}</div>`;
    } else if (session.status === 'denied') {
        statusBadge = '<span class="status-badge status-denied">❌ 授权被拒绝</span>';
        statusMsg = `<div class="hint-box" style="border-color:#fecaca;background:#fef2f2;color:#991b1b;">${esc(session.errorMsg || '用户拒绝了授权')}</div>`;
    } else if (session.status === 'error') {
        statusBadge = '<span class="status-badge status-error">⚠️ 错误</span>';
        statusMsg = `<div class="hint-box" style="border-color:#fecaca;background:#fef2f2;color:#991b1b;">${esc(session.errorMsg || '未知错误')}</div>`;
    }

    const refreshScript = session.status === 'pending'
        ? '<script>setTimeout(function() { location.reload(); }, 5000);</script>'
        : '';
    const copyScript = `<script>
        function copyCode() {
            var code = document.querySelector('.code-display .code').textContent.trim();
            navigator.clipboard.writeText(code).then(function() {
                var tip = document.getElementById('copyTip');
                tip.style.display = 'block';
                setTimeout(function() { tip.style.display = 'none'; }, 2000);
            });
        }
    </script>`;

    return layout('设备码授权', `
        <div class="card">
            <h1>📱 设备码授权 ${statusBadge}</h1>
            <div class="sub">请在另一台设备的浏览器中完成授权</div>
            <div class="code-display" style="position:relative;">
                <div class="label">用户码</div>
                <div class="code">${esc(session.userCode)}</div>
                <button id="copyBtn" onclick="copyCode()" style="margin-top:12px;background:linear-gradient(135deg, #2563eb, #1d4ed8);color:#fff;border:none;padding:8px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;transition:all 0.2s;" onmouseover="this.style.transform='translateY(-1px)';this.style.boxShadow='0 4px 14px rgba(37,99,235,0.35)'" onmouseout="this.style.transform='';this.style.boxShadow=''">📋 复制</button>
                <div id="copyTip" style="display:none;margin-top:6px;font-size:12px;color:#16a34a;font-weight:500;">✅ 已复制到剪贴板</div>
            </div>
            ${statusMsg}
        </div>
        ${refreshScript}
        ${copyScript}
    `, false, null, 'restart');
}

/** API 调用演示 */
async function renderApiDemo(req, res) {
    const session = getSessionTokens(req);
    if (!session || !session.tokens) {
        // 设备码进行中 (pending 尚无 token) → 回设备页继续等待, 不重置授权流程
        const dest = session && session.status === 'pending' ? '/device' : '/start';
        res.writeHead(302, {
            'Location': dest,
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const accessToken = session.tokens.access_token;
    let result;
    try {
        result = await callResourceServer('/biz/clients/mine', accessToken);
    } catch (e) {
        return layout('请求失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre></div>`, true, sessUser(session), 'api');
    }

    if (result.status === 401) {
        sessions.delete(session.sessionId);
        clearSessionCookie(res);
        res.writeHead(302, {
            'Location': '/start',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const ok = result.status === 200;
    let bodyDisplay = result.body;
    try { bodyDisplay = JSON.stringify(JSON.parse(result.body), null, 2); } catch {}

    return layout('应用列表 API (三方受限演示)', `
        <div class="card">
            <h1>${ok ? '✅' : '❌'} /biz/clients/mine — HTTP ${result.status}</h1>
            <div class="sub">使用设备码获取的 access_token 调用受保护资源</div>

            <h2>请求</h2>
            <pre>GET /biz/clients/mine
Authorization: Bearer ${esc(accessToken.substring(0, 40))}...</pre>

            <h2 style="margin-top:16px;">响应</h2>
            <pre>${esc(bodyDisplay)}</pre>

        </div>
    `, true, sessUser(session), 'api');
}

/** UserInfo 演示 */
async function renderUserinfoDemo(req, res) {
    const session = getSessionTokens(req);
    if (!session || !session.tokens) {
        // 设备码进行中 (pending 尚无 token) → 回设备页继续等待, 不重置授权流程
        const dest = session && session.status === 'pending' ? '/device' : '/start';
        res.writeHead(302, {
            'Location': dest,
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const accessToken = session.tokens.access_token;
    let result;
    try {
        result = await callResourceServer('/userinfo', accessToken);
    } catch (e) {
        return layout('请求失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre></div>`, true, sessUser(session), 'userinfo');
    }

    if (result.status === 401) {
        sessions.delete(session.sessionId);
        clearSessionCookie(res);
        res.writeHead(302, {
            'Location': '/start',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const ok = result.status === 200;
    let bodyDisplay = result.body;
    try { bodyDisplay = JSON.stringify(JSON.parse(result.body), null, 2); } catch {}

    return layout('用户信息', `
        <div class="card">
            <h1>${ok ? '✅' : '❌'} /userinfo — HTTP ${result.status}</h1>
            <div class="sub">OIDC UserInfo 端点, 返回用户基本信息</div>
            <pre>${esc(bodyDisplay)}</pre>
        </div>
    `, true, sessUser(session), 'userinfo');
}

/** 刷新 token 演示 */
async function renderRefreshDemo(req, res) {
    const session = getSessionTokens(req);
    if (!session || !session.tokens) {
        // 设备码进行中 (pending 尚无 token) → 回设备页继续等待, 不重置授权流程
        const dest = session && session.status === 'pending' ? '/device' : '/start';
        res.writeHead(302, {
            'Location': dest,
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    let result;
    try {
        result = await refreshAccessToken(session.tokens.refresh_token);
    } catch (e) {
        return layout('刷新失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre></div>`, true, sessUser(session), 'refresh');
    }

    if (result.status !== 200) {
        sessions.delete(session.sessionId);
        clearSessionCookie(res);
        res.writeHead(302, {
            'Location': '/start',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const ok = result.status === 200;
    let bodyDisplay = JSON.stringify(result.data, null, 2);

    if (ok && result.data.access_token) {
        const existing = sessions.get(session.sessionId) || {};
        const mergedTokens = { ...result.data };
        if (!mergedTokens.id_token && session.tokens.id_token) {
            mergedTokens.id_token = session.tokens.id_token;
        }
        sessions.set(session.sessionId, {
            ...existing,
            tokens: mergedTokens,
            status: 'success'
        });
    }

    return layout('刷新 Token', `
        <div class="card">
            <h1>${ok ? '✅' : '❌'} Token 刷新 — HTTP ${result.status}</h1>
            <div class="sub">用 refresh_token 换取新的 access_token</div>
            <pre>${esc(bodyDisplay)}</pre>
            ${ok && result.data.access_token ? `
            <div class="actions">
                <a href="/api-demo" class="btn btn-primary">📋 用新 Token 调 API</a>
            </div>` : ''}
    `, true, sessUser(session), 'refresh');
}

// ============================================================
// HTTP 服务
// ============================================================

const server = http.createServer(async (req, res) => {
    const parsed = url.parse(req.url, true);
    const path = parsed.pathname;

    try {
        let html;
        switch (path) {
            case '/':
            case '/index.html': {
                html = await renderHome(req, res);
                break;
            }

            case '/start': {
                let result;
                try {
                    result = await requestDeviceAuthorization();
                } catch (e) {
                    html = layout('请求失败', `<div class="card"><h1>⚠️ 无法连接授权服务器</h1><pre>${esc(e.message)}</pre><div class="actions"><a href="/" class="btn btn-outline">返回首页</a></div></div>`, false, null, 'restart');
                    break;
                }
                if (result.status !== 200) {
                    html = layout('请求失败', `<div class="card"><h1>⚠️ 设备码请求失败 (HTTP ${result.status})</h1><pre>${esc(JSON.stringify(result.data, null, 2))}</pre><div class="actions"><a href="/" class="btn btn-outline">返回首页</a></div></div>`, false, null, 'restart');
                    break;
                }

                const sessionId = generateSessionId();
                const d = result.data;
                // 优先使用服务器返回的 verification_uri_complete (已包含 user_code),
                // 若不存在则使用 verification_uri 并在渲染时拼接 user_code 参数
                const verificationUri = d.verification_uri_complete || d.verification_uri;
                sessions.set(sessionId, {
                    deviceCode: d.device_code,
                    userCode: d.user_code,
                    verificationUri: verificationUri,
                    interval: d.interval || 5,
                    expiresAt: Date.now() + (d.expires_in || 1800) * 1000,
                    status: 'pending',
                    tokens: null,
                    errorMsg: null
                });
                setSessionCookie(res, sessionId);
                startPolling(sessionId, d.device_code, d.interval || 5);
                res.writeHead(302, { 'Location': '/device', 'Cache-Control': 'no-cache, no-store, must-revalidate' });
                res.end();
                return;
            }

            case '/device': {
                const sid = getSessionIdFromCookie(req);
                const session = sid ? sessions.get(sid) : null;
                if (!session) {
                    res.writeHead(302, { 'Location': '/' });
                    res.end();
                    return;
                }
                html = renderDevicePage(session);
                break;
            }

            case '/api-demo':
                html = await renderApiDemo(req, res);
                break;

            case '/userinfo-demo':
                html = await renderUserinfoDemo(req, res);
                break;

            case '/refresh-demo':
                html = await renderRefreshDemo(req, res);
                break;

            case '/introspect-demo':
                html = await renderIntrospectDemo(req, res);
                break;

            case '/logout': {
                const sid = getSessionIdFromCookie(req);
                if (sid) {
                    const sessionData = sessions.get(sid);
                    sessions.delete(sid);
                    stopPolling(sid);
                    if (sessionData && sessionData.tokens) {
                        try {
                            await Promise.all([
                                revokeToken(sessionData.tokens.access_token, 'access_token'),
                                revokeToken(sessionData.tokens.refresh_token, 'refresh_token')
                            ]);
                        } catch {}
                    }
                }
                clearSessionCookie(res);
                res.writeHead(302, { 'Location': '/', 'Cache-Control': 'no-cache, no-store, must-revalidate' });
                res.end();
                return;
            }

            default:
                res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end('404 Not Found');
                return;
        }
        if (res.headersSent) return;
        res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end(html);
    } catch (e) {
        if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(layout('服务器错误', `<div class="card"><h1>⚠️ 服务器错误</h1><pre>${esc(e.message)}</pre></div>`, false, null, 'restart'));
        }
    }
});

server.listen(PORT, () => {
    console.log('========================================');
    console.log('  OAuth2 设备码授权演示');
    console.log('========================================');
    console.log('  访问: http://localhost:' + PORT);
    console.log('  授权服务器: ' + AUTH_SERVER);
    console.log('  客户端: ' + CLIENT_ID + ' (Public, 无密钥)');
    console.log('  按 Ctrl+C 停止');
    console.log('========================================');
});
