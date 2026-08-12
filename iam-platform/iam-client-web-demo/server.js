/**
 * OAuth2 授权码登录演示
 * ------------------------------------
 * 最精简的授权码流程演示, 全程页面操作, 直观可视:
 *   1. 首页点"登录" → 跳转授权服务器
 *   2. 登录 + 授权确认 → 回调到本服务
 *   3. 服务端用 code 换 token (client_secret 不暴露给浏览器)
 *   4. 展示 token + 调用资源 API
 *
 * 启动: node server.js
 * 端口: 8081  (零依赖)
 */

const http = require('http');
const url = require('url');
const crypto = require('crypto');

const PORT = 8081;
const AUTH_SERVER = 'http://localhost:9000';
const PORTAL_URL = 'http://localhost:8000';
const CLIENT_ID = 'web-app';
const CLIENT_SECRET = '123456';
const REDIRECT_URI = 'http://localhost:8081/callback';

// ========== 设计文档 §6-7: Web 应用 A → 门户 的 prompt=none 静默 SSO 回流 ==========
const PORTAL_CLIENT_ID = 'portal-app';
// 本应用接收门户 prompt=none 授权响应的回调端点
const PORTAL_SSO_REDIRECT_URI = 'http://localhost:8081/portal-sso-callback';
// 动态生成 state, 避免 CSRF
function _generatePortalSsoState() {
    return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}
// 用 Map 暂存 state (一次性)
const _portalSsoStates = new Set();

/**
 * 生成「返回门户」的静默授权 URL.
 * 设计文档 §6: A 返回 Portal 时不直接跳门户首页, 而是为 portal-app 客户端
 * 发起 OIDC 授权请求, 带 prompt=none:
 *   - 有 SAS SSO Session → 直接发 code, 不弹登录页
 *   - 无 SAS Session     → 返回 error=login_required, 不弹登录页
 */
function getPortalSsoUrl() {
    const state = _generatePortalSsoState();
    _portalSsoStates.add(state);
    // portal-app 配置了 requireProofKey=true (PKCE), 必须发送 code_challenge
    // 这里生成一次性的 PKCE 参数, code_verifier 不会用于换 token (仅做 SSO 有效性探测)
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    let url = `${AUTH_SERVER}/oauth2/authorize?response_type=code&client_id=${PORTAL_CLIENT_ID}`;
    url += `&redirect_uri=${encodeURIComponent(PORTAL_SSO_REDIRECT_URI)}`;
    url += `&scope=${encodeURIComponent('openid profile')}`;
    url += `&state=${state}`;
    url += `&code_challenge=${codeChallenge}`;
    url += `&code_challenge_method=S256`;
    // 设计文档 §6-7: prompt=none — 静默授权, 绝不弹登录页
    url += `&prompt=none`;
    return url;
}

/** 生成 OAuth2 授权码请求 URL — token 失效时直接 302 重定向到此地址 */
function getAuthorizationUrl() {
    return `${AUTH_SERVER}/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid%20profile%20email%20read%20write&state=demo`;
}

// ============================================================
// 简易会话管理 (用于演示退出功能和 Token 失效跳转)
// ============================================================
const sessions = new Map(); // sessionId -> { access_token, refresh_token, ... }

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
    res.setHeader('Set-Cookie', 'sessionId=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax');
}

function getSessionTokens(req, res) {
    const sessionId = getSessionIdFromCookie(req);
    if (!sessionId) return null;
    const tokens = sessions.get(sessionId);
    if (!tokens) return null;
    return { sessionId, tokens };
}

// ============================================================
// 工具函数
// ============================================================

function esc(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/** 发起 HTTP 请求 (同步 Promise) */
function request(options, body, timeoutMs) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
        });
        req.on('error', reject);
        // 可选超时: 服务端不可达时主动中止, 避免调用方长时间挂起
        if (timeoutMs && timeoutMs > 0) {
            const timer = setTimeout(() => req.destroy(new Error(`请求超时 (${timeoutMs}ms)`)), timeoutMs);
            req.on('close', () => clearTimeout(timer));
        }
        if (body) req.write(body);
        req.end();
    });
}

/** 用 authorization_code 换 token */
async function exchangeCodeForToken(code) {
    const body = `grant_type=authorization_code&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
    const auth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/token', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${auth}`, 'Content-Length': Buffer.byteLength(body) }
    }, body);
    return { status: res.statusCode, data: JSON.parse(res.body) };
}

/** 用 refresh_token 换新 token */
async function refreshAccessToken(refreshToken) {
    const body = `grant_type=refresh_token&refresh_token=${encodeURIComponent(refreshToken)}`;
    const auth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/token', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${auth}`, 'Content-Length': Buffer.byteLength(body) }
    }, body);
    return { status: res.statusCode, data: JSON.parse(res.body) };
}

/** 调用资源 API (内置 10s 超时，避免服务端异常时请求挂起) */
async function callResourceServer(path, accessToken) {
    const res = await request({
        hostname: 'localhost', port: 9000, path: path, method: 'GET',
        headers: { 'Authorization': `Bearer ${accessToken}` }
    }, null, 10000);
    return { status: res.statusCode, body: res.body };
}

/** Token 内省 — POST /oauth2/introspect (RFC 7662) */
async function introspectToken(token, tokenTypeHint) {
    const body = `token=${encodeURIComponent(token)}&token_type_hint=${tokenTypeHint || 'access_token'}`;
    const auth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/introspect', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${auth}`, 'Content-Length': Buffer.byteLength(body) }
    }, body);
    return { status: res.statusCode, data: JSON.parse(res.body) };
}

/**
 * 吊销 token — 调用授权服务器的 /oauth2/revoke 端点 (RFC 7009)
 * 返回 { ok, status?, error? }: ok=true 表示服务端确认吊销 (HTTP 200)
 * 内置 3s 超时, 服务端不可达时也不会让退出流程长时间挂起
 */
async function revokeToken(token, tokenTypeHint) {
    if (!token) return { ok: false, skipped: true };
    const body = `token=${encodeURIComponent(token)}&token_type_hint=${tokenTypeHint}`;
    const auth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    try {
        const res = await request({
            hostname: 'localhost', port: 9000, path: '/oauth2/revoke', method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${auth}`, 'Content-Length': Buffer.byteLength(body) }
        }, body, 3000);
        // RFC 7009: 吊销成功一律返回 200 (即使 token 不存在也算成功)
        if (res.statusCode === 200) {
            console.log(`[logout] 已吊销 ${tokenTypeHint} (HTTP 200)`);
            return { ok: true };
        }
        console.warn(`[logout] 吊销 ${tokenTypeHint} 失败: HTTP ${res.statusCode} ${res.body}`);
        return { ok: false, status: res.statusCode };
    } catch (e) {
        // 吊销失败不阻断退出流程, 本地 session 仍会清除
        console.warn(`[logout] 吊销 ${tokenTypeHint} 异常:`, e.message);
        return { ok: false, error: e.message };
    }
}

/** 客户端登录页地址 — 授权服务器销毁 session 后回跳到此 (首页带"开始授权登录"按钮) */
const CLIENT_LOGIN_URL = 'http://localhost:8081/';

/**
 * 退出登录流程:
 *   1. 先清理本地 session (无论后端是否可达, 本地必须干净)
 *   2. 尽力调用 /oauth2/revoke 吊销 token (RFC 7009, 3s 超时, 失败不阻断)
 *   3. 清客户端 cookie, 然后 302 到授权服务器 /logout 让它销毁 PORTAL HttpSession 并回跳
 *
 *   — 关键: 只清理本地 + 吊销 token 还不够. 若不销毁服务器端 HttpSession,
 *     下次浏览器点 "开始授权登录" 会带着旧 JSESSIONID, 服务器发现 session 中已认证
 *     直接发授权码不弹登录页, 看起来像 "退出后又自动登录回来了".
 */
async function handleLogout(req, res) {
    const sid = getSessionIdFromCookie(req);
    if (sid) {
        const tokens = sessions.get(sid);
        // 1. 先删除本地 session —— 无论服务端吊销是否成功, 本地必须清理干净
        sessions.delete(sid);
        if (tokens) {
            // 2. 并发吊销 access_token / refresh_token (revokeToken 内置 3s 超时)
            const [atRes, rtRes] = await Promise.all([
                revokeToken(tokens.access_token, 'access_token'),
                revokeToken(tokens.refresh_token, 'refresh_token')
            ]);
            if (!atRes.ok || !rtRes.ok) {
                console.warn('[logout] 服务端吊销未完全成功, 本地 session 已清理; access=%j refresh=%j',
                    atRes, rtRes);
            }
        }
    }
    // 3. 清掉客户端自己的 sessionId cookie, 然后跳授权服务器 /logout 去真正销毁 PORTAL session
    clearSessionCookie(res);
    const serverLogout = `${AUTH_SERVER}/logout?redirect=${encodeURIComponent(CLIENT_LOGIN_URL)}`;
    res.writeHead(302, {
        'Location': serverLogout,
        'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    res.end();
}

// ============================================================
// 页面渲染
// ============================================================

function layout(title, content, isLoggedIn = false, portalAuthUrl = null) {
    // 设计文档 §6: "返回门户" 先打本应用 /return-to-portal 端点, 由服务端构造 prompt=none 静默授权 URL
    const portalBtn = isLoggedIn
        ? `<a href="/return-to-portal" style="background:rgba(255,255,255,0.15);color:#fff;border:1px solid rgba(255,255,255,0.35);padding:6px 14px;border-radius:6px;text-decoration:none;font-size:13px;margin-right:12px;">🏠 返回门户</a>`
        : '';
    const logoutBtn = isLoggedIn ? '<a href="/logout" style="background:rgba(255,255,255,0.15);color:#fff;border:1px solid rgba(255,255,255,0.35);padding:6px 14px;border-radius:6px;text-decoration:none;font-size:13px;">退出登录</a>' : '';
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${esc(title)}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, "Segoe UI", sans-serif; background: #f0f2f5; color: #1e293b; min-height: 100vh; }
        .nav { background: linear-gradient(135deg, #1e3a5f, #2563eb); color: #fff; padding: 0 24px; height: 56px; display: flex; align-items: center; }
        .nav .brand { font-weight: 700; font-size: 16px; }
        .nav a { color: #dbeafe; text-decoration: none; margin-left: 24px; font-size: 14px; }
        .nav .right { margin-left: auto; display: flex; align-items: center; }
        .container { max-width: 860px; margin: 24px auto; padding: 0 24px; }
        .card { background: #fff; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); padding: 28px; margin-bottom: 18px; }
        h1 { font-size: 22px; color: #1e3a5f; margin-bottom: 6px; }
        h2 { font-size: 16px; color: #1e3a5f; margin-bottom: 12px; }
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
        .token-box { margin: 12px 0; }
        .token-box label { font-size: 12px; color: #64748b; font-weight: 500; }
        .token-box .val { font-family: "Cascadia Code", Consolas, monospace; font-size: 12px; color: #1e293b; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 12px; word-break: break-all; margin-top: 4px; }
        .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }
        .info-table { width: 100%; font-size: 13px; }
        .info-table td { padding: 6px 0; }
        .info-table td:first-child { color: #94a3b8; width: 120px; }
        .sso-info { background: linear-gradient(135deg, #f0fdf4, #ecfdf5); border: 1px solid #bbf7d0; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; font-size: 13px; color: #166534; }
    </style>
</head>
<body>
    <div class="nav">
        <div class="brand">🔐 OAuth2 授权码演示</div>
        <a href="/">首页</a>
        <div class="right">
            ${portalBtn}
            ${logoutBtn}
        </div>
    </div>
    <div class="container">${content}</div>
</body>
</html>`;
}

// ============================================================
// 路由
// ============================================================

/** 首页 — 强制跳转到授权服务器，严格遵循 RFC 6749 §4.1 */
async function renderHome(req, res) {
    // 移除本地会话检查，强制每次都发起新的授权请求
    // 授权服务器会根据 HttpSession 状态决定是否需要用户交互（SSO）
    // 如果用户已登录，服务器会直接颁发新的授权码，无需重新登录
    // 这符合 RFC 6749 §4.1 的标准行为：每次授权请求独立生成令牌
    res.writeHead(302, {
        'Location': getAuthorizationUrl(),
        'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    res.end();
}

/** Token 内省演示 */
async function renderIntrospectDemo(req, res) {
    const session = getSessionTokens(req, res);
    if (!session) {
        res.writeHead(302, {
            'Location': getAuthorizationUrl(),
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const portalAuthUrl = await getPortalSsoUrl();

    let result;
    try {
        result = await introspectToken(session.tokens.access_token, 'access_token');
    } catch (e) {
        return layout('请求失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre><div class="actions"><a href="/" class="btn btn-outline">返回</a></div></div>`, true, portalAuthUrl);
    }

    // RFC 7662: introspect 端点在 token 无效时返回 200 + active=false (而非 401)
    // 但我们仍需要清除本地 session 并跳转到授权服务器，保持与其他按钮行为一致
    if (result.status === 401 || (result.status === 200 && result.data.active === false)) {
        sessions.delete(session.sessionId);
        clearSessionCookie(res);
        res.writeHead(302, {
            'Location': getAuthorizationUrl(),
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
            ${ok ? `
            <table class="info-table">
                <tr><td>active</td><td>${result.data.active ? '✅ 有效' : '❌ 已失效'}</td></tr>
                ${result.data.sub ? `<tr><td>sub</td><td>${esc(result.data.sub)}</td></tr>` : ''}
                ${result.data.username ? `<tr><td>username</td><td>${esc(result.data.username)}</td></tr>` : ''}
                ${result.data.client_id ? `<tr><td>client_id</td><td>${esc(result.data.client_id)}</td></tr>` : ''}
                ${result.data.iss ? `<tr><td>iss</td><td>${esc(result.data.iss)}</td></tr>` : ''}
                ${result.data.aud ? `<tr><td>aud</td><td>${esc(result.data.aud)}</td></tr>` : ''}
                ${result.data.scope ? `<tr><td>scope</td><td>${esc(result.data.scope)}</td></tr>` : ''}
                ${result.data.token_type ? `<tr><td>token_type</td><td>${esc(result.data.token_type)}</td></tr>` : ''}
                ${result.data.exp ? `<tr><td>exp</td><td>${esc(new Date(result.data.exp * 1000).toLocaleString())}</td></tr>` : ''}
                ${result.data.iat ? `<tr><td>iat</td><td>${esc(new Date(result.data.iat * 1000).toLocaleString())}</td></tr>` : ''}
                ${result.data.nbf ? `<tr><td>nbf</td><td>${esc(new Date(result.data.nbf * 1000).toLocaleString())}</td></tr>` : ''}
            </table>
            ` : `<pre>${esc(bodyDisplay)}</pre>`}
            <div class="actions">
                <a href="/userinfo-demo" class="btn btn-outline">👤 查询用户信息</a>
                <a href="/api-demo" class="btn btn-outline">📋 调用通讯录 API</a>
                <a href="/refresh-demo" class="btn btn-outline">🔄 刷新 Token</a>
            </div>
        </div>
    `, true, portalAuthUrl);
}

/** 回调页 — 换 token 并展示 */
async function renderCallback(query, res) {
    // 授权失败
    if (query.error) {
        return layout('授权失败', `
            <div class="card">
                <h1>❌ 授权失败</h1>
                <div style="margin-top:12px;font-size:14px;color:#475569;">
                    错误: <code>${esc(query.error)}</code><br>
                    ${query.error_description ? '描述: ' + esc(query.error_description) : ''}
                </div>
                <div class="actions"><a href="/" class="btn btn-outline">返回重试</a></div>
            </div>
        `);
    }

    const code = query.code;
    if (!code) {
        return layout('错误', `<div class="card"><h1>⚠️ 未收到授权码</h1><div class="actions"><a href="/" class="btn btn-outline">返回</a></div></div>`);
    }

    // 用 code 换 token
    let tokenResult;
    try {
        tokenResult = await exchangeCodeForToken(code);
    } catch (e) {
        return layout('Token 交换失败', `
            <div class="card">
                <h1>⚠️ Token 交换失败</h1>
                <pre>${esc(e.message)}</pre>
                <div class="actions"><a href="/" class="btn btn-outline">返回</a></div>
            </div>
        `);
    }

    if (tokenResult.status !== 200) {
        const err = tokenResult.data.error || '';
        const hint = (err === 'invalid_grant')
            ? `<div class="sub" style="color:#94a3b8;margin-bottom:12px;">授权码已失效或已使用, 请重新发起授权登录。<br>授权码是一次性凭证, 使用后或刷新页面都会失效。</div>`
            : '';
        return layout('Token 交换失败', `
            <div class="card">
                <h1>⚠️ Token 交换失败 (HTTP ${tokenResult.status})</h1>
                ${hint}
                <pre>${esc(JSON.stringify(tokenResult.data, null, 2))}</pre>
                <div class="actions"><a href="/" class="btn btn-primary">重新授权登录</a><a href="/" class="btn btn-outline">返回</a></div>
            </div>
        `);
    }

    const t = tokenResult.data;
    
    // 存 Session
    const sessionId = generateSessionId();
    sessions.set(sessionId, t);
    setSessionCookie(res, sessionId);

    const tokenJson = JSON.stringify(t, null, 2);

    // 解析 JWT payload (不验签, 仅展示)
    function decodeJwt(jwt) {
        try {
            const payload = jwt.split('.')[1];
            return JSON.parse(Buffer.from(payload, 'base64').toString());
        } catch { return null; }
    }
    // OIDC 规范: 用户身份信息应从 id_token 解码, access_token 仅用于调用资源 API
    const idTokenPayload = t.id_token ? decodeJwt(t.id_token) : null;

    return layout('授权成功', `
        <div class="card">
            <h1>✅ 授权成功</h1>
            <div class="sub">已通过授权码换取 Token, 可使用下方按钮访问受保护资源</div>

            <div class="flow">
                <div class="flow-step done">① 发起授权</div>
                <span class="flow-arrow">→</span>
                <div class="flow-step done">② 登录确认</div>
                <span class="flow-arrow">→</span>
                <div class="flow-step done">③ 回调取码</div>
                <span class="flow-arrow">→</span>
                <div class="flow-step done">④ 换取 Token</div>
                <span class="flow-arrow">→</span>
                <div class="flow-step current">⑤ 访问资源</div>
            </div>

            <h2>Token 响应</h2>
            <pre>${esc(tokenJson)}</pre>

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

            <div class="actions">
                <a href="/userinfo-demo" class="btn btn-outline">👤 查询用户信息</a>
                <a href="/api-demo" class="btn btn-outline">📋 调用通讯录 API</a>
                <a href="/refresh-demo" class="btn btn-outline">🔄 刷新 Token</a>
                <a href="/introspect-demo" class="btn btn-outline">🔍 验证 Token</a>
            </div>
        </div>
    `, true);
}

/** 资源 API 演示 */
async function renderApiDemo(req, res) {
    const session = getSessionTokens(req, res);
    if (!session) {
        res.writeHead(302, {
            'Location': getAuthorizationUrl(),
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const portalAuthUrl = await getPortalSsoUrl();

    let result;
    try {
        result = await callResourceServer('/api/contacts', session.tokens.access_token);
    } catch (e) {
        return layout('API 调用失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre></div>`, true, portalAuthUrl);
    }

    if (result.status === 401) {
        // Token 失效：清除本地 session，自动重定向到授权服务器重新登录
        sessions.delete(session.sessionId);
        clearSessionCookie(res);
        res.writeHead(302, {
            'Location': getAuthorizationUrl(),
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const ok = result.status === 200;
    let bodyDisplay = result.body;
    try { bodyDisplay = JSON.stringify(JSON.parse(result.body), null, 2); } catch {}

    return layout('通讯录 API', `
        <div class="card">
            <h1>${ok ? '✅' : '❌'} /api/contacts — HTTP ${result.status}</h1>
            <div class="sub">资源服务器验证 JWT: 签名 + 过期 + aud=contacts-api</div>

            <h2>请求</h2>
            <pre>GET /api/contacts
Authorization: Bearer ${esc(session.tokens.access_token.substring(0, 40))}...</pre>

            <h2 style="margin-top:16px;">响应</h2>
            <pre>${esc(bodyDisplay)}</pre>

            <div class="actions">
                <a href="/userinfo-demo" class="btn btn-outline">👤 查询用户信息</a>
                <a href="/refresh-demo" class="btn btn-outline">🔄 刷新 Token</a>
                <a href="/introspect-demo" class="btn btn-outline">🔍 验证 Token</a>
            </div>
        </div>
    `, true, portalAuthUrl);
}

/** UserInfo 演示 */
async function renderUserinfoDemo(req, res) {
    const session = getSessionTokens(req, res);
    if (!session) {
        res.writeHead(302, {
            'Location': getAuthorizationUrl(),
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const portalAuthUrl = await getPortalSsoUrl();

    let result;
    try {
        result = await callResourceServer('/userinfo', session.tokens.access_token);
    } catch (e) {
        return layout('请求失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre></div>`, true, portalAuthUrl);
    }

    if (result.status === 401) {
        // Token 失效：清除本地 session，自动重定向到授权服务器重新登录
        sessions.delete(session.sessionId);
        clearSessionCookie(res);
        res.writeHead(302, {
            'Location': getAuthorizationUrl(),
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const ok = result.status === 200;
    let bodyDisplay = result.body;
    try { bodyDisplay = JSON.parse(result.body) ? JSON.stringify(JSON.parse(result.body), null, 2) : result.body; } catch {}

    return layout('用户信息', `
        <div class="card">
            <h1>${ok ? '✅' : '❌'} /userinfo — HTTP ${result.status}</h1>
            <div class="sub">OIDC UserInfo 端点, 返回用户基本信息</div>
            <pre>${esc(bodyDisplay)}</pre>
            <div class="actions">
                <a href="/api-demo" class="btn btn-outline">📋 调用通讯录 API</a>
                <a href="/refresh-demo" class="btn btn-outline">🔄 刷新 Token</a>
                <a href="/introspect-demo" class="btn btn-outline">🔍 验证 Token</a>
            </div>
        </div>
    `, true, portalAuthUrl);
}

/** 刷新 token 演示 */
async function renderRefreshDemo(req, res) {
    const session = getSessionTokens(req, res);
    if (!session) {
        res.writeHead(302, {
            'Location': getAuthorizationUrl(),
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const portalAuthUrl = await getPortalSsoUrl();

    let result;
    try {
        result = await refreshAccessToken(session.tokens.refresh_token);
    } catch (e) {
        return layout('刷新失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre></div>`, true, portalAuthUrl);
    }

    // RFC 6749 §5.2: token 端点错误返回 400 (invalid_grant), 401 (client 认证失败) 等
    // 任何非 200 都意味着 refresh_token 已失效 (被强制下线/吊销/过期), 必须清除本地 session
    if (result.status !== 200) {
        // Refresh Token 失效：清除本地 session，自动重定向到授权服务器重新登录
        sessions.delete(session.sessionId);
        clearSessionCookie(res);
        res.writeHead(302, {
            'Location': getAuthorizationUrl(),
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end();
        return;
    }

    const ok = result.status === 200;
    let bodyDisplay = JSON.stringify(result.data, null, 2);

    if (ok && result.data.access_token) {
        // 更新 Session 中的 Token (保留原 id_token, 因 refresh 响应通常不返回新的 id_token)
        const merged = { ...result.data };
        if (!merged.id_token && session.tokens.id_token) {
            merged.id_token = session.tokens.id_token;
        }
        sessions.set(session.sessionId, merged);
    }

    return layout('刷新 Token', `
        <div class="card">
            <h1>${ok ? '✅' : '❌'} Token 刷新 — HTTP ${result.status}</h1>
            <div class="sub">用 refresh_token 换取新的 access_token</div>
            <pre>${esc(bodyDisplay)}</pre>
            <div class="actions">
                <a href="/userinfo-demo" class="btn btn-outline">👤 查询用户信息</a>
                <a href="/api-demo" class="btn btn-outline">📋 调用通讯录 API</a>
                <a href="/introspect-demo" class="btn btn-outline">🔍 验证 Token</a>
            </div>
        </div>
    `, true, portalAuthUrl);
}

// ========== 设计文档 §6-7: Web 应用 A → 门户 的 prompt=none 静默 SSO 回流 ==========

/**
 * 点击"返回门户"端点: 302 到认证中心为 portal-app 发起静默授权.
 */
function handleReturnToPortal(req, res) {
    res.writeHead(302, {
        'Location': getPortalSsoUrl(),
        'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    res.end();
}

/**
 * 门户 SSO 授权回调端点 (/portal-sso-callback).
 * 与 mobile-app 的 handlePortalSsoCallback 逻辑一致:
 *   - code 存在: SAS SSO Session 有效 → 302 到门户首页 (门户自己完成剩余 OAuth2 流程, 依然无感)
 *   - error=login_required: SSO Session 失效 → 302 到门户 /login 触发正常登录
 *   - 其他错误 → 跳门户首页
 */
function handlePortalSsoCallback(query, res) {
    const state = query.state;
    if (state) _portalSsoStates.delete(state);

    let redirectTarget = PORTAL_URL;
    if (query.error === 'login_required') {
        // 设计文档 §7: 无 SAS Session → error=login_required → 转门户正常登录
        console.log('[web-app portal-sso] 认证中心无 SSO Session, 返回 login_required, 转门户正常登录');
        redirectTarget = PORTAL_URL + '/login';
    } else if (query.code) {
        // 设计文档 §7: 有 SAS Session → code 返回 → 用户无感进入门户
        console.log('[web-app portal-sso] 认证中心 SSO Session 有效, 获得 code, 转门户');
    } else if (query.error) {
        console.log('[web-app portal-sso] 授权失败 error=%s desc=%s, 转门户首页', query.error, query.error_description);
    }

    res.writeHead(302, {
        'Location': redirectTarget,
        'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    res.end();
}

// ============================================================
// HTTP 服务
// ============================================================

const server = http.createServer(async (req, res) => {
    const parsed = url.parse(req.url, true);
    const path = parsed.pathname;
    const query = parsed.query;

    try {
        let html;
        switch (path) {
            case '/':
            case '/index.html':
                html = await renderHome(req, res);
                break;
            case '/callback':
                html = await renderCallback(query, res);
                break;
            // 设计文档 §6: A → Portal 静默 SSO 端点
            case '/return-to-portal':
                handleReturnToPortal(req, res);
                return;
            // 设计文档 §6-7: A → Portal prompt=none 授权回调
            case '/portal-sso-callback':
                handlePortalSsoCallback(query, res);
                return;
            case '/logout':
                await handleLogout(req, res);
                return;
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
            default:
                res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end('404 Not Found');
                return;
        }
        // 路由处理函数可能已直接处理了 response (如 token 失效时的 302 重定向)
        if (res.headersSent) return;
        res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end(html);
    } catch (e) {
        if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(layout('服务器错误', `<div class="card"><h1>⚠️ 服务器错误</h1><pre>${esc(e.message)}</pre></div>`));
        }
    }
});

server.listen(PORT, () => {
    console.log('========================================');
    console.log('  OAuth2 授权码登录演示');
    console.log('========================================');
    console.log('  访问: http://localhost:' + PORT);
    console.log('  授权服务器: ' + AUTH_SERVER);
    console.log('  按 Ctrl+C 停止');
    console.log('========================================');
});