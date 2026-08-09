/**
 * OAuth2 授权码 + PKCE 演示 (Public Client)
 * ------------------------------------
 * 模拟原生移动应用 (iOS/Android) 或 无后端纯前端 SPA (Vue/React) 接入场景。
 * 与 oauth2-callback-web-app 的差异 (仅 PKCE 相关):
 *   1) 拼授权 URL 时: 生成 code_verifier + code_challenge, URL 多带 code_challenge + code_challenge_method=S256
 *   2) 换 token 时:   多带 code_verifier, 不带 client_secret (Public Client 无密钥)
 *   3) 刷新/内省/撤销: 不带 client_secret (Public Client 只认 client_id)
 *   其余环节 (调 API / userinfo) 与 web-app 完全一致, 只用 access_token。
 *
 * 启动: node server.js
 * 端口: 8082  (零依赖, 仅用 Node 内置 crypto 模块)
 */

const http = require('http');
const url = require('url');
const crypto = require('crypto');

const PORT = 8082;
const AUTH_SERVER = 'http://localhost:9000';
const CLIENT_ID = 'mobile-app';
// Public Client 无 client_secret, 此处保留为 null 仅作文档说明, 实际请求不会使用
const CLIENT_SECRET = null;
const REDIRECT_URI = 'http://localhost:8082/callback';

// ============================================================
// PKCE 工具函数 (RFC 7636)
// ============================================================

/**
 * 生成 PKCE code_verifier (43~128 字符的高随机度字符串)
 * RFC 7636 §4.1: verifier = 高熵随机串, 字符集 [A-Z / a-z / 0-9 / - . _ ~], 长度 43~128
 */
function generateCodeVerifier() {
    return base64url(crypto.randomBytes(32));
}

/**
 * 由 code_verifier 派生 code_challenge (S256 方法)
 * RFC 7636 §4.2: challenge = BASE64URL-ENCODE(SHA256(ASCII(verifier)))
 */
function generateCodeChallenge(verifier) {
    return base64url(crypto.createHash('sha256').update(verifier).digest());
}

/** Base64URL 编码 (无填充), 用于 verifier / challenge 生成 */
function base64url(buf) {
    return buf.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// ============================================================
// 简易会话管理 (用于演示退出功能和 Token 失效跳转)
// 与 web-app 唯一差异: session 中额外保存 pkce_code_verifier, 供 /callback 换 token 使用
// ============================================================
const sessions = new Map(); // sessionId -> { access_token, refresh_token, id_token, pkce_code_verifier, ... }
const pkceStore = new Map(); // state -> code_verifier  (发起授权时暂存, 回调时取出)

function generateSessionId() {
    return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}

function generateState() {
    return base64url(crypto.randomBytes(16));
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
    return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
        if (timeoutMs && timeoutMs > 0) {
            const timer = setTimeout(() => req.destroy(new Error(`请求超时 (${timeoutMs}ms)`)), timeoutMs);
            req.on('close', () => clearTimeout(timer));
        }
        if (body) req.write(body);
        req.end();
    });
}

/**
 * 生成 OAuth2 授权码 + PKCE 请求 URL
 * 与 web-app 差异:
 *   - 生成 code_verifier + code_challenge
 *   - URL 多带 code_challenge + code_challenge_method=S256
 *   - state 用于关联 pkceStore 中的 verifier (回调时按 state 取回)
 */
function getAuthorizationUrl() {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = generateState();
    // 暂存 verifier, 等回调时按 state 取回 (Map 无 TTL, 演示用, 生产环境应设过期时间)
    pkceStore.set(state, codeVerifier);
    return `${AUTH_SERVER}/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&scope=${encodeURIComponent('openid profile email read write')}` +
        `&state=${state}` +
        `&code_challenge=${codeChallenge}&code_challenge_method=S256`;
}

/**
 * 用 authorization_code + code_verifier 换 token (PKCE 关键步骤)
 * 与 web-app 差异:
 *   - 请求体多带 code_verifier
 *   - 无 Authorization: Basic 头 (Public Client 无密钥)
 */
async function exchangeCodeForToken(code, codeVerifier) {
    const body = `grant_type=authorization_code` +
        `&code=${encodeURIComponent(code)}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&client_id=${CLIENT_ID}` +
        `&code_verifier=${encodeURIComponent(codeVerifier)}`;
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/token', method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body)
        }
    }, body);
    return { status: res.statusCode, data: JSON.parse(res.body) };
}

/** 调用资源 API — 与 web-app 完全一致, 只认 Bearer access_token */
async function callResourceServer(path, accessToken) {
    const res = await request({
        hostname: 'localhost', port: 9000, path: path, method: 'GET',
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return { status: res.statusCode, body: res.body };
}

/**
 * Token 内省 — POST /oauth2/introspect (RFC 7662)
 * 与 web-app 差异: Public Client 无 client_secret, 用 client_id 参数认证
 */
async function introspectToken(token, tokenTypeHint) {
    const body = `token=${encodeURIComponent(token)}` +
        `&token_type_hint=${tokenTypeHint || 'access_token'}` +
        `&client_id=${CLIENT_ID}`;
    const res = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/introspect', method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body)
        }
    }, body);
    return { status: res.statusCode, data: JSON.parse(res.body) };
}

/**
 * 吊销 token — /oauth2/revoke (RFC 7009)
 * 与 web-app 差异: Public Client 无 client_secret, 用 client_id 参数认证
 */
async function revokeToken(token, tokenTypeHint) {
    if (!token) return { ok: false, skipped: true };
    const body = `token=${encodeURIComponent(token)}&token_type_hint=${tokenTypeHint}&client_id=${CLIENT_ID}`;
    try {
        const res = await request({
            hostname: 'localhost', port: 9000, path: '/oauth2/revoke', method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(body)
            }
        }, body, 3000);
        if (res.statusCode === 200) {
            console.log(`[logout] 已吊销 ${tokenTypeHint} (HTTP 200)`);
            return { ok: true };
        }
        console.warn(`[logout] 吊销 ${tokenTypeHint} 失败: HTTP ${res.statusCode} ${res.body}`);
        return { ok: false, status: res.statusCode };
    } catch (e) {
        console.warn(`[logout] 吊销 ${tokenTypeHint} 异常:`, e.message);
        return { ok: false, error: e.message };
    }
}

const CLIENT_LOGIN_URL = 'http://localhost:8082/';

/**
 * 退出登录流程 — 与 web-app 逻辑一致, 仅 client_id 认证方式不同
 */
async function handleLogout(req, res) {
    const sid = getSessionIdFromCookie(req);
    if (sid) {
        const tokens = sessions.get(sid);
        sessions.delete(sid);
        if (tokens) {
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

function layout(title, content, isLoggedIn = false) {
    const logoutBtn = isLoggedIn ? '<a href="/logout" style="margin-left:auto;background:rgba(255,255,255,0.15);color:#fff;border:1px solid rgba(255,255,255,0.35);padding:6px 14px;border-radius:6px;text-decoration:none;font-size:13px;">退出登录</a>' : '';
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
        .pkce-badge { display: inline-block; background: #dbeafe; color: #2563eb; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-left: 8px; vertical-align: middle; }
        .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }
        .info-table { width: 100%; font-size: 13px; }
        .info-table td { padding: 6px 0; }
        .info-table td:first-child { color: #94a3b8; width: 120px; }
    </style>
</head>
<body>
    <div class="nav">
        <div class="brand">🔐 OAuth2 授权码 + PKCE 演示</div>
        <a href="/">首页</a>
        ${logoutBtn}
    </div>
    <div class="container">${content}</div>
</body>
</html>`;
}

// ============================================================
// 路由
// ============================================================

/** 首页 */
async function renderHome(req, res) {
    const session = getSessionTokens(req, res);
    const isLoggedIn = !!session;
    let content = '';
    if (isLoggedIn) {
        content = `
            <div class="card">
                <h1>🎉 欢迎回来</h1>
                <div class="sub">你已通过 PKCE 授权码流程登录, 可以继续操作。</div>
                <div class="actions">
                    <a href="/userinfo-demo" class="btn btn-outline">👤 查询用户信息</a>
                    <a href="/api-demo" class="btn btn-outline">📋 调用通讯录 API</a>
                    <a href="/reauth" class="btn btn-outline">🔄 重新授权</a>
                    <a href="/introspect-demo" class="btn btn-outline">🔍 验证 Token</a>
                </div>
            </div>
        `;
    } else {
        const authUrl = getAuthorizationUrl();
        content = `
            <div class="card">
                <h1>授权码 + PKCE 模式 <span class="pkce-badge">Public Client</span></h1>
                <div class="sub">原生移动应用 / 纯前端 SPA 场景, 无 client_secret, 通过 PKCE 防止授权码拦截攻击</div>
                <div class="flow">
                    <div class="flow-step current">① 发起授权<br><small style="font-weight:normal;">+code_challenge</small></div>
                    <span class="flow-arrow">→</span>
                    <div class="flow-step todo">② 登录确认</div>
                    <span class="flow-arrow">→</span>
                    <div class="flow-step todo">③ 回调取码</div>
                    <span class="flow-arrow">→</span>
                    <div class="flow-step todo">④ 换取 Token<br><small style="font-weight:normal;">+code_verifier</small></div>
                    <span class="flow-arrow">→</span>
                    <div class="flow-step todo">⑤ 访问资源</div>
                </div>
                <p style="font-size:14px;color:#475569;line-height:1.8;margin:16px 0;">
                    点击下方按钮跳转到授权服务器。本服务已自动生成 <code>code_verifier</code> + <code>code_challenge</code>,
                    授权服务器会暂存 challenge; 回调换 token 时需带上 <code>code_verifier</code>,
                    服务器校验 <code>SHA256(verifier) == challenge</code> 才发 token。
                </p>
                <a href="${esc(authUrl)}" class="btn btn-primary">🚀 开始 PKCE 授权登录</a>
            </div>
        `;
    }
    return layout('OAuth2 PKCE 授权码登录演示', content, isLoggedIn);
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

    let result;
    try {
        result = await introspectToken(session.tokens.access_token, 'access_token');
    } catch (e) {
        return layout('请求失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre><div class="actions"><a href="/" class="btn btn-outline">返回</a></div></div>`);
    }

    if (result.status === 401) {
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
            </table>
            ` : `<pre>${esc(bodyDisplay)}</pre>`}
            <div class="actions">
                <a href="/userinfo-demo" class="btn btn-outline">👤 查询用户信息</a>
                <a href="/api-demo" class="btn btn-outline">📋 调用通讯录 API</a>
                <a href="/reauth" class="btn btn-outline">🔄 重新授权</a>
            </div>
        </div>
    `, true);
}

/**
 * 回调页 — 换 token 并展示 (PKCE 关键步骤)
 * 与 web-app 差异:
 *   - 从 query.state 取出 pkceStore 中的 code_verifier
 *   - 调用 exchangeCodeForToken(code, codeVerifier)
 */
async function renderCallback(query, res) {
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
    const state = query.state;
    if (!code) {
        return layout('错误', `<div class="card"><h1>⚠️ 未收到授权码</h1><div class="actions"><a href="/" class="btn btn-outline">返回</a></div></div>`);
    }

    // 按 state 取出暂存的 code_verifier, 取出后立即删除 (一次性)
    const codeVerifier = pkceStore.get(state);
    if (!codeVerifier) {
        return layout('PKCE 校验失败', `
            <div class="card">
                <h1>⚠️ PKCE 状态丢失</h1>
                <div class="sub">未找到 state=${esc(state)} 对应的 code_verifier, 可能会话已过期, 请重新发起授权。</div>
                <div class="actions"><a href="/" class="btn btn-primary">重新授权登录</a></div>
            </div>
        `);
    }
    pkceStore.delete(state);

    let tokenResult;
    try {
        tokenResult = await exchangeCodeForToken(code, codeVerifier);
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
            ? `<div class="sub" style="color:#94a3b8;margin-bottom:12px;">授权码已失效或 code_verifier 校验失败, 请重新发起授权登录。</div>`
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

    const sessionId = generateSessionId();
    sessions.set(sessionId, t);
    setSessionCookie(res, sessionId);

    const tokenJson = JSON.stringify(t, null, 2);

    function decodeJwt(jwt) {
        try {
            const payload = jwt.split('.')[1];
            return JSON.parse(Buffer.from(payload, 'base64').toString());
        } catch { return null; }
    }
    const idTokenPayload = t.id_token ? decodeJwt(t.id_token) : null;

    return layout('授权成功', `
        <div class="card">
            <h1>✅ 授权成功 <span class="pkce-badge">PKCE</span></h1>
            <div class="sub">已通过授权码 + code_verifier 换取 Token</div>

            <div class="flow">
                <div class="flow-step done">① 发起授权<br><small style="font-weight:normal;">+code_challenge</small></div>
                <span class="flow-arrow">→</span>
                <div class="flow-step done">② 登录确认</div>
                <span class="flow-arrow">→</span>
                <div class="flow-step done">③ 回调取码</div>
                <span class="flow-arrow">→</span>
                <div class="flow-step done">④ 换取 Token<br><small style="font-weight:normal;">+code_verifier</small></div>
                <span class="flow-arrow">→</span>
                <div class="flow-step current">⑤ 访问资源</div>
            </div>

            <h2>Token 响应</h2>
            <pre>${esc(tokenJson)}</pre>

            ${!t.refresh_token ? `
            <div style="margin-top:12px;padding:12px;background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;font-size:13px;color:#92400e;line-height:1.7;">
                ℹ️ <b>Public Client 不签发 refresh_token</b> — 这是 SAS 安全策略 (RFC 8252): Public Client 无法安全存储 refresh_token, 签发会有被窃取后无限刷新的风险。<br>
                access_token 过期后请点击"重新授权"静默获取新 token (若授权服务器 session 仍有效, 无需重新登录)。
            </div>
            ` : ''}

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
                <a href="/reauth" class="btn btn-outline">🔄 重新授权</a>
                <a href="/introspect-demo" class="btn btn-outline">🔍 验证 Token</a>
            </div>
        </div>
    `, true);
}

/** 资源 API 演示 — 与 web-app 完全一致, 只用 access_token 调用 */
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

    let result;
    try {
        result = await callResourceServer('/api/contacts', session.tokens.access_token);
    } catch (e) {
        return layout('API 调用失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre></div>`);
    }

    if (result.status === 401) {
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
            <div class="sub">资源服务器验证 access_token (Opaque introspect)</div>

            <h2>请求</h2>
            <pre>GET /api/contacts
Authorization: Bearer ${esc(session.tokens.access_token.substring(0, 40))}...</pre>

            <h2 style="margin-top:16px;">响应</h2>
            <pre>${esc(bodyDisplay)}</pre>

            <div class="actions">
                <a href="/userinfo-demo" class="btn btn-outline">👤 查询用户信息</a>
                <a href="/reauth" class="btn btn-outline">🔄 重新授权</a>
                <a href="/introspect-demo" class="btn btn-outline">🔍 验证 Token</a>
            </div>
        </div>
    `, true);
}

/** UserInfo 演示 — 与 web-app 完全一致, 只用 access_token 调用 */
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

    let result;
    try {
        result = await callResourceServer('/userinfo', session.tokens.access_token);
    } catch (e) {
        return layout('请求失败', `<div class="card"><h1>⚠️ 请求失败</h1><pre>${esc(e.message)}</pre></div>`);
    }

    if (result.status === 401) {
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
                <a href="/reauth" class="btn btn-outline">🔄 重新授权</a>
                <a href="/introspect-demo" class="btn btn-outline">🔍 验证 Token</a>
            </div>
        </div>
    `, true);
}

/**
 * 重新授权 (静默) — Public Client 无 refresh_token, access_token 过期后直接重新走授权码流程。
 * 若授权服务器 session (PORTAL_SECURITY_CONTEXT) 仍有效, 用户无需重新登录, 整个过程无感知。
 * 这就是 SPA / 移动端的 "silent renew" 替代方案。
 */
function handleReauth(req, res) {
    // 清除旧 session, 避免残留已过期的 token
    const sid = getSessionIdFromCookie(req);
    if (sid) sessions.delete(sid);
    clearSessionCookie(res);
    res.writeHead(302, {
        'Location': getAuthorizationUrl(),
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
            case '/logout':
                await handleLogout(req, res);
                return;
            case '/api-demo':
                html = await renderApiDemo(req, res);
                break;
            case '/userinfo-demo':
                html = await renderUserinfoDemo(req, res);
                break;
            case '/reauth':
                handleReauth(req, res);
                return;
            case '/introspect-demo':
                html = await renderIntrospectDemo(req, res);
                break;
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
            res.end(layout('服务器错误', `<div class="card"><h1>⚠️ 服务器错误</h1><pre>${esc(e.message)}</pre></div>`));
        }
    }
});

server.listen(PORT, () => {
    console.log('========================================');
    console.log('  OAuth2 授权码 + PKCE 演示 (Public Client)');
    console.log('========================================');
    console.log('  访问: http://localhost:' + PORT);
    console.log('  授权服务器: ' + AUTH_SERVER);
    console.log('  客户端: ' + CLIENT_ID + ' (无 client_secret)');
    console.log('  按 Ctrl+C 停止');
    console.log('========================================');
});
