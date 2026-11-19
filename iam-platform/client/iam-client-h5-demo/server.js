/**
 * OA H5 演示 (iam-client-h5-demo) — 纯 Web 应用的 H5 形态
 * ------------------------------------------------------------------
 * 对接方式与 web-demo (8081) 本质一模一样:
 *   机密客户端 + 授权码 + PKCE(S256) + 服务端换票 (client_secret 不进浏览器)
 *   client_id = oa-h5-app   secret = 123456   redirect = http://localhost:8084/callback
 *
 * 页面布局: 左侧手机模拟器 (硬编码业务模块) + 右侧对接控制台
 *   (连接配置 / 运行状态 / 事件终端 — 服务端换票事件与前端调用实时打点)。
 *
 * 端口: 8084 (零依赖, 仅 node 内置模块)
 */
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = 8084;
const AUTH_SERVER = 'http://localhost:9000';
const PORTAL_URL = 'http://localhost:8000';
const CLIENT_ID = 'oa-h5-app';
const CLIENT_SECRET = '123456';
const REDIRECT_URI = 'http://localhost:8084/callback';
const SCOPES = 'openid profile email';

// ========== 返回门户: prompt=none 静默 SSO 回流 (与 web-demo 同款) ==========
const PORTAL_CLIENT_ID = 'portal-app';
const PORTAL_SSO_REDIRECT_URI = 'http://localhost:8084/portal-sso-callback';
const _portalSsoStates = new Set();

/** 生成「返回门户」静默授权 URL: 有 SSO Session → 直接发 code 不弹登录; 无 → error=login_required */
function getPortalSsoUrl() {
    const state = newId();
    _portalSsoStates.add(state);
    // portal-app requireProofKey=true, 必须带 PKCE (verifier 仅做 SSO 探测, 不用于换票)
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    let url = `${AUTH_SERVER}/oauth2/authorize?response_type=code&client_id=${PORTAL_CLIENT_ID}`;
    url += `&redirect_uri=${encodeURIComponent(PORTAL_SSO_REDIRECT_URI)}`;
    url += `&scope=${encodeURIComponent('openid profile')}`;
    url += `&state=${state}`;
    url += `&code_challenge=${challenge}&code_challenge_method=S256`;
    url += `&prompt=none`;
    return url;
}

/** 返回门户回调: 不换票, 仅按 SSO 探测结果转门户 (login_required → 门户正常登录) */
function handlePortalSsoCallback(query, res) {
    if (query.state) _portalSsoStates.delete(query.state);
    let target = PORTAL_URL;
    if (query.error === 'login_required') {
        console.log('[oa-h5-app portal-sso] 无 SSO Session → login_required, 转门户正常登录');
        target = PORTAL_URL + '/login';
    } else if (query.code) {
        console.log('[oa-h5-app portal-sso] SSO Session 有效, 获得 code, 转门户 (无感)');
    } else if (query.error) {
        console.log('[oa-h5-app portal-sso] 授权失败 error=%s, 转门户首页', query.error);
    }
    res.writeHead(302, { 'Location': target, 'Cache-Control': 'no-cache, no-store, must-revalidate' });
    res.end();
}

// ============================================================
// 会话与 PKCE (与 web-demo 同款实现)
// ============================================================
const sessions = new Map();        // sessionId -> { access_token, ..., events: [] }
const pkceStates = new Map();      // state -> code_verifier (一次性)
const pendingLoginFrom = new Map(); // state -> 发起登录前想打开的模块 (回调后续开)

function newId() { return crypto.randomBytes(16).toString('base64url'); }

function now() { return new Date().toTimeString().substring(0, 8); }

/** 服务端事件打点 (渲染进右侧控制台终端) */
function logEvent(sess, msg) {
    if (!sess) return;
    if (!sess.events) sess.events = [];
    sess.events.push({ t: now(), m: msg });
    if (sess.events.length > 30) sess.events.shift();
}

function getSession(req) {
    const m = (req.headers.cookie || '').match(/sessionId=([^;]+)/);
    if (!m) return null;
    const s = sessions.get(m[1]);
    return s ? { sessionId: m[1], s } : null;
}
function setSession(res, sid) {
    res.setHeader('Set-Cookie', `sessionId=${sid}; Path=/; HttpOnly; SameSite=Lax`);
}
function clearSession(res) {
    res.setHeader('Set-Cookie', 'sessionId=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax');
}

function esc(str) {
    return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function request(options, body, timeoutMs) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
        });
        req.on('error', reject);
        if (timeoutMs > 0) {
            const t = setTimeout(() => req.destroy(new Error(`请求超时 (${timeoutMs}ms)`)), timeoutMs);
            req.on('close', () => clearTimeout(t));
        }
        if (body) req.write(body);
        req.end();
    });
}

/** 发起授权码 + PKCE (与 web-demo getAuthorizationUrl 同构); state 关联发起前的模块 (回调后续开) */
function buildAuthorizeUrl(from) {
    const state = newId();
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    pkceStates.set(state, verifier);                 // 换票时取回, 一次性
    pendingLoginFrom.set(state, from || 'home');     // 登录回来继续打开该模块
    return `${AUTH_SERVER}/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&scope=${encodeURIComponent(SCOPES)}` +
        `&state=${state}` +
        `&code_challenge=${challenge}&code_challenge_method=S256`;
}

/** 用授权码换令牌 (服务端持 secret) */
async function exchangeCode(code, verifier) {
    const body = `grant_type=authorization_code&code=${encodeURIComponent(code)}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&code_verifier=${encodeURIComponent(verifier)}`;
    const auth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const r = await request({
        hostname: 'localhost', port: 9000, path: '/oauth2/token', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${auth}` }
    }, body, 10000);
    if (r.statusCode !== 200) throw new Error(`换票失败 HTTP ${r.statusCode}: ${r.body}`);
    return JSON.parse(r.body);
}

/** 解 payload 无签名验签 (仅演示展示) */
function decodeJwtPayload(jwt) {
    try {
        const p = jwt.split('.')[1];
        return JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    } catch { return {}; }
}

// ============================================================
// 页面数据 (手机模拟器硬编码业务模块)
// ============================================================
const MODULES = [
    { id: 'leave',   name: '请假管理', icon: '🏝️', desc: '年假 / 事假 / 调休申请与审批' },
    { id: 'expense', name: '报销审核', icon: '🧾', desc: '差旅、办公费用报销单审核' },
    { id: 'approve', name: '审批中心', icon: '✅', desc: '待办审批聚合, 一键处理' },
    { id: 'attend',  name: '考勤打卡', icon: '🕐', desc: '上下班打卡 / 排班查询' },
    { id: 'contacts',name: '通讯录',   icon: '📇', desc: '组织架构与员工查询' },
    { id: 'more',    name: '更多应用', icon: '🧩', desc: '敬请期待' }
];

/** 模块 mock 数据 (仅登录后可见, 演示「令牌保护的资源」) */
const MODULE_DATA = {
    leave:   [{ title: '年假申请',   status: '已通过', date: '2026-10-01 ~ 10-05' }, { title: '事假申请', status: '审批中', date: '2026-11-10' }],
    expense: [{ title: '上海出差差旅费', amount: '¥ 2,480.00', status: '待审核' }, { title: '办公用品采购', amount: '¥ 356.50', status: '已打款' }],
    approve: [{ title: '张三的请假单', from: 'HR 系统', wait: '2 小时' }, { title: '李四的报销单', from: '财务系统', wait: '1 天' }],
    attend:  [{ title: '今日打卡', in: '09:02', out: '-' }, { title: '昨日打卡', in: '08:57', out: '18:31' }],
    contacts: [{ name: '王五', dept: '研发部', tel: '138****0001' }, { name: '赵六', dept: '产品部', tel: '139****0002' }],
    more: []
};

function phoneShell(session, notice = null) {
    const logged = !!session;
    const userTag = logged
        ? `<span class="chip ok">已登录: ${esc(session.s.username || '')}</span>`
        : `<span class="chip">未登录</span>`;
    const moduleCards = MODULES.map(m => `
        <div class="app-cell" onclick="openModule('${m.id}')">
            <div class="app-ico">${m.icon}</div>
            <div class="app-name">${m.name}</div>
        </div>`).join('');

    // ===== 右侧控制台: 连接配置 =====
    const cfgRows = [
        ['认证中心', AUTH_SERVER],
        ['client_id', CLIENT_ID],
        ['认证方式', 'client_secret_basic (secret 仅存服务端)'],
        ['授权模式', 'authorization_code + refresh_token'],
        ['PKCE', '强制 S256 (requireProofKey=true)'],
        ['redirect_uri', REDIRECT_URI],
        ['返回门户回调', PORTAL_SSO_REDIRECT_URI],
        ['对齐关系', '与 web 版 (8081) 本质一模一样, 仅 UI 壳不同']
    ].map(r => `<div class="k">${esc(r[0])}</div><div class="v">${esc(r[1])}</div>`).join('');

    // ===== 运行状态 =====
    const statusBadge = logged
        ? `<span class="badge ok">● 已登录 ${esc(session.s.username || '')}</span>`
        : `<span class="badge off">● 未登录</span>`;
    const statusRows = [
        ['scope', session ? (session.s.scope || '-') : '-'],
        ['令牌剩余', logged ? '<span id="ttl">--</span> 秒' : '-'],
        ['受保护接口', '/api/module (无令牌 401)'],
        ['会话', logged ? esc(session.sessionId.substring(0, 10)) + '…' : '-']
    ].map(r => `<div class="k">${esc(r[0])}</div><div class="v">${r[1]}</div>`).join('');

    // ===== 事件终端 (服务端事件预渲染 + 前端实时打点) =====
    const srvEvents = (session && session.s.events || [])
        .map(e => `<div class="logline"><span class="lt">[${esc(e.t)}]</span><span class="tag auth">srv</span>${esc(e.m)}</div>`)
        .join('');

    const expiresAt = logged ? session.s.expires : 0;

    return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OA H5 演示 · 模拟器 + 对接控制台</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; background: #0f172a; min-height: 100vh;
         display: flex; flex-direction: column; align-items: center; padding: 20px; color: #1e293b; }
  .desk-head { color: #94a3b8; font-size: 13px; margin-bottom: 16px; text-align: center; line-height: 1.8; }
  .desk-head b { color: #e2e8f0; font-size: 16px; }
  .desk-head code { background:#1e293b; color:#7dd3fc; padding:1px 5px; border-radius:4px; }
  /* ===== 左右舞台 ===== */
  .stage { display: flex; gap: 26px; align-items: flex-start; justify-content: center; flex-wrap: wrap; }
  /* ===== 左: 手机壳 ===== */
  .phone { width: 390px; background: #0b1220; border-radius: 44px; padding: 12px; box-shadow: 0 24px 60px rgba(0,0,0,.55), inset 0 0 0 2px #334155; flex-shrink: 0; }
  .screen { background: #f5f7fb; border-radius: 34px; overflow: hidden; min-height: 720px; display: flex; flex-direction: column; }
  .statusbar { height: 34px; background: linear-gradient(135deg,#2563eb,#4f46e5); color:#fff; display:flex; align-items:center; justify-content:space-between; padding: 0 18px; font-size: 12px; }
  .appbar { background: linear-gradient(135deg,#2563eb,#4f46e5); color:#fff; padding: 10px 16px 16px; }
  .appbar h1 { font-size: 18px; }
  .appbar .sub { font-size: 11px; opacity: .85; margin-top: 2px; }
  .chip { display:inline-block; background: rgba(255,255,255,.18); border:1px solid rgba(255,255,255,.4); color:#fff; font-size:11px; border-radius: 10px; padding: 2px 8px; margin-top: 8px; }
  .chip.ok { background: rgba(34,197,94,.25); border-color:#4ade80; }
  .banner { margin: 10px 12px 0; background: #fff7ed; border: 1px dashed #fdba74; color: #9a3412; font-size: 12px; border-radius: 10px; padding: 8px 10px; }
  .banner.err { background: #fef2f2; border: 1px dashed #fca5a5; color: #991b1b; line-height: 1.7; }
  .banner.err code { background: #fee2e2; padding: 1px 5px; border-radius: 4px; }
  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; padding: 14px 12px; }
  .app-cell { background: #fff; border-radius: 14px; padding: 14px 6px; text-align: center; cursor: pointer; transition: .15s; border: 1px solid #eef2f7; }
  .app-cell:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(37,99,235,.15); }
  .app-ico { font-size: 26px; }
  .app-name { font-size: 12px; margin-top: 6px; color: #334155; }
  .panel { margin: 0 12px 12px; background:#fff; border-radius: 14px; border: 1px solid #eef2f7; padding: 12px; display:none; }
  .panel.show { display:block; }
  .panel h3 { font-size: 14px; color:#1e3a5f; margin-bottom: 8px; display:flex; justify-content:space-between; align-items:center; }
  .panel h3 a { font-size: 11px; color:#64748b; cursor:pointer; text-decoration:none; }
  .row { display:flex; justify-content:space-between; font-size:12px; padding:7px 0; border-bottom:1px dashed #eef2f7; color:#475569; }
  .row:last-child { border-bottom:none; }
  .empty { font-size:12px; color:#94a3b8; text-align:center; padding: 10px 0; }
  .footer { margin-top:auto; background:#fff; border-top:1px solid #eef2f7; padding: 10px 12px; display:flex; gap:8px; }
  .btn { flex:1; text-align:center; font-size:12px; padding:9px 0; border-radius:10px; cursor:pointer; border:none; text-decoration:none; }
  .btn.primary { background:#2563eb; color:#fff; }
  .btn.ghost { background:#eef2f7; color:#334155; }
  .btn.danger { background:#fee2e2; color:#dc2626; }
  /* ===== 右: 对接控制台 ===== */
  .console { width: 620px; max-width: 100%; display: flex; flex-direction: column; gap: 14px; }
  .cardx { background: #111c33; border: 1px solid #24344f; border-radius: 14px; padding: 14px 16px; }
  .cardx h4 { color: #e2e8f0; font-size: 13px; margin-bottom: 12px; letter-spacing: .5px; display:flex; justify-content:space-between; align-items:center; }
  .cardx h4 small { color:#64748b; font-weight: normal; font-size: 11px; }
  .kv { display: grid; grid-template-columns: 108px 1fr; gap: 7px 10px; font-size: 12px; align-items: baseline; }
  .kv .k { color: #7f93ad; }
  .kv .v { font-family: Consolas, "Cascadia Code", monospace; color: #7dd3fc; word-break: break-all; }
  .badges { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
  .badge { font-size: 11px; border-radius: 8px; padding: 3px 9px; background: #1d2c4a; color: #93c5fd; font-family: Consolas, monospace; }
  .badge.ok { background: rgba(34,197,94,.15); color: #4ade80; }
  .badge.off { background: rgba(239,68,68,.15); color: #f87171; }
  .terminal { background: #0b1220; border: 1px solid #1e293b; border-radius: 10px; padding: 10px 12px; height: 232px;
              overflow-y: auto; font-family: Consolas, "Cascadia Code", monospace; font-size: 11.5px; line-height: 1.9; }
  .logline { color: #94a3b8; white-space: nowrap; }
  .logline .lt { color: #475569; margin-right: 6px; }
  .logline .tag { display: inline-block; padding: 0 5px; border-radius: 4px; font-size: 10px; margin-right: 6px; }
  .tag.sys  { background: #1e3a5f; color: #7dd3fc; }
  .tag.click{ background: #3b2f7a; color: #c4b5fd; }
  .tag.api  { background: #14532d; color: #86efac; }
  .tag.auth { background: #7c2d12; color: #fdba74; }
  .tag.err  { background: #7f1d1d; color: #fecaca; }
  .clearbtn { background: none; border: 1px solid #334155; color: #94a3b8; font-size: 11px; border-radius: 6px; padding: 2px 9px; cursor: pointer; }
  .clearbtn:hover { border-color:#2563eb; color:#7dd3fc; }
  .desc { margin-top: 12px; border-top: 1px dashed #24344f; padding-top: 10px; }
  .desc b { color: #cbd5e1; font-size: 12px; }
  .desc ul { margin: 6px 0 0 18px; font-size: 12px; line-height: 2; color: #94a3b8; }
  .desc code { background:#0b1220; color:#7dd3fc; padding:1px 5px; border-radius:4px; font-size:11px; }
  @media (max-width: 1120px) { .stage { flex-direction: column; align-items: center; } .console { width: 390px; } }
</style></head><body>
  <div class="desk-head"><b>OA H5 演示</b> · 纯 Web 应用的 H5 形态 — 左: 手机模拟器 (业务壳) / 右: 对接控制台 (OAuth2 事实) <br>也可用手机访问 <code>本机IP:8084</code></div>
  <div class="stage">
    <!-- ================= 左: 手机模拟器 ================= -->
    <div class="phone">
      <div class="screen">
        <div class="statusbar"><span>9:41</span><span>📶 ⚡ 🔋</span></div>
        <div class="appbar">
          <h1>移动办公 · OA</h1>
          <div class="sub">授权码 + PKCE 对接 · client_id: oa-h5-app</div>
          ${userTag}
        </div>
        ${notice ? `<div class="banner err">${notice}</div>` : ''}
        ${logged ? '' : '<div class="banner">未登录 — 点击任意模块将发起授权码登录 (SSO 在场则免登)</div>'}
        <div class="grid">${moduleCards}</div>
        <div class="panel" id="panel"><h3><span id="panelTitle"></span><a onclick="closePanel()">收起 ✕</a></h3><div id="panelBody"></div></div>
        <div class="footer">
          ${logged
            ? '<a class="btn ghost" href="/me">令牌信息</a><a class="btn danger" href="/logout">退出登录</a>'
            : '<a class="btn primary" href="/login">登录 (授权码+PKCE)</a>'}
          <a class="btn ghost" href="/return-to-portal">🏠 返回门户</a>
        </div>
      </div>
    </div>

    <!-- ================= 右: 对接控制台 ================= -->
    <div class="console">
      <div class="cardx">
        <h4>⚙️ 连接配置 <small>client 注册事实 (与 8081 同款)</small></h4>
        <div class="kv">${cfgRows}</div>
      </div>

      <div class="cardx">
        <h4>📡 运行状态 <small>本页会话实时</small></h4>
        <div class="badges">${statusBadge}<span class="badge">modules: ${MODULES.length}</span><span class="badge">PKCE: S256</span></div>
        <div class="kv">${statusRows}</div>
      </div>

      <div class="cardx">
        <h4>🖥️ 事件终端 <button class="clearbtn" onclick="clearCon()">清空</button></h4>
        <div class="terminal" id="con">
          <div class="logline"><span class="lt">[${now()}]</span><span class="tag sys">sys</span>页面加载 (左右布局 · 模拟器 + 控制台)</div>
          <div class="logline"><span class="lt">[${now()}]</span><span class="tag sys">sys</span>${logged ? '会话有效, 点击模块请求受保护数据' : '未登录 — 点击模块发起授权码 + PKCE 登录'}</div>
          ${srvEvents}
        </div>
        <div class="desc">
          <b>对接要点 (与 web 版本质一致)</b>
          <ul>
            <li>机密客户端: <code>client_secret</code> 只存本服务, 换票由服务端发起, 不进浏览器</li>
            <li><code>PKCE S256</code> 强制: 授权请求带 code_challenge, 换票回传 code_verifier, 防授权码拦截</li>
            <li>模块数据经 <code>/api/module</code> 以会话令牌换取 — 无令牌 401, 令牌过期 401</li>
            <li><code>返回门户</code> 走 portal-app + <code>prompt=none</code> 静默回流, 不弹登录页</li>
            <li>SSO 在场时登录全程免输账号 (9000 会话复用), 首次授权弹同意页</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
<script>
const EXPIRES = ${expiresAt};
const LOGGED = ${logged ? 'true' : 'false'};

function escHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

/** 前端事件打点 → 右侧终端 */
function clog(tag, msg, cls) {
    const box = document.getElementById('con');
    const t = new Date().toTimeString().substring(0, 8);
    const div = document.createElement('div');
    div.className = 'logline';
    div.innerHTML = '<span class="lt">[' + t + ']</span><span class="tag ' + (cls || tag) + '">' + tag + '</span>' + escHtml(msg);
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
}
function clearCon() {
    document.getElementById('con').innerHTML = '';
    clog('sys', '日志已清空');
}

/** 令牌倒计时 */
function tickTtl() {
    const el = document.getElementById('ttl');
    if (!el || !EXPIRES) return;
    const left = Math.round((EXPIRES - Date.now()) / 1000);
    el.textContent = left > 0 ? left : '已过期';
    el.style.color = left > 60 ? '#7dd3fc' : '#f87171';
}
setInterval(tickTtl, 1000); tickTtl();

/** 登录回跳事件回放 (?log=login_ok) + 模块续开 (?resume=xxx) */
const qs = new URLSearchParams(location.search);
if (qs.get('log') === 'login_ok') clog('auth', '授权码换票成功, 会话已建立 (SSO 免登或同意后发码)');
if (qs.get('resume')) {
    const mod = qs.get('resume');
    clog('sys', '继续打开登录前选择的模块: ' + mod);
    setTimeout(() => openModule(mod), 300);
}

async function openModule(id) {
    if (!LOGGED) {
        clog('click', '点击模块 ' + id + ' → 发起授权码登录 (带 PKCE)');
        location.href = '/start?from=' + encodeURIComponent(id);
        return;
    }
    clog('click', '点击模块 ' + id);
    const res = await fetch('/api/module?id=' + id);
    const data = await res.json();
    clog('api', 'GET /api/module?id=' + id + ' → ' + res.status + (res.status === 200 ? ' (' + ((data.items||[]).length) + ' 条)' : ' ' + (data.error||'')), res.status === 200 ? 'api' : 'err');
    const panel = document.getElementById('panel');
    document.getElementById('panelTitle').textContent = data.moduleName + ' (令牌保护数据)';
    const body = document.getElementById('panelBody');
    if (!data.items || data.items.length === 0) {
        body.innerHTML = '<div class="empty">暂无数据</div>';
    } else {
        body.innerHTML = data.items.map(it => {
            const parts = Object.entries(it).map(([k, v]) => '<span>' + k + ': <b>' + escHtml(v) + '</b></span>');
            return '<div class="row">' + parts.join('<span style="color:#cbd5e1">|</span>') + '</div>';
        }).join('');
    }
    panel.classList.add('show');
}
function closePanel(){ document.getElementById('panel').classList.remove('show'); }
</script>
</body></html>`;
}

// ============================================================
// HTTP 路由
// ============================================================
const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, `http://localhost:${PORT}`);
    const path = u.pathname;
    const session = getSession(req);

    try {
        // 发起登录 (授权码 + PKCE); from 记录到 state, 回调后继续打开该模块
        if (path === '/start' || path === '/login') {
            const from = u.searchParams.get('from') || 'home';
            res.writeHead(302, { Location: buildAuthorizeUrl(from) + `&nonce=${newId()}` });
            return res.end();
        }

        // 授权回调: code 换票 (服务端持 secret)
        if (path === '/callback') {
            const code = u.searchParams.get('code');
            const state = u.searchParams.get('state');
            const err = u.searchParams.get('error');
            if (err) {
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                return res.end(phoneShell(null, `⚠️ 授权失败: <code>${esc(err)}</code> ${esc(u.searchParams.get('error_description') || '')} — 点击底部「登录」重新发起授权码 + PKCE 流程`));
            }
            const verifier = pkceStates.get(state);
            if (!code || !verifier) {
                res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
                return res.end(phoneShell(null, '⚠️ state 校验失败 (页面可能已过期或已使用) — 点击底部「登录」重新发起授权码 + PKCE 流程'));
            }
            const from = pendingLoginFrom.get(state) || 'home';
            pkceStates.delete(state);       // 一次性
            pendingLoginFrom.delete(state);
            const tok = await exchangeCode(code, verifier);
            const payload = decodeJwtPayload(tok.id_token || tok.access_token || '');
            const sid = newId();
            const sess = {
                access_token: tok.access_token,
                refresh_token: tok.refresh_token,
                id_token: tok.id_token,
                scope: tok.scope,
                expires: Date.now() + (tok.expires_in || 300) * 1000,
                username: payload.preferred_username || payload.sub || '',
                events: []
            };
            logEvent(sess, `POST /oauth2/token 换票成功 (Basic ${CLIENT_ID}, PKCE verifier 校验通过)`);
            logEvent(sess, `access_token 有效期 ${tok.expires_in || '?'}s · scope=${tok.scope || '-'}`);
            sessions.set(sid, sess);
            setSession(res, sid);
            const back = from && from !== 'home' ? `/?log=login_ok&resume=${encodeURIComponent(from)}` : '/?log=login_ok';
            res.writeHead(302, { Location: back });
            return res.end();
        }

        // 返回门户 (prompt=none 静默 SSO 回流)
        if (path === '/return-to-portal') {
            res.writeHead(302, { Location: getPortalSsoUrl() });
            return res.end();
        }
        if (path === '/portal-sso-callback') {
            return handlePortalSsoCallback(u.searchParams, res);
        }

        // 令牌信息
        if (path === '/me') {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            if (!session) { return res.end('<meta http-equiv="refresh" content="0;url=/">'); }
            const p = decodeJwtPayload(session.s.id_token || session.s.access_token || '');
            const rows = [
                ['登录账号', session.s.username],
                ['scope', session.s.scope],
                ['令牌剩余', Math.max(0, Math.round((session.s.expires - Date.now()) / 1000)) + ' 秒'],
                ['id_token.sub', p.sub || '-'],
                ['id_token.preferred_username', p.preferred_username || '-'],
                ['id_token.issuer', p.iss || '-'],
                ['access_token 前缀', (session.s.access_token || '').substring(0, 36) + '...']
            ].map(r => `<div class="row"><span>${esc(r[0])}</span><b style="font-family:monospace;font-size:11px;word-break:break-all;max-width:60%;text-align:right">${esc(r[1])}</b></div>`).join('');
            return res.end(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>令牌信息 · OA H5</title>
<style>body{font-family:-apple-system,"Microsoft YaHei";background:#f0f2f5;padding:24px;max-width:640px;margin:0 auto}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px}
.row{display:flex;justify-content:space-between;gap:12px;font-size:13px;padding:8px 0;border-bottom:1px dashed #eef2f7}
.row:last-child{border:none}a{color:#2563eb;font-size:13px}</style></head><body>
<div class="card"><h3 style="margin-bottom:8px">🎫 令牌信息 (oa-h5-app)</h3>${rows}
<p style="margin-top:14px"><a href="/">← 返回模拟器首页</a></p></div></body></html>`);
        }

        // 退出 (本地会话; 9000 侧 SSO 会话保留 — 跨端免登仍在, 演示单点注销时可扩展)
        if (path === '/logout') {
            if (session) sessions.delete(session.sessionId);
            clearSession(res);
            res.writeHead(302, { Location: '/' });
            return res.end();
        }

        // 受保护 API: 令牌会话换取模块数据 (模拟资源接口)
        if (path === '/api/module') {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            if (!session) { res.statusCode = 401; return res.end(JSON.stringify({ error: '未登录 (无会话)' })); }
            if (Date.now() > session.s.expires) {
                logEvent(session.s, 'GET /api/module → 401 令牌已过期');
                res.statusCode = 401; return res.end(JSON.stringify({ error: '令牌已过期, 请重新登录' }));
            }
            const id = u.searchParams.get('id') || '';
            const m = MODULES.find(x => x.id === id);
            if (!m) { res.statusCode = 404; return res.end(JSON.stringify({ error: '模块不存在' })); }
            logEvent(session.s, `GET /api/module?id=${id} → 200 (${(MODULE_DATA[id] || []).length} 条)`);
            return res.end(JSON.stringify({ moduleName: m.name, items: MODULE_DATA[id] || [] }));
        }

        // 首页
        if (path === '/' || path === '/index.html') {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate' });
            return res.end(phoneShell(session));
        }

        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('404 Not Found');
    } catch (e) {
        res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(phoneShell(null, `⚠️ 服务器错误: ${esc(e && e.message ? e.message : e)}`));
    }
});

server.listen(PORT, () => {
    console.log(`[oa-h5-demo] http://localhost:${PORT}  (client_id=${CLIENT_ID}, 授权码+PKCE, 左右布局: 模拟器+控制台)`);
});
