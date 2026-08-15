/* ============================================================
 * iam-admin-web 全局通用脚本
 * ------------------------------------------------------------
 * App.guard()         登录守卫: 未登录 → /login; 非管理端(异常兜底) → /logout
 * App.api(path, opts) fetch 封装: 统一 JSON、业务码校验、401/403 踢回登录
 * App.renderNavbar(key[, user]) 渲染顶部导航(右侧显示当前用户)并绑定退出登录
 * App.esc(s)          HTML 转义
 * App.fmtTime(t)      "2026-01-01T08:00:00" → "2026-01-01 08:00:00"
 * ============================================================ */
window.App = (() => {
    const LOGIN_URL = '/login';

    function esc(s) {
        if (s === null || s === undefined) return '';
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function fmtTime(t) {
        if (!t) return '-';
        return String(t).replace('T', ' ').substring(0, 19);
    }

    /**
     * fetch 封装: 同源 /api/** (Cookie 自动携带)。
     * - 非 GET 且 body 为对象时自动 JSON 序列化
     * - 401/403 会话失效 → 踢回登录页, 抛异常中断后续
     * - 业务 code !== 200 → 抛异常
     * @returns {Promise<any>} 后端 Result.data
     */
    async function api(path, options = {}) {
        const opts = { ...options };
        opts.headers = opts.headers || {};
        if (opts.body && typeof opts.body !== 'string') {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(opts.body);
        }
        const res = await fetch(path, opts);
        if (res.status === 401 || res.status === 403) {
            location.href = LOGIN_URL;
            throw new Error('登录状态已失效, 请重新登录');
        }
        let json;
        try {
            json = await res.json();
        } catch (e) {
            throw new Error('响应解析失败: HTTP ' + res.status);
        }
        if (!json || json.code !== 200) {
            throw new Error((json && json.msg) || '请求失败');
        }
        return json.data;
    }

    /**
     * 登录守卫: 校验当前会话 (ROLE_ADMIN)。
     * - 未登录 → 跳转 /login
     * - 已登录但非管理端 (ROLE_USER) → 走 /logout (清除本地 + SSO 会话), 由服务端准入把关
     *   正常情况下不会发生: admin-service 登录成功处理器已拒绝非管理端建立会话。
     * 通过则返回 /api/current-user 数据。
     */
    async function guard() {
        try {
            const res = await fetch('/api/current-user');
            if (res.status === 401 || res.status === 403) {
                location.href = LOGIN_URL;
                return null;
            }
            const me = await res.json();
            if (!me || me.authenticated !== true) {
                location.href = LOGIN_URL;
                return null;
            }
            // 仅允许管理端 (identity_type=1, id_token roles 含 ROLE_ADMIN) 进入后台
            const roles = Array.isArray(me.roles) ? me.roles : [];
            let isAdmin = roles.includes('ROLE_ADMIN');
            if (roles.length === 0) {
                // 兼容旧会话/roles 缺失时回退到 authorities 判断
                const authorities = me.authorities || [];
                isAdmin = authorities.includes('ROLE_ADMIN') || authorities.includes('SCOPE_admin');
            }
            if (!isAdmin) {
                location.href = '/logout';
                return null;
            }
            return me;
        } catch (e) {
            location.href = LOGIN_URL;
            return null;
        }
    }

    const NAV_ITEMS = [
        ['tenant', '/tenant.html', '租户管理'],
        ['index', '/index.html', '首页'],
        ['user', '/user.html', '用户管理'],
        ['role', '/role.html', '角色管理'],
        ['permission', '/permission.html', '权限管理'],
        ['client', '/client.html', '客户端管理'],
        ['policy', '/policy.html', '准入策略'],
        ['authorization', '/authorization.html', '授权管理'],
        ['online', '/online.html', '在线用户']
    ];

    /**
     * 渲染顶部导航 (需页面存在 <div class="navbar" id="navbar"></div>), 绑定退出登录。
     * @param {string} active 当前页 key (对应 NAV_ITEMS 首列)
     */
    function renderNavbar(active, user) {
        const el = document.getElementById('navbar');
        if (!el) return;
        el.classList.add('navbar');
        const userLabel = (user && (user.username || user.nickname))
            ? `<span style="color:#dbeafe;font-size:13px;white-space:nowrap;margin-right:14px;" title="${esc(user.email || '')}">👤 ${esc(user.nickname || user.username)}</span>`
            : '';
        el.innerHTML =
            `<div class="brand">🚀 统一认证中心</div>` +
            NAV_ITEMS.map(function (item) {
                const [key, href, label] = item;
                return `<a href="${href}"${key === active ? ' class="active"' : ''}>${label}</a>`;
            }).join('') +
            `<div class="spacer"></div>` +
            userLabel +
            `<a href="#" class="logout" id="logoutLink">退出登录</a>`;
        const logout = document.getElementById('logoutLink');
        if (logout) {
            logout.addEventListener('click', function (e) {
                e.preventDefault();
                if (confirm('确认退出登录？')) location.href = '/logout';
            });
        }
    }

    return { LOGIN_URL, esc, fmtTime, api, guard, renderNavbar };
})();