/**
 * 管理后台前端 (iam-admin-web)
 * ------------------------------------
 * 纯前端静态服务 (零依赖, 仅用 Node.js 内置模块), 通过 iam-admin-service (8085) 访问管理 API:
 *   1. /api/**      → 代理到 iam-admin-service (8085), 透传 Cookie + Set-Cookie (JSESSIONID)
 *   2. /login       → 302 到 admin-service 的 OAuth2 登录 (/oauth2/authorization/admin-app)
 *   3. /logout      → 302 到 admin-service 的登出 (认证中心 RP-Initiated Logout)
 *
 * 启动: node server.js
 * 端口: 8001
 */

const http = require('http');
const url = require('url');
const path = require('path');
const fs = require('fs');

const PORT = 8201;
const ADMIN_SERVICE = 'http://localhost:8101';
const PUBLIC_DIR = path.join(__dirname, 'public');

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

/** 读取请求体 (Promise) */
function readBody(req) {
    return new Promise((resolve) => {
        let data = '';
        req.on('data', c => data += c);
        req.on('end', () => resolve(data.length > 0 ? data : null));
    });
}

/** 转发 HTTP 请求到上游 (Promise) */
function forward(target, method, body, headers) {
    return new Promise((resolve, reject) => {
        const u = url.parse(target);
        const options = {
            hostname: u.hostname,
            port: u.port,
            path: u.path,
            method: method,
            headers: headers || {}
        };
        const req = http.request(options, (res) => {
            let data = '';
            res.setEncoding('utf8');
            res.on('data', c => data += c);
            res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

/** 代理处理: 转发请求 + 回写响应 (重写相对 Location, 透传 Set-Cookie) */
async function respondProxy(res, target, req) {
    const method = req.method;
    const body = (method === 'GET' || method === 'HEAD') ? null : await readBody(req);

    const headers = {};
    if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];
    if (req.headers.cookie) headers['Cookie'] = req.headers.cookie;

    try {
        const upstream = await forward(target, method, body, headers);
        const respHeaders = {};
        if (upstream.headers['content-type']) respHeaders['Content-Type'] = upstream.headers['content-type'];
        if (upstream.headers['set-cookie']) respHeaders['Set-Cookie'] = upstream.headers['set-cookie'];

        let status = upstream.statusCode;
        if (upstream.headers.location) {
            let loc = upstream.headers.location;
            if (loc.startsWith('/')) {
                const base = url.parse(target);
                loc = base.protocol + '//' + base.host + loc;
            }
            respHeaders['Location'] = loc;
        }
        res.writeHead(status, respHeaders);
        res.end(upstream.body);
    } catch (e) {
        res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: '上游服务不可达: ' + e.message }));
    }
}

/** 静态文件服务 (防目录穿越) */
function serveStatic(res, pathname) {
    const rel = pathname === '/' ? '/index.html' : pathname;
    const full = path.resolve(PUBLIC_DIR, '.' + rel);
    if (!full.startsWith(PUBLIC_DIR)) {
        res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<h1>403 Forbidden</h1>');
        return;
    }
    fs.readFile(full, (err, data) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end('<h1>404 Not Found</h1>');
            return;
        }
        const ext = path.extname(full).toLowerCase();
        res.writeHead(200, {
            'Content-Type': MIME[ext] || 'application/octet-stream',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end(data);
    });
}

const server = http.createServer((req, res) => {
    const parsed = url.parse(req.url);
    const pathname = parsed.pathname || '/';
    const withQuery = parsed.path || '/';

    // 管理 API → iam-admin-service
    if (pathname.startsWith('/api/')) {
        return respondProxy(res, ADMIN_SERVICE + withQuery, req);
    }

    // 登录 / 登出 → admin-service
    if (pathname === '/login') {
        res.writeHead(302, { 'Location': ADMIN_SERVICE + '/oauth2/authorization/admin-app' });
        return res.end();
    }
    if (pathname === '/logout') {
        res.writeHead(302, { 'Location': ADMIN_SERVICE + '/logout' });
        return res.end();
    }

    if (pathname === '/favicon.ico') {
        res.writeHead(204);
        return res.end();
    }

    if (pathname === '/logged-out') {
        return serveStatic(res, '/logged-out.html');
    }

    // 其余全部走静态文件
    return serveStatic(res, pathname);
});

server.listen(PORT, () => {
    console.log(`[iam-admin-web] 管理后台前端已启动: http://localhost:${PORT}`);
    console.log(`[iam-admin-web] 后端服务地址: ${ADMIN_SERVICE}`);
});
