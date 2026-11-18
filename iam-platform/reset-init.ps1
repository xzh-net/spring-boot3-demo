# =====================================================================
# reset-init.ps1 — IAM 环境一键重置为「最干净初始化状态」(PowerShell 5.1)
# ---------------------------------------------------------------------
# 执行流程:
#   1. 读取项目当前连接的 MySQL / Redis 配置
#      (profile 取自计划任务 iam9000 参数, 缺省回退 application.yml 默认 profile)
#   2. 停止依赖服务: 9000 / 8085 / 8080 (+ 相关计划任务)
#   3. 清空 Redis: db1(认证中心) + db3(管理BFF) —— db2 属其他项目, 不动
#   4. 清空 MySQL iam 库全部表结构与数据, 重新执行 sql/iam.sql 种子
#      (种子用户编码已为标准 UUID: 550e8400-...-446655440001/0002)
#   5. 校验种子: 17 表 / 3 用户 UUID 编码 / 6 客户端 / 3 角色
#   6. 调 start-all.ps1 重启 5 服务, 并做入口健康检查
#
# 用法: 双击 reset-init.bat, 或
#       powershell -ExecutionPolicy Bypass -File .\reset-init.ps1 [-Force]
# =====================================================================

param([switch]$Force)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SqlFile  = Join-Path $RepoRoot 'sql\iam.sql'
$TmpDir   = Join-Path $env:TEMP 'iam-reset'
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

function Say([string]$m, [string]$c = 'White') { Write-Host $m -ForegroundColor $c }

# ---------------------------------------------------------------------
# 1. 解析项目连接配置
# ---------------------------------------------------------------------
Say '== 1) 读取项目连接配置 ==' Yellow

$profileName = $null
try {
    $taskArgs = (Get-ScheduledTask -TaskName 'iam9000' -ErrorAction Stop).Actions.Arguments
    if ($taskArgs -match 'spring\.profiles\.active=(\S+)') { $profileName = $Matches[1] }
} catch { }
if (-not $profileName) {
    $appYml = Join-Path $RepoRoot 'server\iam-authorization-server\src\main\resources\application.yml'
    if ((Get-Content $appYml -Raw) -match 'profiles:\s*\r?\n\s*active:\s*(\S+)') { $profileName = $Matches[1].Trim() }
}
if (-not $profileName) { Say '  无法确定 active profile' Red; exit 1 }

$profFile = Join-Path $RepoRoot ("server\iam-authorization-server\src\main\resources\application-{0}.yml" -f $profileName)
if (-not (Test-Path $profFile)) { Say ("  配置文件不存在: " + $profFile) Red; exit 1 }
$yml = Get-Content $profFile -Raw

if ($yml -notmatch 'url:\s*jdbc:mysql://([^:/]+):(\d+)/(\w+)') { Say '  未解析到 MySQL url' Red; exit 1 }
$dbHost = $Matches[1]; $dbPort = $Matches[2]; $dbName = $Matches[3]
if ($yml -notmatch 'username:\s*(\S+)') { Say '  未解析到 DB username' Red; exit 1 }
$dbUser = $Matches[1]
$dbPass = ''
if ($yml -match '(?m)^\s*password:\s*(\S*)\s*$') { $dbPass = $Matches[1] }

if ($yml -notmatch 'redis:\s*\r?\n\s*host:\s*(\S+)') { Say '  未解析到 Redis host' Red; exit 1 }
$rHost = $Matches[1]
$rPort = 6379
if ($yml -match '(?s)redis:.*?port:\s*(\d+)') { $rPort = [int]$Matches[1] }
$rDb = 1
if ($yml -match '(?m)^\s*database:\s*(\d+)') { $rDb = [int]$Matches[1] }

# 管理 BFF 的 Redis 库 (Spring Session 存储)
$rbDb = 3
$BffYml = Join-Path $RepoRoot 'bff\iam-admin-bff\src\main\resources\application.yml'
if ((Test-Path $BffYml) -and ((Get-Content $BffYml -Raw) -match '(?m)^\s*database:\s*(\d+)')) { $rbDb = [int]$Matches[1] }

if (-not (Test-Path $SqlFile)) { Say ("  种子文件不存在: " + $SqlFile) Red; exit 1 }

Say ("  profile      = " + $profileName)
Say ("  MySQL        = " + $dbHost + ":" + $dbPort + "/" + $dbName + "   (user=" + $dbUser + ")")
Say ("  Redis        = " + $rHost + ":" + $rPort + "   将清空 db" + $rDb + "(认证中心) + db" + $rbDb + "(管理BFF)")
Say ("  不动         = Redis db2 (其他项目 sessionreg:all)")
Say ("  种子         = " + $SqlFile)

# ---------------------------------------------------------------------
# 确认 (破坏性操作)
# ---------------------------------------------------------------------
if (-not $Force) {
    Say ''
    Say ('!! 即将清空 ' + $dbName + ' 库全部表结构与数据 + Redis db' + $rDb + '/db' + $rbDb + ', 并重启核心服务') Red
    $ans = Read-Host '输入 Y 继续, 其他键取消'
    if ($ans -ne 'Y') { Say '已取消' Yellow; exit 0 }
}

# ---------------------------------------------------------------------
# 2. 停止依赖服务 (9000/8085/8080 + 相关计划任务)
# ---------------------------------------------------------------------
Say ''
Say '== 2) 停止依赖服务 ==' Yellow
foreach ($t in 'iam9000', 'iam8085', 'iam8001') {
    try { Stop-ScheduledTask -TaskName $t -ErrorAction Stop; Say ("  计划任务 " + $t + " 已停") DarkGray } catch { }
}
foreach ($port in 9000, 8085, 8080) {
    $pids = @()
    try { $pids = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction Stop | Select-Object -ExpandProperty OwningProcess -Unique) } catch { }
    foreach ($p in $pids) { taskkill.exe /PID $p /T /F 2>$null | Out-Null }
    if ($pids.Count -gt 0) { Say ("  端口 " + $port + " 进程已结束 (PID " + ($pids -join ',') + ")") DarkGray }
}
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    $up = @()
    foreach ($port in 9000, 8085, 8080) {
        try { $up += Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction Stop } catch { }
    }
    if ($up.Count -eq 0) { break }
    Start-Sleep -Milliseconds 500
}
Say '  9000 / 8085 / 8080 端口已释放' Green

# ---------------------------------------------------------------------
# Java 工具 (JDBC + Jedis 单文件模式)
# ---------------------------------------------------------------------
$java = $null
if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin\java.exe'))) { $java = Join-Path $env:JAVA_HOME 'bin\java.exe' }
if (-not $java) { $java = (Get-Command java -ErrorAction SilentlyContinue).Source }
if (-not $java) { $java = 'C:\Program Files\Java\jdk-17\bin\java.exe' }

$mysqlJar = (Get-ChildItem (Join-Path $env:USERPROFILE '.m2\repository\com\mysql') -Recurse -Filter 'mysql-connector-j-*.jar' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
$jedisJar = (Get-ChildItem (Join-Path $env:USERPROFILE '.m2\repository\redis\clients') -Recurse -Filter 'jedis-*.jar' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
$slf4jJar = (Get-ChildItem (Join-Path $env:USERPROFILE '.m2\repository\org\slf4j\slf4j-api') -Recurse -Filter 'slf4j-api-*.jar' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if (-not $mysqlJar) { Say '  未找到 mysql-connector jar (.m2)' Red; exit 1 }
if (-not $jedisJar) { Say '  未找到 jedis jar (.m2)' Red; exit 1 }
$cp = $mysqlJar + ';' + $jedisJar
if ($slf4jJar) { $cp = $cp + ';' + $slf4jJar }

$toolSrc = Join-Path $TmpDir 'ResetTool.java'
$toolCode = @'
import redis.clients.jedis.Jedis;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** 环境重置工具: flush(清Redis) / drop(清表) / load(执行SQL种子) / verify(种子校验) */
public class ResetTool {
    static final Pattern UUID_RX =
        Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    public static void main(String[] a) throws Exception {
        switch (a[0]) {
            case "flush":  doFlush(a);  break;
            case "drop":   doDrop(a);   break;
            case "load":   doLoad(a);   break;
            case "verify": doVerify(a); break;
            default: System.out.println("unknown cmd: " + a[0]); System.exit(2);
        }
    }

    /** flush host port db */
    static void doFlush(String[] a) {
        try (Jedis j = new Jedis(a[1], Integer.parseInt(a[2]))) {
            j.select(Integer.parseInt(a[3]));
            long n = j.dbSize();
            j.flushDB();
            System.out.println("  FLUSH db" + a[3] + " OK, removed keys=" + n);
        }
    }

    static Connection conn(String[] a) throws Exception {
        return DriverManager.getConnection(a[1], a[2], a[3]);
    }

    /** drop url user pass schema */
    static void doDrop(String[] a) throws Exception {
        try (Connection c = conn(a)) {
            List<String> ts = new ArrayList<>();
            ResultSet rs = c.createStatement().executeQuery(
                "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + a[4] + "'");
            while (rs.next()) ts.add(rs.getString(1));
            try (Statement s = c.createStatement()) {
                // FK 无序删除保护 (V6.17 起 iam_endpoint/sys_scope_permission → sys_permission;
                // information_schema 返回顺序不保证依赖序, 关检查无序 DROP 才稳)
                s.execute("SET FOREIGN_KEY_CHECKS = 0");
                for (String t : ts) s.executeUpdate("DROP TABLE IF EXISTS `" + t + "`");
                s.execute("SET FOREIGN_KEY_CHECKS = 1");
            }
            System.out.println("  DROP OK, removed tables=" + ts.size());
        }
    }

    /** load url user pass sqlFile (iam.sql 自带 CREATE DATABASE/USE/SET, 多语句一次执行) */
    static void doLoad(String[] a) throws Exception {
        String sql = new String(Files.readAllBytes(Paths.get(a[4])), "UTF-8");
        try (Connection c = conn(a); Statement s = c.createStatement()) {
            s.execute(sql);
            System.out.println("  LOAD OK, file=" + a[4]);
        }
    }

    /** verify url user pass — 退出码非 0 = 校验失败 (输出纯 ASCII, 避免控制台编码链乱码) */
    static void doVerify(String[] a) throws Exception {
        boolean ok = true;
        try (Connection c = conn(a)) {
            int tables = q1(c, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()");
            ok &= chk("tables = 18", tables == 18, String.valueOf(tables));

            int users = q1(c, "SELECT COUNT(*) FROM sys_user");
            ok &= chk("seed users = 3", users == 3, String.valueOf(users));

            ResultSet rs = c.createStatement().executeQuery("SELECT username, user_code FROM sys_user ORDER BY id");
            boolean any = false;
            while (rs.next()) {
                any = true;
                String un = rs.getString(1), uc = rs.getString(2);
                ok &= chk("user [" + un + "] code is standard UUID", UUID_RX.matcher(uc).matches(), uc);
            }
            ok &= chk("user rows exist", any, any ? "ok" : "0 rows");

            int clients = q1(c, "SELECT COUNT(*) FROM oauth2_registered_client");
            ok &= chk("oauth2 clients = 6", clients == 6, String.valueOf(clients));
            int roles = q1(c, "SELECT COUNT(*) FROM sys_role");
            ok &= chk("builtin roles = 3", roles == 3, String.valueOf(roles));
        }
        if (!ok) System.exit(1);
    }

    static int q1(Connection c, String sql) throws Exception {
        ResultSet rs = c.createStatement().executeQuery(sql);
        rs.next();
        return rs.getInt(1);
    }

    static boolean chk(String name, boolean pass, String detail) {
        System.out.println("  [" + (pass ? "PASS" : "FAIL") + "] " + name + "  (" + detail + ")");
        return pass;
    }
}
'@
# 写无 BOM 的 UTF-8 (javac 不认 BOM)
[System.IO.File]::WriteAllText($toolSrc, $toolCode, (New-Object System.Text.UTF8Encoding($false)))

function Invoke-Tool([string[]]$ToolArgs) {
    # Out-Host: java stdout 直送控制台, 不进函数返回流 (否则 $rc 会被输出污染成数组)
    & $java "-Dstdout.encoding=UTF-8" -cp $cp $toolSrc @ToolArgs | Out-Host
    $rc = $LASTEXITCODE
    if ($rc -ne 0) { Write-Host ("    [debug] java exit=" + $rc + "  args=" + ($ToolArgs -join ' ')) -ForegroundColor DarkGray }
    return $rc
}

# ---------------------------------------------------------------------
# 3. 清空 Redis (db1 认证中心 + db3 管理BFF; db2 其他项目不动)
# ---------------------------------------------------------------------
Say ''
Say '== 3) 清空 Redis ==' Yellow
$rc = Invoke-Tool @('flush', $rHost, [string]$rPort, [string]$rDb)
if ($rc -ne 0) { Say ('  Redis db' + $rDb + ' 清空失败') Red; exit 1 }
$rc = Invoke-Tool @('flush', $rHost, [string]$rPort, [string]$rbDb)
if ($rc -ne 0) { Say ('  Redis db' + $rbDb + ' 清空失败') Red; exit 1 }
Say '  db2 (其他项目) 未触碰' DarkGray

# ---------------------------------------------------------------------
# 4. 清空 MySQL 全部表 + 执行种子
# ---------------------------------------------------------------------
Say ''
Say '== 4) 清空 MySQL 并执行种子 ==' Yellow
$url = "jdbc:mysql://${dbHost}:${dbPort}/${dbName}?useUnicode=true&characterEncoding=utf8&useSSL=false&serverTimezone=Asia/Shanghai&allowMultiQueries=true"

$rc = Invoke-Tool @('drop', $url, $dbUser, $dbPass, $dbName)
if ($rc -ne 0) { Say '  清表失败' Red; exit 1 }

$rc = Invoke-Tool @('load', $url, $dbUser, $dbPass, $SqlFile)
if ($rc -ne 0) { Say '  种子执行失败' Red; exit 1 }

# ---------------------------------------------------------------------
# 5. 种子校验
# ---------------------------------------------------------------------
Say ''
Say '== 5) 种子校验 ==' Yellow
$rc = Invoke-Tool @('verify', $url, $dbUser, $dbPass)
if ($rc -ne 0) { Say '  种子校验失败, 请检查上方 FAIL 项' Red; exit 1 }

# ---------------------------------------------------------------------
# 6. 重启服务 + 健康检查
# ---------------------------------------------------------------------
Say ''
Say '== 6) 重启核心服务 (start-all.ps1) ==' Yellow
& (Join-Path $RepoRoot 'start-all.ps1')

function Wait-Http([string]$Url, [int[]]$Ok, [int]$TimeoutSec = 90) {
    # 用 curl 取首跳状态码 (PS5.1 Invoke-WebRequest -MaximumRedirection 0 对 302 抛异常且取不到码)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $code = (& curl.exe -s -o NUL -w '%{http_code}' --max-time 5 $Url 2>$null) -join ''
        if ($Ok -contains [int]$code) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

Say ''
Say '== 7) 入口健康检查 ==' Yellow
$checks = @(
    @{ N = '9000 认证中心 (oidc discovery)'; U = 'http://localhost:9000/.well-known/openid-configuration'; Ok = @(200) },
    @{ N = '8085 管理BFF (未登录302正常)';  U = 'http://localhost:8085/api/current-user';                Ok = @(200, 302, 401, 403) },
    @{ N = '8080 门户BFF';                  U = 'http://localhost:8080/';                                Ok = @(200, 302) },
    @{ N = '8001 管理台';                   U = 'http://localhost:8001/';                                Ok = @(200) },
    @{ N = '8000 门户';                     U = 'http://localhost:8000/';                                Ok = @(200) }
)
$allOk = $true
foreach ($c in $checks) {
    if (Wait-Http $c.U $c.Ok) { Say ("  [PASS] " + $c.N) Green }
    else { Say ("  [FAIL] " + $c.N + "  (" + $c.U + ")") Red; $allOk = $false }
}

Say ''
if ($allOk) {
    Say '========== 初始化完成: 环境已回到最干净状态 ==========' Green
    Say '种子账号: admin / 123456  (编码 550e8400-...-446655440001)' Cyan
    Say '          user  / 123456  (编码 550e8400-...-446655440002)' Cyan
    Say '注: 所有旧登录态已失效, 请重新登录管理台/门户后再开始验证' DarkYellow
    exit 0
} else {
    Say '========== 初始化完成但健康检查有 FAIL, 请排查上方输出 ==========' Red
    exit 1
}
