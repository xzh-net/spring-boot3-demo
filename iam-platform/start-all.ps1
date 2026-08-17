# =====================================================================
# start-all.ps1 — iam-platform 全量服务启停脚本 (PowerShell 5.1)
# ---------------------------------------------------------------------
# 每次执行:
#   1. 检查目标端口是否已被监听 (即服务是否在运行);
#   2. 已运行 -> 先结束旧进程 (递归 kill), 再重新启动 = 重启;
#   3. 未运行 -> 直接启动;
#   4. 启动后轮询端口就绪, 输出各服务状态汇总。
#
# 服务清单 (核心平台):
#   4 个 Java  (mvn spring-boot:run): authorization-server:9000,
#              resource-service:9010, admin-service:8085, portal-service:8080
#   2 个 Node  (node server.js):       admin-web:8001,       portal-web:8000
#
# 用法:  powershell -ExecutionPolicy Bypass -File .\start-all.ps1
# 可配:  powershell ... -File .\start-all.ps1 -SkipMvnBuild   (跳过 mvn 预编译, 直接 spring-boot:run)
# =====================================================================

param(
    [switch]$SkipMvnBuild
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir   = Join-Path $RepoRoot 'logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# ---------------------------------------------------------------------
# 服务定义
# ---------------------------------------------------------------------
$services = @(
    @{ Name = 'iam-authorization-server'; Type = 'java'; Port = 9000; Dir = 'iam-authorization-server'; ReadyPath = '/actuator/health'; ReadyPort = 9000 }
    @{ Name = 'iam-resource-service';     Type = 'java'; Port = 9010; Dir = 'iam-resource-service';     ReadyPort = 9010 }
    @{ Name = 'iam-admin-service';        Type = 'java'; Port = 8085; Dir = 'iam-admin-service';        ReadyPort = 8085 }
    @{ Name = 'iam-portal-service';       Type = 'java'; Port = 8080; Dir = 'iam-portal-service';       ReadyPort = 8080 }
    @{ Name = 'iam-admin-web';            Type = 'node'; Port = 8001; Dir = 'iam-admin-web';            ReadyPort = 8001 }
    @{ Name = 'iam-portal-web';           Type = 'node'; Port = 8000; Dir = 'iam-portal-web';           ReadyPort = 8000 }
)

# ---------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------
function Test-PortListening([int]$Port) {
    try {
        $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop
        return ($null -ne $conn)
    } catch {
        return $false
    }
}

function Get-PortPids([int]$Port) {
    try {
        $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop
        return @($conn | Select-Object -ExpandProperty OwningProcess -Unique)
    } catch {
        return @()
    }
}

# 递归结束监听该端口的进程树 (含父 cmd/mvn/java/node)
function Stop-ByPort([int]$Port) {
    $pids = Get-PortPids $Port
    foreach ($pid0 in $pids) {
        if ($pid0 -le 0) { continue }
        # 若该 PID 是 java, 顺带结束其父 mvn 外壳 (fork 出来的 java.exe 是 mvn 子进程)
        taskkill.exe /PID $pid0 /T /F 2>$null | Out-Null
    }
    Start-Sleep -Milliseconds 500
}

function Start-JavaService($svc) {
    $dir = Join-Path $RepoRoot $svc.Dir
    $out = Join-Path $LogDir ($svc.Name + '.log')
    $err = Join-Path $LogDir ($svc.Name + '.err.log')

    if (-not $SkipMvnBuild) {
        Write-Host ("  预编译 " + $svc.Name + " ...") -ForegroundColor DarkGray
        Push-Location $dir
        mvn -q compile 2>$null | Out-Null
        Pop-Location
    }

    Write-Host ("  启动 " + $svc.Name + " (mvn spring-boot:run) ...") -ForegroundColor Cyan
    $p = Start-Process -FilePath 'mvn' -ArgumentList 'spring-boot:run' `
        -WorkingDirectory $dir -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden -PassThru
    return $p.Id
}

function Start-NodeService($svc) {
    $dir = Join-Path $RepoRoot $svc.Dir
    $out = Join-Path $LogDir ($svc.Name + '.log')
    $err = Join-Path $LogDir ($svc.Name + '.err.log')

    Write-Host ("  启动 " + $svc.Name + " (node server.js) ...") -ForegroundColor Cyan
    $p = Start-Process -FilePath 'node' -ArgumentList 'server.js' `
        -WorkingDirectory $dir -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden -PassThru
    return $p.Id
}

# 轮询端口就绪, 超时返回 $false
function Wait-Port([int]$Port, [int]$TimeoutSec = 120) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-PortListening $Port) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

# ---------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------
Write-Host '========== iam-platform 全量服务启动 ==========' -ForegroundColor Yellow

foreach ($svc in $services) {
    $port = $svc.Port
    Write-Host ("[" + $svc.Name + "] 端口 " + $port + " ...") -ForegroundColor Yellow

    if (Test-PortListening $port) {
        $pids = (Get-PortPids $port) -join ', '
        Write-Host ("  检测到运行中 (PID: " + $pids + "), 执行重启...") -ForegroundColor DarkYellow
        Stop-ByPort $port
    } else {
        Write-Host "  未运行, 执行启动..." -ForegroundColor DarkGray
    }

    if ($svc.Type -eq 'java') { Start-JavaService $svc } else { Start-NodeService $svc }

    if (Wait-Port $port) {
        Write-Host ("  OK  " + $svc.Name + " 已就绪 (http://localhost:" + $port + ")") -ForegroundColor Green
    } else {
        Write-Host ("  WARN " + $svc.Name + " 端口 " + $port + " 轮询超时, 请查看日志: " + $LogDir) -ForegroundColor Magenta
    }
}

Write-Host ''
Write-Host '========== 汇总 ==========' -ForegroundColor Yellow
foreach ($svc in $services) {
    if (Test-PortListening $svc.Port) {
        Write-Host ("  [OK] " + $svc.Name + "  ->  http://localhost:" + $svc.Port) -ForegroundColor Green
    } else {
        Write-Host ("  [!!] " + $svc.Name + "  ->  端口 " + $svc.Port + " 未监听") -ForegroundColor Red
    }
}
Write-Host ''
Write-Host '日志目录: ' $LogDir -ForegroundColor DarkGray
Write-Host '管理台:   http://localhost:8001' -ForegroundColor White
Write-Host '门户:     http://localhost:8000' -ForegroundColor White