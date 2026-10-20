# Sets up ioessa-VPN on a new Windows computer. Run in PowerShell:
#   irm https://raw.githubusercontent.com/ioessa-alt/ioessa-VPN/main/setup.ps1 | iex
# or, with options:
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/ioessa-alt/ioessa-VPN/main/setup.ps1))) -SkipTests
# or from a downloaded copy:
#   .\setup.ps1 -Target D:\src\ioessa-VPN -Carry E:\ioessa-carry.zip -SkipTests
#
# Steps: install Git and Python with winget if missing, clone the repo (or pull if it is already there),
# pip install requirements.txt (--user), restore Claude's project memory from ioessa-carry.zip if one is found, run the test suites.
# It does not copy SSH keys, install ProVerif or rebuild the audit package (see HANDOVER.md).

param(
    [string]$Target = (Join-Path $env:USERPROFILE 'ioessa-VPN'),
    [string]$Carry = '',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$Repo = 'https://github.com/ioessa-alt/ioessa-VPN.git'

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path', 'User')
}

function Ensure-Tool($name, $wingetId) {
    if (Get-Command $name -ErrorAction SilentlyContinue) { return }
    Step "Installing $wingetId with winget"
    winget install -e --id $wingetId --accept-package-agreements --accept-source-agreements
    Refresh-Path
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "$name is still not on PATH. Open a new PowerShell window and run this again."
    }
}

# The Microsoft Store 'python' stub exists on fresh Windows but is not a real interpreter, so check the version.
function Find-Python {
    foreach ($cand in @(@('py', '-3.13'), @('python'), @('py', '-3'))) {
        $exe = $cand[0]; $rest = @($cand | Select-Object -Skip 1)
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        try { $v = & $exe @rest --version 2>&1 } catch { continue }
        if ("$v" -match '^Python 3\.(\d+)' -and [int]$Matches[1] -ge 11) { return , $cand }
    }
    return $null
}

# 1. Tools
Ensure-Tool 'git' 'Git.Git'
$py = Find-Python
if (-not $py) {
    Step 'Installing Python 3.13 with winget'
    winget install -e --id Python.Python.3.13 --accept-package-agreements --accept-source-agreements
    Refresh-Path
    $py = Find-Python
    if (-not $py) { throw 'Python 3.11+ not found. Open a new PowerShell window and run this again.' }
}
$pyExe = $py[0]; $pyArgs = @($py | Select-Object -Skip 1)
Step ("Python: " + (& $pyExe @pyArgs --version))

# 2. Repo (files stay LF, as on the original machine)
if (Test-Path (Join-Path $Target '.git')) {
    Step "Pulling in $Target"
    git -C $Target pull --ff-only
} else {
    Step "Cloning to $Target"
    git -c core.autocrlf=false clone $Repo $Target
    git -C $Target config core.autocrlf false
}

Step 'Installing Python packages (requirements.txt)'
& $pyExe @pyArgs -m pip install --user --no-input --disable-pip-version-check -q -r (Join-Path $Target 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'pip install failed (see above).' }

# 3. Claude memory from the carry bundle. Claude Code keys project memory by the folder path.
if (-not $Carry) {
    $places = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:OneDrive,
                "$env:OneDrive\Desktop", $env:USERPROFILE) | Where-Object { $_ -and (Test-Path $_) }
    $found = Get-ChildItem -Path $places -Filter 'ioessa-carry*.zip' -File -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($found) { $Carry = $found.FullName }
}
if ($Carry) {
    $full = (Resolve-Path $Target).Path
    $key = $full -replace '[^A-Za-z0-9-]', '-'
    $memDir = Join-Path $env:USERPROFILE ".claude\projects\$key\memory"
    Step "Restoring Claude memory from $Carry to $memDir"
    $tmp = Join-Path $env:TEMP ("ioessa-carry-" + [guid]::NewGuid())
    Expand-Archive -Path $Carry -DestinationPath $tmp
    New-Item -ItemType Directory -Force $memDir | Out-Null
    Copy-Item (Join-Path $tmp 'memory\*') $memDir -Force
    Remove-Item -Recurse -Force $tmp
} else {
    Write-Host 'No ioessa-carry.zip found; skipping Claude memory (pass -Carry <path> to restore it).' -ForegroundColor Yellow
}

# 4. Tests
if (-not $SkipTests) {
    $results = @()
    $suites = @(
        @{ Name = 'Tunnel';   Dir = 'tunnel'; Args = @('-m', 'unittest') },
        @{ Name = 'Analysis'; Dir = 'tunnel'; Args = @('-m', 'unittest', 'discover', '-s', 'analysis', '-p', 'test_*.py') },
        @{ Name = 'Web';      Dir = '.';      Args = @('-m', 'unittest', 'test_web', 'test_fuzz_web', 'test_web_accounts', 'test_web_tls') }
    )
    foreach ($s in $suites) {
        Step "Tests: $($s.Name)"
        Push-Location (Join-Path $Target $s.Dir)
        try {
            $ErrorActionPreference = 'Continue'
            & $pyExe @pyArgs @($s.Args) 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ } |
                Select-Object -Last 2 | ForEach-Object { "    $_" }
            $results += "$($s.Name): " + $(if ($LASTEXITCODE -eq 0) { 'pass' } else { "FAIL (exit $LASTEXITCODE)" })
        } finally {
            $ErrorActionPreference = 'Stop'
            Pop-Location
        }
    }
    $results | ForEach-Object { Write-Host "    $_" }
}

Step "Done. Project is in $Target. Open it with: cd `"$Target`"; claude"
Write-Host 'Not carried over: ~\.ssh keys (copy by hand), ProVerif, the audit zip. See HANDOVER.md.'
