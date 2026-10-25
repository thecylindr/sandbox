<#
.SYNOPSIS
  Installer of the AI sandbox launcher for Windows (WSL2, Docker or native managed account).
.DESCRIPTION
  Copies the program files to %LOCALAPPDATA%\AISandbox\app (never projects, tokens, logs), checks the chosen
  backend, installs the sandbox.cmd command with an absolute Python path and adds it to the user PATH.
  Native user mode uses ACL/WFP, not namespaces; setup is a separate administrator action.
  NOT verified on a real Windows machine in the review that produced it: run with -Check, then -DryRun first.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Check
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Backend wsl -Distribution Ubuntu
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Backend docker -BuildImage
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall [-Purge]
#>
param(
    [ValidateSet('wsl', 'docker', 'both', 'user')][string]$Backend = 'both',
    [string]$Distribution = '',
    [switch]$BuildImage,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'AISandbox'),
    [switch]$NoPath,
    [switch]$Check,
    [switch]$DryRun,
    [switch]$Uninstall,
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
$script:Problems = 0

function Say($text) { Write-Host $text }
function Step($text) { Write-Host ''; Write-Host "== $text ==" }
function Problem($text) { Write-Host "[!!] $text"; $script:Problems++ }
function Do-Action($text, [scriptblock]$action) {
    if ($DryRun) { Write-Host "+ $text" } else { & $action }
}

# ---------- uninstall ----------
$app = Join-Path $InstallDir 'app'
$bin = Join-Path $InstallDir 'bin'
if ($Uninstall) {
    Step 'Uninstall'
    Do-Action "remove $bin\sandbox.cmd" { Remove-Item -LiteralPath (Join-Path $bin 'sandbox.cmd') -Force -ErrorAction SilentlyContinue }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath) {
        $kept = ($userPath -split ';') | Where-Object { $_ -and ($_.TrimEnd('\') -ne $bin.TrimEnd('\')) }
        Do-Action 'remove the command folder from the user PATH' { [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User') }
    }
    if ($Purge) {
        if (-not (Test-Path -LiteralPath (Join-Path $app 'windows.py'))) { throw "Refusing to delete $InstallDir: no app\windows.py inside, not an installation folder." }
        Say "This deletes $InstallDir including windows-data (copied projects and Docker proxy logs)."
        Say 'Docker volumes with agent settings (sbx-home-*) are kept; remove them with: docker volume ls / docker volume rm NAME'
        $answer = if ($DryRun) { 'n' } else { Read-Host 'Delete it permanently? [y/N]' }
        if ($answer -match '^(y|yes)$') { Remove-Item -LiteralPath $InstallDir -Recurse -Force; Say 'Deleted.' } else { Say 'Kept.' }
    } else {
        Say "Program and data stay in $InstallDir (full removal: -Uninstall -Purge)."
    }
    return
}

# ---------- environment ----------
Step 'Environment'
$caption = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { 'Windows' }
Say "system: $caption, PowerShell $($PSVersionTable.PSVersion)"

# Python 3.11+: the launcher needs tomllib. The absolute path is written into sandbox.cmd.
$python = $null
foreach ($candidate in @('py', 'python')) {
    $command = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { continue }
    $argsList = if ($candidate -eq 'py') { @('-3') } else { @() }
    $exe = & $command.Source @argsList -c 'import sys; print(sys.executable if sys.version_info >= (3, 11) else "")' 2>$null
    if ($exe -and (Test-Path -LiteralPath $exe)) { $python = $exe.Trim(); break }
}
if ($python) { Say "python: $python" } else { Problem 'Python 3.11+ for Windows is required (python.org; include tkinter for the window). Run this installer again afterwards.' }

function Get-WslDistros {
    # wsl.exe prints UTF-16; docker-desktop service distributions are not user distributions
    $wsl = Get-Command wsl.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $wsl) { return @() }
    $old = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        $raw = & $wsl.Source -l -v 2>$null
    } catch { return @() } finally { [Console]::OutputEncoding = $old }
    $found = @()
    foreach ($line in $raw) {
        $clean = ($line -replace "`0", '').Trim()
        if ($clean -match '^\*?\s*(\S+)\s+(\S+)\s+([12])\s*$' -and $Matches[1] -notlike 'docker-desktop*') {
            $found += [pscustomobject]@{ Name = $Matches[1]; Version = [int]$Matches[3] }
        }
    }
    return $found
}

$wslOk = $false
$dockerOk = $false
if ($Backend -in @('wsl', 'both')) {
    $distros = @(Get-WslDistros)
    $target = if ($Distribution) { $distros | Where-Object { $_.Name -eq $Distribution } | Select-Object -First 1 } else { $distros | Select-Object -First 1 }
    if ($distros.Count -eq 0) {
        Say 'WSL: no Linux distribution found. Install one (administrator PowerShell): wsl --install -d Ubuntu  (then reboot if asked)'
    } elseif (-not $target) {
        Say "WSL: distribution '$Distribution' not found. Installed: $(($distros | ForEach-Object { $_.Name }) -join ', ')"
    } elseif ($target.Version -ne 2) {
        Say "WSL: '$($target.Name)' is WSL1; namespaces are not supported there. Convert: wsl --set-version $($target.Name) 2"
    } else {
        $wslOk = $true
        Say "WSL2: $($target.Name)"
    }
}
if ($Backend -in @('docker', 'both') -and $python) {
    $dockerCmd = Get-Command docker -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dockerCmd) {
        & $python (Join-Path $PSScriptRoot 'windows.py') check --backend docker 2>$null | Out-Null
        $dockerOk = ($LASTEXITCODE -eq 0)
    }
    Say $(if ($dockerOk) { 'Docker: local Docker Desktop/Engine with Linux containers is available' } else { 'Docker: not available (install Docker Desktop, start it, choose Linux containers)' })
}

$usable = ($Backend -eq 'user' -and $python -and [Environment]::Is64BitProcess) -or ($Backend -eq 'wsl' -and $wslOk) -or ($Backend -eq 'docker' -and $dockerOk) -or ($Backend -eq 'both' -and ($wslOk -or $dockerOk))
if (-not $usable) {
    Problem 'No isolation backend is usable, so nothing is installed: the sandbox never runs agents without isolation.'
    Say 'Options: -Backend user for the weaker native account mode (see WINDOWS_NATIVE.md); (1) WSL2: wsl --install -d Ubuntu, then re-run; (2) Docker Desktop with Linux containers; (3) a Linux virtual machine with install.sh inside. See WINDOWS.md.'
}
if ($Check) { Say ''; Say "Problems: $script:Problems"; if ($script:Problems -gt 0) { exit 1 } else { return } }
if ($script:Problems -gt 0) { throw "Fix the problems above and run the installer again (problems: $script:Problems)." }

# ---------- files ----------
Step 'Files'
# Only program files; workspaces, state, logs, tokens and build output are never packaged.
$skip = @('home', 'workspaces', 'state', 'logs', 'dist', 'profiles', 'windows-data', 'venv', '.venv', '__pycache__', '.git')
if ([IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') -ne [IO.Path]::GetFullPath($app).TrimEnd('\')) {
    Do-Action "create $app" { New-Item -ItemType Directory -Force $app | Out-Null }
    foreach ($item in Get-ChildItem -LiteralPath $PSScriptRoot -Force) {
        if ($skip -contains $item.Name) { continue }
        if ($item.Name -eq 'agent-skills') {
            Do-Action 'copy bundled agent skills' {
                foreach ($skillName in @('sandbox-fix-report', 'sandbox-project-tests')) {
                    $source = Join-Path (Join-Path $item.FullName $skillName) 'SKILL.md'
                    $destination = Join-Path (Join-Path (Join-Path $app 'agent-skills') $skillName) 'SKILL.md'
                    New-Item -ItemType Directory -Force (Split-Path -Parent $destination) | Out-Null
                    Copy-Item -LiteralPath $source -Destination $destination -Force
                }
            }
            continue
        }
        if ($item.PSIsContainer) {
            $destination = Join-Path $app $item.Name
            Do-Action "copy folder $($item.Name)" {
                New-Item -ItemType Directory -Force $destination | Out-Null
                Get-ChildItem -LiteralPath $item.FullName -File | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $destination -Force }
            }
        } else {
            Do-Action "copy $($item.Name)" { Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $app $item.Name) -Force }
        }
    }
    $profiles = Join-Path $app 'profiles'
    Do-Action "create $profiles" { New-Item -ItemType Directory -Force $profiles | Out-Null }
    foreach ($profile in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'profiles') -Filter '*.toml' -File) {
        $destination = Join-Path $profiles $profile.Name
        if (-not (Test-Path -LiteralPath $destination)) {
            Do-Action "copy profile $($profile.Name)" { Copy-Item -LiteralPath $profile.FullName -Destination $destination }
        } elseif ((Get-FileHash -LiteralPath $destination).Hash -ne (Get-FileHash -LiteralPath $profile.FullName).Hash) {
            Do-Action "keep your edited profile $($profile.Name), new version saved as $($profile.Name).new" {
                Copy-Item -LiteralPath $profile.FullName -Destination "$destination.new" -Force
            }
        }
    }
} else {
    Say 'Files are already in the installation folder.'
}

# ---------- backends ----------
if ($Backend -eq 'user') {
    Say 'Native account backend installed. No account or network rules were changed by this installer.'
    Say 'Run the launcher as administrator: sandbox interfaces ; sandbox setup-user --interface GUID'
    Say 'This mode does not hide host adapters/processes. See WINDOWS_NATIVE.md, then run: sandbox selftest --backend user'
}
if ($Backend -in @('wsl', 'both') -and $wslOk) {
    Step 'WSL backend'
    $setup = @((Join-Path $app 'windows.py'), 'setup-wsl')
    if ($Distribution) { $setup += @('--distro', $Distribution) }
    if (-not $DryRun) {
        & $python @setup
        if ($LASTEXITCODE -ne 0) { throw 'WSL setup or self-test failed (output above). This backend is not confirmed.' }
    } else { Say "+ $python $($setup -join ' ')" }
}
if ($Backend -in @('docker', 'both') -and $dockerOk) {
    Step 'Docker backend'
    if ($BuildImage -and -not $DryRun) {
        & $python (Join-Path $app 'windows.py') build
        if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed.' }
        & $python (Join-Path $app 'windows.py') selftest --backend docker
        if ($LASTEXITCODE -ne 0) { throw 'Docker self-test failed; protection was not confirmed.' }
    } elseif (-not $BuildImage) {
        Say 'Docker image not built. Run: sandbox build ; sandbox selftest --backend docker   (or re-run with -BuildImage)'
    }
}

# ---------- command ----------
Step 'Command sandbox'
function Get-AsciiPath([string]$path) {
    # cmd.exe reads .cmd files in the OEM code page: non-ASCII characters in a path would break; use the 8.3 name
    if ($path -match '^[\x00-\x7F]*$') { return $path }
    $short = (New-Object -ComObject Scripting.FileSystemObject).GetFile($path).ShortPath
    if ($short -match '^[\x00-\x7F]*$') { return $short }
    throw "Path contains non-ASCII characters and has no short name: $path. Use -InstallDir with an ASCII-only path."
}
if (-not $DryRun) {
    New-Item -ItemType Directory -Force $bin | Out-Null
    $launcher = "@echo off`r`nrem Absolute interpreter and no current-directory lookup: a project folder must never be able to supply a program.`r`n" +
        "set `"NoDefaultCurrentDirectoryInExePath=1`"`r`n" +
        "`"$(Get-AsciiPath $python)`" `"$(Get-AsciiPath (Join-Path $app 'windows.py'))`" %*`r`nexit /b %errorlevel%`r`n"
    Set-Content -Encoding ascii -LiteralPath (Join-Path $bin 'sandbox.cmd') -Value $launcher -NoNewline
} else { Say "+ write $bin\sandbox.cmd (absolute Python path)" }
if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $userPath) { $userPath = '' }
    if (($userPath -split ';') -notcontains $bin) {
        Do-Action "add $bin to the user PATH" { [Environment]::SetEnvironmentVariable('Path', (($userPath.TrimEnd(';') + ';' + $bin).TrimStart(';')), 'User') }
    }
}

Step 'Done'
Say "Command: $bin\sandbox.cmd  (open a new terminal for TUI; graphical window: py -3 `"$app\windows.py`" gui)"
Say 'Examples: sandbox gui | sandbox new demo --backend wsl --copy "C:\Code\Project" | sandbox run claude demo --backend wsl --access read'
Say 'Update: run this installer from the new package (profiles and projects are kept). Remove: install.ps1 -Uninstall [-Purge]'
