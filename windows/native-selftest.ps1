# Trusted probe, run only with the managed account and controlled fixture paths/ports.
$ErrorActionPreference = 'Stop'
if ($env:SANDBOX_BACKEND -ne 'user' -or -not $env:SBX_EXPECT_SID) { exit 90 }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne $env:SBX_EXPECT_SID) { exit 10 }
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 11 }
try {
    $stream = [IO.File]::OpenRead($env:SBX_PRIVATE_FIXTURE)
    $stream.Dispose()
    exit 20
} catch [UnauthorizedAccessException] { } catch { exit 21 }
try {
    $stream = [IO.File]::Open($env:SANDBOX_POLICY, [IO.FileMode]::Open, [IO.FileAccess]::Write)
    $stream.Dispose()
    exit 22
} catch [UnauthorizedAccessException] { } catch { exit 23 }
$target = Join-Path $env:SANDBOX_WORKSPACE ('.native-selftest-' + [Guid]::NewGuid().ToString('N'))
$writable = $false
try {
    $stream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    $stream.Dispose()
    $writable = $true
    [IO.File]::Delete($target)
} catch [UnauthorizedAccessException] { } catch { exit 24 }
if ($writable -ne ($env:SBX_ACCESS -eq 'edit')) { exit 25 }

# WFP must reject the known listening fixture with WSAEACCES, not merely a refused connection.
$client = New-Object Net.Sockets.TcpClient
try {
    $task = $client.ConnectAsync([Net.IPAddress]::Loopback, [int]$env:SBX_BLOCKED_PORT)
    $null = $task.Wait(5000)
    if (-not $task.IsCompleted) { exit 31 }
    exit 30
} catch {
    $errorObject = $_.Exception
    while ($errorObject.InnerException) { $errorObject = $errorObject.InnerException }
    if (-not ($errorObject -is [Net.Sockets.SocketException]) -or $errorObject.NativeErrorCode -ne 10013) { exit 32 }
} finally { $client.Dispose() }

if ($env:SBX_OFFLINE -eq '0') {
    foreach ($authenticated in @($false, $true)) {
        $client = New-Object Net.Sockets.TcpClient
        try {
            $task = $client.ConnectAsync([Net.IPAddress]::Loopback, [int]$env:SBX_PROXY_PORT)
            if (-not $task.Wait(5000)) { exit 40 }
            $stream = $client.GetStream()
            $stream.ReadTimeout = 5000
            $stream.WriteTimeout = 5000
            $request = "HEAD / HTTP/1.1`r`n"
            if ($authenticated) {
                $credential = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('sandbox:' + $env:SBX_PROXY_TOKEN))
                $request += "Proxy-Authorization: Basic $credential`r`n"
            }
            $bytes = [Text.Encoding]::ASCII.GetBytes($request + "`r`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII)
            $line = $reader.ReadLine()
            $status = if ($authenticated) { '405' } else { '407' }
            if (-not $line.StartsWith("HTTP/1.1 $status ")) { exit 41 }
        } catch { exit 42 } finally { $client.Dispose() }
    }
}
Write-Output 'Native account fixture checks passed.'
exit 0
