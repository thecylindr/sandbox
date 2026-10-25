# Windows PowerShell 5.1 / 64-bit. Input JSON is data on stdin, never executable text.
param([ValidateSet('interfaces','interface','create','verify','enable','disable','remove','acl')][string]$Action)
$ErrorActionPreference = 'Stop'
# Warning/progress text would be mixed into the JSON that the launcher reads from stdout.
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json

function Interface-Record($index, $guid, $alias) {
    $ip = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue |
        Where-Object { -not $_.SkipAsSource -and $_.IPAddress -notlike '169.254.*' })
    $dns = @((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4).ServerAddresses |
        Where-Object { [System.Net.IPAddress]::Parse($_).AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
    if ($ip.Count -eq 0 -or $dns.Count -eq 0) { return }
    [pscustomobject]@{ guid = $guid.ToString(); index = [int]$index; alias = [string]$alias;
        address = [string]$ip[0].IPAddress; dns = @($dns) }
}

if ($Action -eq 'interfaces') {
    # Only this explicit owner action lists adapters. No VPN/process/service classification.
    $items = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
        Interface-Record $_.ifIndex $_.InterfaceGuid $_.Name
    })
    ConvertTo-Json -InputObject $items -Depth 4 -Compress
    exit 0
}
if ($Action -eq 'interface') {
    $guid = [Guid]::Parse([string]$request.guid).ToString('B')
    # Exact GUID query: never silently choose the default route or a different adapter.
    $adapter = @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter -Filter "InterfaceGuid='$guid'")
    if ($adapter.Count -ne 1 -or $adapter[0].InterfaceOperationalStatus -ne 1) { throw 'Selected adapter is disconnected or missing.' }
    $result = Interface-Record $adapter[0].InterfaceIndex $guid $adapter[0].Name
    if (-not $result) { throw 'Selected adapter needs a preferred IPv4 address and IPv4 DNS.' }
    $result | ConvertTo-Json -Depth 4 -Compress
    exit 0
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the launcher as administrator.' }
if ($Action -eq 'acl') {
    $root = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'AISandboxNative')).TrimEnd('\')
    foreach ($entry in $request.entries) {
        $path = [IO.Path]::GetFullPath([string]$entry.path)
        if ($path -ne $root -and -not $path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'ACL target outside managed root.' }
        $item = Get-Item -LiteralPath $path -Force
        $cursor = $item
        while ($null -ne $cursor) {
            if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are forbidden in ACL targets.' }
            $cursor = if ($cursor.PSIsContainer) { $cursor.Parent } else { $cursor.Directory }
        }
        $acl = if ($item.PSIsContainer) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
        $acl.SetAccessRuleProtection($true, $false)
        $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
        $acl.SetOwner($admins)
        $inherit = if ($item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
        foreach ($sid in @($admins, $system)) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')))
        }
        if ($entry.rights -ne 'none') {
            if ($entry.rights -notin @('read','edit')) { throw 'Invalid access mode.' }
            $sid = New-Object Security.Principal.SecurityIdentifier([string]$request.sid)
            $rights = if ($entry.rights -eq 'read') { 'ReadAndExecute' } else { 'Modify' }
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, $rights, $inherit, 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $path -AclObject $acl
    }
    Write-Output '{}'
    exit 0
}

$name = [string]$request.username
if ($name -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,19}$') { throw 'Invalid account name.' }
$marker = 'AI Sandbox native managed account v1'
if ($Action -eq 'create') {
    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { throw 'Account already exists; it will not be reused or modified.' }
    $secure = ConvertTo-SecureString ([string]$request.password) -AsPlainText -Force
    $user = $null
    try {
        $user = New-LocalUser -Name $name -Password $secure -Description $marker -Disabled -UserMayNotChangePassword -PasswordNeverExpires -AccountNeverExpires
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
    } catch {
        if ($user) { Remove-LocalUser -SID $user.SID }
        throw
    }
    @{ sid = $user.SID.Value } | ConvertTo-Json -Compress
    exit 0
}
$user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
if (-not $user -and $Action -eq 'remove') { Write-Output '{}'; exit 0 }
if (-not $user) { throw 'Managed account is missing.' }
if ($user.SID.Value -ne $request.sid -or $user.Description -ne $marker) { throw 'Account identity mismatch; refusing changes.' }
if ($Action -eq 'remove') { $user | Disable-LocalUser; $user | Remove-LocalUser; Write-Output '{}'; exit 0 }
if ($Action -eq 'disable') { $user | Disable-LocalUser; Write-Output '{}'; exit 0 }
$isAdmin = $false
try {
    $isAdmin = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $user.SID.Value }).Count -ne 0
} catch {
    # Windows PowerShell 5.1 fails to list a group that contains an unresolvable SID (Azure AD or removed domain
    # accounts). native-selftest.ps1 still checks the real token of the worker before every agent start.
    $isAdmin = $false
}
if ($isAdmin) { throw 'Worker must not belong to Administrators.' }
if ($Action -eq 'enable') { $user | Enable-LocalUser }
@{ sid = $user.SID.Value; enabled = [bool]$user.Enabled } | ConvertTo-Json -Compress
