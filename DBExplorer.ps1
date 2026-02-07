<#
.SYNOPSIS
    DBExplorer - Active Directory MSSQL Discovery & Inventory Tool

.DESCRIPTION
    Discovers SQL Server instances across Active Directory, inventories their
    configuration, databases, and security model via WinRM, and produces
    self-contained per-server HTML reports.

    Workflow:
    1. Discover computers from AD (or use -ComputerName)
    2. Parallel port scan for common MSSQL ports
    3. Connect via WinRM, detect SQL instances
    4. Inventory: config, databases, backups, security, agent jobs
    5. Generate per-server HTML reports + summary index

.PARAMETER SearchBase
    AD OU distinguished name to scope computer search (e.g. "OU=Servers,DC=corp,DC=local").
    Default: searches the entire domain.

.PARAMETER ComputerName
    Comma-separated list of server names to scan directly, bypassing AD discovery.

.PARAMETER Ports
    TCP ports to scan for MSSQL services. Default: 1433,1434,2383,4022

.PARAMETER PortTimeout
    Port scan timeout in milliseconds. Default: 1000

.PARAMETER MaxThreads
    Maximum parallel threads for port scanning. Default: 20

.PARAMETER OutputPath
    Directory for HTML reports and logs. Default: .\DBExplorer_Reports

.PARAMETER IncludeSystemDatabases
    Include system databases (master, model, msdb, tempdb) in the inventory.

.EXAMPLE
    .\DBExplorer.ps1
    Scans entire AD domain for SQL servers.

.EXAMPLE
    .\DBExplorer.ps1 -ComputerName "SQL01,SQL02,SQL03"
    Scans specific servers without AD discovery.

.EXAMPLE
    .\DBExplorer.ps1 -SearchBase "OU=Servers,DC=corp,DC=local" -IncludeSystemDatabases
    Scans servers in a specific OU, including system databases.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [string]$ComputerName,

    [Parameter(Mandatory = $false)]
    [int[]]$Ports = @(1433, 1434, 2383, 4022),

    [Parameter(Mandatory = $false)]
    [int]$PortTimeout = 1000,

    [Parameter(Mandatory = $false)]
    [int]$MaxThreads = 20,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\DBExplorer_Reports",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSystemDatabases
)

$ErrorActionPreference = "Continue"
$script:StartTime = Get-Date
$script:LogFile = $null
$script:CredentialCache = @{}
$script:GlobalCredential = $null

#region ==================== LOGGING ====================

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        Info    = "Cyan"
        Warning = "Yellow"
        Error   = "Red"
        Success = "Green"
    }

    $prefix = switch ($Level) {
        "Info"    { "[*]" }
        "Warning" { "[!]" }
        "Error"   { "[-]" }
        "Success" { "[+]" }
    }

    Write-Host "$prefix $Message" -ForegroundColor $colors[$Level]

    if ($script:LogFile) {
        # Use .NET to append UTF8 without BOM (PS5 Out-File -Encoding UTF8 adds BOM)
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::AppendAllText($script:LogFile, "$timestamp [$Level] $Message`r`n", $utf8NoBom)
    }
}

#endregion

#region ==================== AD DISCOVERY ====================

function Get-ADComputerTargets {
    param(
        [string]$SearchBase,

        [ValidateSet("Servers", "Workstations", "Both")]
        [string]$TargetScope = "Servers"
    )

    Write-Log "Discovering computers from Active Directory..."

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Log "ActiveDirectory PowerShell module is not available. Install RSAT or use -ComputerName parameter." -Level Error
        return $null
    }

    $adParams = @{
        Filter     = {Enabled -eq $true}
        Properties = @("DNSHostName", "OperatingSystem", "OperatingSystemVersion", "IPv4Address")
    }

    if ($SearchBase) {
        $adParams.SearchBase = $SearchBase
        Write-Log "Scoping AD search to: $SearchBase"
    }

    try {
        $allComputers = @(Get-ADComputer @adParams | Where-Object { $_.OperatingSystem })

        # Apply scope filter
        $computers = switch ($TargetScope) {
            "Servers" {
                @($allComputers | Where-Object { $_.OperatingSystem -like "*Windows Server*" })
            }
            "Workstations" {
                @($allComputers | Where-Object {
                    $_.OperatingSystem -like "*Windows*" -and $_.OperatingSystem -notlike "*Windows Server*"
                })
            }
            "Both" {
                @($allComputers | Where-Object { $_.OperatingSystem -like "*Windows*" })
            }
        }

        $computers = @($computers | Select-Object Name, DNSHostName, OperatingSystem, OperatingSystemVersion, IPv4Address)

        Write-Log "Found $($computers.Count) enabled Windows computers in AD (scope: $TargetScope)" -Level Success
        return $computers
    }
    catch {
        Write-Log "AD query failed: $_" -Level Error
        return $null
    }
}

#endregion

#region ==================== PORT SCANNER ====================

function Invoke-ParallelPortScan {
    param(
        [Parameter(Mandatory)]
        [string[]]$Computers,

        [Parameter(Mandatory)]
        [int[]]$Ports,

        [int]$Timeout = 1000,
        [int]$MaxThreads = 20
    )

    Write-Log "Port scanning $($Computers.Count) computers on ports: $($Ports -join ', ')..."

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    $jobs = [System.Collections.ArrayList]::new()

    $scanScript = {
        param($Computer, $Port, $Timeout)
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connect = $tcp.BeginConnect($Computer, $Port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)

            if ($wait -and $tcp.Connected) {
                try { $tcp.EndConnect($connect) } catch {}
                $tcp.Close()
                return [PSCustomObject]@{
                    Computer = $Computer
                    Port     = $Port
                    IsOpen   = $true
                }
            }
            else {
                $tcp.Close()
                return [PSCustomObject]@{
                    Computer = $Computer
                    Port     = $Port
                    IsOpen   = $false
                }
            }
        }
        catch {
            return [PSCustomObject]@{
                Computer = $Computer
                Port     = $Port
                IsOpen   = $false
            }
        }
    }

    foreach ($computer in $Computers) {
        foreach ($port in $Ports) {
            $ps = [powershell]::Create().AddScript($scanScript).AddArgument($computer).AddArgument($port).AddArgument($Timeout)
            $ps.RunspacePool = $runspacePool
            [void]$jobs.Add(@{
                Pipe     = $ps
                Result   = $ps.BeginInvoke()
                Computer = $computer
                Port     = $port
            })
        }
    }

    $results = [System.Collections.ArrayList]::new()
    $total = $jobs.Count
    $completed = 0

    foreach ($job in $jobs) {
        try {
            $output = $job.Pipe.EndInvoke($job.Result)
            # EndInvoke returns a PSDataCollection - iterate to extract the actual PSCustomObject(s)
            foreach ($item in $output) {
                if ($item) {
                    [void]$results.Add($item)
                }
            }
        }
        catch {
            # Silently skip failed scans
        }
        finally {
            $job.Pipe.Dispose()
        }
        $completed++
        if ($completed % 50 -eq 0 -or $completed -eq $total) {
            Write-Progress -Activity "Port Scanning" -Status "$completed of $total checks complete" -PercentComplete (($completed / $total) * 100)
        }
    }

    Write-Progress -Activity "Port Scanning" -Completed
    $runspacePool.Close()
    $runspacePool.Dispose()

    $openPorts = $results | Where-Object { $_.IsOpen }
    $sqlHosts = $openPorts | Select-Object -ExpandProperty Computer -Unique

    Write-Log "Port scan complete. Found $($openPorts.Count) open SQL ports on $($sqlHosts.Count) hosts" -Level Success

    return $openPorts
}

#endregion

#region ==================== WINRM & CREDENTIALS ====================

function Test-WinRMAccess {
    param(
        [Parameter(Mandatory)]
        [string]$Computer,

        [System.Management.Automation.PSCredential]$Credential
    )

    $invokeParams = @{
        ComputerName = $Computer
        ScriptBlock  = { $env:COMPUTERNAME }
        ErrorAction  = "Stop"
    }
    if ($Credential) {
        $invokeParams.Credential = $Credential
    }

    try {
        $result = Invoke-Command @invokeParams
        return $true
    }
    catch {
        return $false
    }
}

function Get-CredentialFallback {
    param(
        [Parameter(Mandatory)]
        [string]$Computer
    )

    # Check cache first
    if ($script:CredentialCache.ContainsKey($Computer)) {
        return $script:CredentialCache[$Computer]
    }

    $currentAuth = if ($script:GlobalCredential) { $script:GlobalCredential.UserName } else { "current running context" }
    Write-Log "Authentication with $currentAuth failed for $Computer. Prompting for alternate credentials..." -Level Warning

    $choice = $null
    while ($choice -notin @("W", "K")) {
        Write-Host ""
        Write-Host "Authentication failed for $Computer using $currentAuth." -ForegroundColor Yellow
        Write-Host "Choose an option:" -ForegroundColor Yellow
        Write-Host "  [W] Enter alternative Windows credentials for this server (domain\user)"
        Write-Host "  [K] Skip this server"
        $choice = (Read-Host "Selection").Trim().ToUpper()
    }

    if ($choice -eq "K") {
        return $null
    }

    $cred = Get-Credential -Message "Enter Windows credentials for $Computer"
    if (-not $cred) {
        return $null
    }

    # Cache for reuse
    $script:CredentialCache[$Computer] = $cred
    return $cred
}

#endregion

#region ==================== SQL INSTANCE DETECTION ====================

function Get-SQLInstances {
    param(
        [Parameter(Mandatory)]
        [string]$Computer,

        [System.Management.Automation.PSCredential]$Credential
    )

    $invokeParams = @{
        ComputerName = $Computer
        ErrorAction  = "Stop"
    }
    if ($Credential) {
        $invokeParams.Credential = $Credential
    }

    $scriptBlock = {
        $instances = @()

        # Method 1: Registry
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
            if (Test-Path $regPath) {
                $regInstances = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                foreach ($prop in $regInstances.PSObject.Properties) {
                    if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                        $instanceName = if ($prop.Name -eq "MSSQLSERVER") { "DEFAULT" } else { $prop.Name }
                        $instances += [PSCustomObject]@{
                            InstanceName = $instanceName
                            InternalName = $prop.Value
                            Source       = "Registry"
                        }
                    }
                }
            }
        }
        catch {}

        # Method 2: Services
        try {
            $sqlServices = Get-Service -Name "MSSQL`$*", "MSSQLSERVER" -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq "Running" }

            foreach ($svc in $sqlServices) {
                $instName = if ($svc.Name -eq "MSSQLSERVER") {
                    "DEFAULT"
                }
                else {
                    $svc.Name -replace "^MSSQL\$", ""
                }

                if ($instName -notin $instances.InstanceName) {
                    $instances += [PSCustomObject]@{
                        InstanceName = $instName
                        InternalName = $svc.Name
                        Source       = "Service"
                    }
                }
            }
        }
        catch {}

        return $instances
    }

    try {
        $invokeParams.ScriptBlock = $scriptBlock
        $instances = Invoke-Command @invokeParams
        return $instances
    }
    catch {
        Write-Log "Failed to detect SQL instances on $Computer : $_" -Level Error
        return @()
    }
}

#endregion

#region ==================== SQL INVENTORY ====================

function Invoke-RemoteSQLQuery {
    param(
        [Parameter(Mandatory)]
        [string]$Computer,

        [Parameter(Mandatory)]
        [string]$InstanceName,

        [Parameter(Mandatory)]
        [string]$Query,

        [System.Management.Automation.PSCredential]$WinCredential,

        [string]$Database = "master"
    )

    $invokeParams = @{
        ComputerName = $Computer
        ErrorAction  = "Stop"
    }
    if ($WinCredential) {
        $invokeParams.Credential = $WinCredential
    }

    $serverInstance = if ($InstanceName -eq "DEFAULT") { "localhost" } else { "localhost\$InstanceName" }

    $scriptBlock = {
        param($ServerInstance, $Query, $Database)

        $useSqlCmd = $false

        # Try loading SQL module
        try {
            Import-Module SqlServer -ErrorAction Stop -DisableNameChecking
            $useSqlCmd = $true
        }
        catch {
            try {
                Import-Module SQLPS -ErrorAction Stop -DisableNameChecking
                $useSqlCmd = $true
            }
            catch {
                $useSqlCmd = $false
            }
        }

        if ($useSqlCmd) {
            $sqlParams = @{
                ServerInstance = $ServerInstance
                Query          = $Query
                Database       = $Database
                ErrorAction    = "Stop"
                QueryTimeout   = 30
            }
            return Invoke-Sqlcmd @sqlParams
        }
        else {
            # .NET SqlClient fallback
            $connString = "Server=$ServerInstance;Database=$Database;Integrated Security=SSPI;Connection Timeout=10;Command Timeout=30;"

            $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
            $conn.Open()
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = $Query
            $cmd.CommandTimeout = 30
            $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
            $dataset = New-Object System.Data.DataSet
            [void]$adapter.Fill($dataset)
            $conn.Close()
            $conn.Dispose()

            return $dataset.Tables[0]
        }
    }

    $invokeParams.ScriptBlock = $scriptBlock
    $invokeParams.ArgumentList = @($serverInstance, $Query, $Database)

    return Invoke-Command @invokeParams
}

function Get-SQLServerConfig {
    param(
        [Parameter(Mandatory)] [string]$Computer,
        [Parameter(Mandatory)] [string]$InstanceName,
        [System.Management.Automation.PSCredential]$WinCredential
    )

    $config = @{}
    $queryParams = @{
        Computer     = $Computer
        InstanceName = $InstanceName
        WinCredential = $WinCredential
    }

    # Server properties
    try {
        $config.ServerProperties = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    SERVERPROPERTY('MachineName') AS MachineName,
    SERVERPROPERTY('ServerName') AS ServerName,
    SERVERPROPERTY('InstanceName') AS InstanceName,
    SERVERPROPERTY('ProductVersion') AS ProductVersion,
    SERVERPROPERTY('ProductLevel') AS ProductLevel,
    SERVERPROPERTY('Edition') AS Edition,
    SERVERPROPERTY('ProductMajorVersion') AS MajorVersion,
    SERVERPROPERTY('IsClustered') AS IsClustered,
    SERVERPROPERTY('IsHadrEnabled') AS IsHadrEnabled,
    SERVERPROPERTY('Collation') AS ServerCollation,
    SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly
"@
    }
    catch {
        Write-Log "  Failed to get server properties from $Computer\$InstanceName : $_" -Level Warning
        $config.ServerProperties = $null
    }

    # Configuration settings
    try {
        $config.Settings = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT name AS ConfigName, CAST(value_in_use AS VARCHAR(100)) AS ValueInUse, description AS Description
FROM sys.configurations
WHERE name IN (
    'max server memory (MB)', 'min server memory (MB)',
    'max degree of parallelism', 'cost threshold for parallelism',
    'user connections', 'remote access', 'remote admin connections',
    'xp_cmdshell', 'clr enabled', 'Ad Hoc Distributed Queries',
    'Database Mail XPs', 'Ole Automation Procedures'
)
ORDER BY name
"@
    }
    catch {
        Write-Log "  Failed to get configuration settings: $_" -Level Warning
        $config.Settings = $null
    }

    # Service accounts
    try {
        $config.Services = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT servicename, service_account, startup_type_desc, status_desc,
       last_startup_time, instant_file_initialization_enabled
FROM sys.dm_server_services
"@
    }
    catch {
        Write-Log "  Failed to get service info: $_" -Level Warning
        $config.Services = $null
    }

    # Uptime
    try {
        $config.Uptime = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT sqlserver_start_time,
       DATEDIFF(DAY, sqlserver_start_time, GETDATE()) AS UptimeDays,
       DATEDIFF(HOUR, sqlserver_start_time, GETDATE()) % 24 AS UptimeHours,
       cpu_count AS LogicalCPUs,
       physical_memory_kb / 1024 AS PhysicalMemoryMB
FROM sys.dm_os_sys_info
"@
    }
    catch {
        Write-Log "  Failed to get uptime info: $_" -Level Warning
        $config.Uptime = $null
    }

    return $config
}

function Get-SQLDatabases {
    param(
        [Parameter(Mandatory)] [string]$Computer,
        [Parameter(Mandatory)] [string]$InstanceName,
        [System.Management.Automation.PSCredential]$WinCredential,
        [switch]$IncludeSystem
    )

    $queryParams = @{
        Computer      = $Computer
        InstanceName  = $InstanceName
        WinCredential = $WinCredential
    }

    $whereClause = if ($IncludeSystem) { "" } else { "WHERE d.database_id > 4" }

    try {
        return Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    d.name AS DatabaseName,
    d.database_id AS DatabaseID,
    d.state_desc AS State,
    d.recovery_model_desc AS RecoveryModel,
    d.compatibility_level AS CompatibilityLevel,
    d.collation_name AS Collation,
    d.user_access_desc AS UserAccess,
    CASE WHEN d.is_read_only = 1 THEN 'Yes' ELSE 'No' END AS IsReadOnly,
    CASE WHEN d.is_auto_close_on = 1 THEN 'Yes' ELSE 'No' END AS AutoClose,
    CASE WHEN d.is_auto_shrink_on = 1 THEN 'Yes' ELSE 'No' END AS AutoShrink,
    d.page_verify_option_desc AS PageVerify,
    d.create_date AS CreateDate,
    ISNULL(SUM(CAST(mf.size AS BIGINT) * 8 / 1024), 0) AS TotalSizeMB,
    ISNULL(SUM(CASE WHEN mf.type = 0 THEN CAST(mf.size AS BIGINT) * 8 / 1024 ELSE 0 END), 0) AS DataSizeMB,
    ISNULL(SUM(CASE WHEN mf.type = 1 THEN CAST(mf.size AS BIGINT) * 8 / 1024 ELSE 0 END), 0) AS LogSizeMB,
    COUNT(mf.file_id) AS FileCount
FROM sys.databases d
LEFT JOIN sys.master_files mf ON d.database_id = mf.database_id
$whereClause
GROUP BY d.name, d.database_id, d.state_desc, d.recovery_model_desc,
    d.compatibility_level, d.collation_name, d.user_access_desc,
    d.is_read_only, d.is_auto_close_on, d.is_auto_shrink_on,
    d.page_verify_option_desc, d.create_date
ORDER BY d.name
"@
    }
    catch {
        Write-Log "  Failed to get database inventory: $_" -Level Warning
        return $null
    }
}

function Get-SQLBackupStatus {
    param(
        [Parameter(Mandatory)] [string]$Computer,
        [Parameter(Mandatory)] [string]$InstanceName,
        [System.Management.Automation.PSCredential]$WinCredential
    )

    $queryParams = @{
        Computer      = $Computer
        InstanceName  = $InstanceName
        WinCredential = $WinCredential
    }

    try {
        return Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    d.name AS DatabaseName,
    MAX(CASE WHEN bs.type = 'D' THEN bs.backup_finish_date END) AS LastFullBackup,
    MAX(CASE WHEN bs.type = 'I' THEN bs.backup_finish_date END) AS LastDiffBackup,
    MAX(CASE WHEN bs.type = 'L' THEN bs.backup_finish_date END) AS LastLogBackup,
    ISNULL(DATEDIFF(DAY, MAX(CASE WHEN bs.type = 'D' THEN bs.backup_finish_date END), GETDATE()), -1) AS DaysSinceFullBackup,
    MAX(CASE WHEN bs.type = 'D' THEN CAST(bs.backup_size / 1048576 AS DECIMAL(18,2)) END) AS LastFullSizeMB
FROM sys.databases d
LEFT JOIN msdb.dbo.backupset bs ON d.name = bs.database_name
WHERE d.database_id > 4
GROUP BY d.name
ORDER BY d.name
"@
    }
    catch {
        Write-Log "  Failed to get backup status: $_" -Level Warning
        return $null
    }
}

function Get-SQLServerSecurity {
    param(
        [Parameter(Mandatory)] [string]$Computer,
        [Parameter(Mandatory)] [string]$InstanceName,
        [System.Management.Automation.PSCredential]$WinCredential
    )

    $security = @{}
    $queryParams = @{
        Computer      = $Computer
        InstanceName  = $InstanceName
        WinCredential = $WinCredential
    }

    # Server logins with roles - try STRING_AGG first, fall back to FOR XML PATH
    try {
        $security.Logins = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    sp.name AS LoginName,
    sp.type_desc AS LoginType,
    CASE WHEN sp.is_disabled = 1 THEN 'Yes' ELSE 'No' END AS IsDisabled,
    sp.create_date AS CreateDate,
    sp.modify_date AS ModifyDate,
    ISNULL(STRING_AGG(sr.name, ', '), '') AS ServerRoles
FROM sys.server_principals sp
LEFT JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id
LEFT JOIN sys.server_principals sr ON srm.role_principal_id = sr.principal_id
WHERE sp.type IN ('S','U','G') AND sp.name NOT LIKE '##%'
GROUP BY sp.name, sp.type_desc, sp.is_disabled, sp.create_date, sp.modify_date
ORDER BY sp.name
"@
    }
    catch {
        # Fallback for SQL Server < 2017 (no STRING_AGG)
        try {
            $security.Logins = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    sp.name AS LoginName,
    sp.type_desc AS LoginType,
    CASE WHEN sp.is_disabled = 1 THEN 'Yes' ELSE 'No' END AS IsDisabled,
    sp.create_date AS CreateDate,
    sp.modify_date AS ModifyDate,
    ISNULL(STUFF((
        SELECT ', ' + sr2.name
        FROM sys.server_role_members srm2
        JOIN sys.server_principals sr2 ON srm2.role_principal_id = sr2.principal_id
        WHERE srm2.member_principal_id = sp.principal_id
        FOR XML PATH(''), TYPE).value('.','VARCHAR(MAX)'), 1, 2, ''), '') AS ServerRoles
FROM sys.server_principals sp
WHERE sp.type IN ('S','U','G') AND sp.name NOT LIKE '##%'
ORDER BY sp.name
"@
        }
        catch {
            Write-Log "  Failed to get server logins: $_" -Level Warning
            $security.Logins = $null
        }
    }

    # Server-level permissions
    try {
        $security.ServerPermissions = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    pr.name AS PrincipalName,
    pr.type_desc AS PrincipalType,
    pe.permission_name AS Permission,
    pe.state_desc AS PermissionState,
    pe.class_desc AS PermissionClass
FROM sys.server_permissions pe
JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id
WHERE pr.name NOT LIKE '##%' AND pr.name NOT IN ('public')
ORDER BY pr.name, pe.permission_name
"@
    }
    catch {
        Write-Log "  Failed to get server permissions: $_" -Level Warning
        $security.ServerPermissions = $null
    }

    return $security
}

function Get-SQLDatabaseSecurity {
    param(
        [Parameter(Mandatory)] [string]$Computer,
        [Parameter(Mandatory)] [string]$InstanceName,
        [Parameter(Mandatory)] [string]$DatabaseName,
        [System.Management.Automation.PSCredential]$WinCredential
    )

    $dbSecurity = @{}
    $queryParams = @{
        Computer      = $Computer
        InstanceName  = $InstanceName
        WinCredential = $WinCredential
        Database      = $DatabaseName
    }

    # Database users with roles - try STRING_AGG first
    try {
        $dbSecurity.Users = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    DB_NAME() AS DatabaseName,
    dp.name AS UserName,
    dp.type_desc AS UserType,
    dp.create_date AS CreateDate,
    ISNULL(STRING_AGG(drole.name, ', '), '') AS DatabaseRoles,
    sp.name AS LinkedLogin
FROM sys.database_principals dp
LEFT JOIN sys.database_role_members drm ON dp.principal_id = drm.member_principal_id
LEFT JOIN sys.database_principals drole ON drm.role_principal_id = drole.principal_id
LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid
WHERE dp.type IN ('S','U','G')
    AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys')
    AND dp.name NOT LIKE '##%'
GROUP BY dp.name, dp.type_desc, dp.create_date, sp.name
ORDER BY dp.name
"@
    }
    catch {
        # FOR XML PATH fallback
        try {
            $dbSecurity.Users = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    DB_NAME() AS DatabaseName,
    dp.name AS UserName,
    dp.type_desc AS UserType,
    dp.create_date AS CreateDate,
    ISNULL(STUFF((
        SELECT ', ' + drole2.name
        FROM sys.database_role_members drm2
        JOIN sys.database_principals drole2 ON drm2.role_principal_id = drole2.principal_id
        WHERE drm2.member_principal_id = dp.principal_id
        FOR XML PATH(''), TYPE).value('.','VARCHAR(MAX)'), 1, 2, ''), '') AS DatabaseRoles,
    sp.name AS LinkedLogin
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid
WHERE dp.type IN ('S','U','G')
    AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys')
    AND dp.name NOT LIKE '##%'
ORDER BY dp.name
"@
        }
        catch {
            Write-Log "    Failed to get users for $DatabaseName : $_" -Level Warning
            $dbSecurity.Users = $null
        }
    }

    # Explicit permissions
    try {
        $dbSecurity.Permissions = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    DB_NAME() AS DatabaseName,
    dp.name AS PrincipalName,
    dp.type_desc AS PrincipalType,
    perm.permission_name AS Permission,
    perm.state_desc AS PermissionState,
    perm.class_desc AS PermissionClass,
    ISNULL(OBJECT_NAME(perm.major_id), '') AS ObjectName,
    ISNULL(SCHEMA_NAME(perm.major_id), '') AS SchemaName
FROM sys.database_permissions perm
JOIN sys.database_principals dp ON perm.grantee_principal_id = dp.principal_id
WHERE dp.name NOT IN ('public','dbo','guest')
    AND dp.name NOT LIKE '##%'
ORDER BY dp.name, perm.permission_name
"@
    }
    catch {
        Write-Log "    Failed to get permissions for $DatabaseName : $_" -Level Warning
        $dbSecurity.Permissions = $null
    }

    return $dbSecurity
}

function Get-SQLAgentJobs {
    param(
        [Parameter(Mandatory)] [string]$Computer,
        [Parameter(Mandatory)] [string]$InstanceName,
        [System.Management.Automation.PSCredential]$WinCredential
    )

    $queryParams = @{
        Computer      = $Computer
        InstanceName  = $InstanceName
        WinCredential = $WinCredential
        Database      = "msdb"
    }

    try {
        return Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    j.name AS JobName,
    CASE WHEN j.enabled = 1 THEN 'Yes' ELSE 'No' END AS IsEnabled,
    ISNULL(j.description, '') AS Description,
    SUSER_SNAME(j.owner_sid) AS JobOwner,
    j.date_created AS CreateDate,
    j.date_modified AS ModifyDate,
    h.run_date AS LastRunDate,
    CASE h.run_status
        WHEN 0 THEN 'Failed'
        WHEN 1 THEN 'Succeeded'
        WHEN 2 THEN 'Retry'
        WHEN 3 THEN 'Canceled'
        WHEN 4 THEN 'In Progress'
        ELSE 'Unknown'
    END AS LastRunOutcome
FROM msdb.dbo.sysjobs j
OUTER APPLY (
    SELECT TOP 1 run_date, run_status
    FROM msdb.dbo.sysjobhistory jh
    WHERE jh.job_id = j.job_id AND jh.step_id = 0
    ORDER BY jh.run_date DESC, jh.run_time DESC
) h
ORDER BY j.name
"@
    }
    catch {
        Write-Log "  Failed to get SQL Agent jobs: $_" -Level Warning
        return $null
    }
}

function Get-SQLSecurityAssessment {
    param(
        [Parameter(Mandatory)] [string]$Computer,
        [Parameter(Mandatory)] [string]$InstanceName,
        [System.Management.Automation.PSCredential]$WinCredential
    )

    $findings = [System.Collections.ArrayList]::new()
    $queryParams = @{
        Computer      = $Computer
        InstanceName  = $InstanceName
        WinCredential = $WinCredential
    }

    # --- Check 1: Dangerous server configurations ---
    try {
        $configs = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT name, CAST(value_in_use AS INT) AS ValueInUse
FROM sys.configurations
WHERE name IN (
    'xp_cmdshell', 'clr enabled', 'Ole Automation Procedures',
    'Ad Hoc Distributed Queries', 'Database Mail XPs',
    'remote access', 'remote admin connections',
    'scan for startup procs', 'cross db ownership chaining'
)
"@

        $configChecks = @(
            @{ Name = 'xp_cmdshell';                Severity = 'Critical'; Finding = 'xp_cmdshell is enabled';                     Detail = 'Allows execution of OS commands from SQL Server. Major attack vector for privilege escalation.'; Remediation = "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;" }
            @{ Name = 'clr enabled';                Severity = 'Warning';  Finding = 'CLR integration is enabled';                 Detail = 'Allows .NET assemblies to run inside SQL Server. Can be exploited to execute arbitrary code.'; Remediation = "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;" }
            @{ Name = 'Ole Automation Procedures';  Severity = 'Warning';  Finding = 'OLE Automation Procedures enabled';          Detail = 'Allows COM object instantiation from T-SQL. Can access file system and network.'; Remediation = "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;" }
            @{ Name = 'Ad Hoc Distributed Queries'; Severity = 'Warning';  Finding = 'Ad Hoc Distributed Queries enabled';         Detail = 'Allows OPENROWSET/OPENDATASOURCE to access remote data sources without linked server.'; Remediation = "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;" }
            @{ Name = 'Database Mail XPs';          Severity = 'Info';     Finding = 'Database Mail XPs enabled';                  Detail = 'Allows sending email from SQL Server. Can be abused for data exfiltration.'; Remediation = "EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE;" }
            @{ Name = 'remote access';              Severity = 'Warning';  Finding = 'Remote access is enabled';                   Detail = 'Legacy feature allowing remote stored procedure calls. Deprecated and should be disabled.'; Remediation = "EXEC sp_configure 'remote access', 0; RECONFIGURE;" }
            @{ Name = 'remote admin connections';   Severity = 'Info';     Finding = 'Remote DAC (Dedicated Admin Connection) enabled'; Detail = 'Allows remote diagnostic connections. Useful but increases attack surface.'; Remediation = "EXEC sp_configure 'remote admin connections', 0; RECONFIGURE;" }
            @{ Name = 'scan for startup procs';     Severity = 'Warning';  Finding = 'Scan for startup procedures enabled';        Detail = 'SQL Server scans for and runs stored procedures marked for auto-execution at startup.'; Remediation = "EXEC sp_configure 'scan for startup procs', 0; RECONFIGURE;" }
            @{ Name = 'cross db ownership chaining'; Severity = 'Warning'; Finding = 'Cross-database ownership chaining enabled';  Detail = 'Allows cross-database access via ownership chains. Can bypass database-level permissions.'; Remediation = "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE;" }
        )

        if ($configs) {
            foreach ($check in $configChecks) {
                $cfg = $configs | Where-Object { $_.name -eq $check.Name }
                if ($cfg -and $cfg.ValueInUse -eq 1) {
                    [void]$findings.Add([PSCustomObject]@{
                        Finding     = $check.Finding
                        Severity    = $check.Severity
                        CurrentValue = "Enabled (1)"
                        Detail      = $check.Detail
                        Remediation = $check.Remediation
                    })
                }
            }
        }
    }
    catch {
        Write-Log "    Security assessment - config check failed: $_" -Level Warning
    }

    # --- Check 2: Authentication mode ---
    try {
        $authMode = Invoke-RemoteSQLQuery @queryParams -Query "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly"
        if ($authMode -and $authMode.WindowsAuthOnly -eq 0) {
            [void]$findings.Add([PSCustomObject]@{
                Finding      = 'Mixed mode authentication enabled'
                Severity     = 'Warning'
                CurrentValue = 'SQL and Windows Authentication'
                Detail       = 'SQL Server logins use password-based auth which is weaker than Windows/Kerberos authentication.'
                Remediation  = 'Switch to Windows Authentication Only mode if SQL logins are not required.'
            })
        }
    }
    catch {
        Write-Log "    Security assessment - auth mode check failed: $_" -Level Warning
    }

    # --- Check 3: sa account status ---
    try {
        $saInfo = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT name, is_disabled, is_policy_checked, is_expiration_checked
FROM sys.sql_logins WHERE name = 'sa'
"@
        if ($saInfo) {
            if ($saInfo.is_disabled -eq 0) {
                [void]$findings.Add([PSCustomObject]@{
                    Finding      = 'sa account is enabled'
                    Severity     = 'Critical'
                    CurrentValue = 'Enabled'
                    Detail       = 'The built-in sa account is a well-known target. Should be disabled and a renamed admin account used instead.'
                    Remediation  = 'ALTER LOGIN [sa] DISABLE;'
                })
            }
            if ($saInfo.is_policy_checked -eq 0) {
                [void]$findings.Add([PSCustomObject]@{
                    Finding      = 'sa account has no password policy'
                    Severity     = 'Warning'
                    CurrentValue = 'Policy not enforced'
                    Detail       = 'The sa login does not enforce Windows password complexity policy.'
                    Remediation  = 'ALTER LOGIN [sa] WITH CHECK_POLICY = ON;'
                })
            }
            if ($saInfo.is_expiration_checked -eq 0) {
                [void]$findings.Add([PSCustomObject]@{
                    Finding      = 'sa account password never expires'
                    Severity     = 'Warning'
                    CurrentValue = 'Expiration not enforced'
                    Detail       = 'The sa login password has no expiration. Stale credentials increase risk.'
                    Remediation  = 'ALTER LOGIN [sa] WITH CHECK_EXPIRATION = ON;'
                })
            }
        }
    }
    catch {
        Write-Log "    Security assessment - sa account check failed: $_" -Level Warning
    }

    # --- Check 4: Excessive sysadmins ---
    try {
        $sysadminCount = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT COUNT(*) AS SysadminCount
FROM sys.server_role_members srm
JOIN sys.server_principals sp ON srm.member_principal_id = sp.principal_id
WHERE srm.role_principal_id = (
    SELECT principal_id FROM sys.server_principals WHERE name = 'sysadmin'
)
AND sp.name NOT LIKE '##%'
"@
        if ($sysadminCount -and $sysadminCount.SysadminCount -gt 3) {
            [void]$findings.Add([PSCustomObject]@{
                Finding      = 'Excessive sysadmin role members'
                Severity     = 'Warning'
                CurrentValue = "$($sysadminCount.SysadminCount) members"
                Detail       = 'Too many accounts with sysadmin privileges increases risk. Follow principle of least privilege.'
                Remediation  = 'Review sysadmin members and remove unnecessary accounts. Use granular server roles instead.'
            })
        }
    }
    catch {
        Write-Log "    Security assessment - sysadmin count check failed: $_" -Level Warning
    }

    # --- Check 5: TRUSTWORTHY databases ---
    try {
        $trustworthy = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT name AS DatabaseName
FROM sys.databases
WHERE is_trustworthy_on = 1 AND database_id > 4
"@
        if ($trustworthy) {
            $dbNames = @($trustworthy) | ForEach-Object { $_.DatabaseName }
            [void]$findings.Add([PSCustomObject]@{
                Finding      = 'TRUSTWORTHY databases found'
                Severity     = 'Critical'
                CurrentValue = ($dbNames -join ', ')
                Detail       = 'TRUSTWORTHY allows database code to access resources outside the database. Combined with db_owner, this enables privilege escalation to sysadmin.'
                Remediation  = 'ALTER DATABASE [dbname] SET TRUSTWORTHY OFF;'
            })
        }
    }
    catch {
        Write-Log "    Security assessment - TRUSTWORTHY check failed: $_" -Level Warning
    }

    # --- Check 6: Guest access in user databases ---
    try {
        $guestAccess = Invoke-RemoteSQLQuery @queryParams -Query @"
DECLARE @results TABLE (DatabaseName SYSNAME)
DECLARE @sql NVARCHAR(MAX) = ''
SELECT @sql = @sql + 'USE ' + QUOTENAME(name) + '; IF EXISTS (SELECT 1 FROM sys.database_permissions p JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id WHERE dp.name = ''guest'' AND p.permission_name = ''CONNECT'' AND p.state_desc = ''GRANT'' AND p.class = 0) INSERT @results VALUES (''' + REPLACE(name, '''', '''''') + '''); '
FROM sys.databases WHERE database_id > 4 AND state = 0
EXEC sp_executesql @sql
SELECT DatabaseName FROM @results
"@
        if ($guestAccess) {
            $dbNames = @($guestAccess) | ForEach-Object { $_.DatabaseName }
            [void]$findings.Add([PSCustomObject]@{
                Finding      = 'Guest user has CONNECT access'
                Severity     = 'Warning'
                CurrentValue = ($dbNames -join ', ')
                Detail       = 'The guest user can connect to these databases. Any authenticated login can access data without an explicit user mapping.'
                Remediation  = 'USE [dbname]; REVOKE CONNECT FROM guest;'
            })
        }
    }
    catch {
        Write-Log "    Security assessment - guest access check failed: $_" -Level Warning
    }

    # --- Check 7: BUILTIN\Administrators login ---
    try {
        $builtinAdmin = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT name FROM sys.server_principals
WHERE name = 'BUILTIN\Administrators' AND type = 'G'
"@
        if ($builtinAdmin) {
            [void]$findings.Add([PSCustomObject]@{
                Finding      = 'BUILTIN\Administrators login exists'
                Severity     = 'Critical'
                CurrentValue = 'Present'
                Detail       = 'All local Administrators have sysadmin access to SQL Server. Any local admin compromise gives full database control.'
                Remediation  = 'DROP LOGIN [BUILTIN\Administrators]; -- Grant specific AD groups instead'
            })
        }
    }
    catch {
        Write-Log "    Security assessment - BUILTIN Admins check failed: $_" -Level Warning
    }

    # --- Check 8: Public server permissions beyond defaults ---
    try {
        $publicPerms = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT permission_name AS PermissionName
FROM sys.server_permissions
WHERE grantee_principal_id = 0
AND permission_name NOT IN ('CONNECT SQL', 'VIEW ANY DATABASE')
AND state_desc = 'GRANT'
"@
        if ($publicPerms) {
            $permNames = @($publicPerms) | ForEach-Object { $_.PermissionName }
            [void]$findings.Add([PSCustomObject]@{
                Finding      = 'Public role has extra server permissions'
                Severity     = 'Warning'
                CurrentValue = ($permNames -join ', ')
                Detail       = 'The public server role has permissions beyond defaults. All logins inherit these permissions.'
                Remediation  = 'REVOKE <permission> FROM public;'
            })
        }
    }
    catch {
        Write-Log "    Security assessment - public permissions check failed: $_" -Level Warning
    }

    # --- Check 9: Orphaned users ---
    try {
        $orphaned = Invoke-RemoteSQLQuery @queryParams -Query @"
DECLARE @results TABLE (UserName SYSNAME, DatabaseName SYSNAME)
DECLARE @sql NVARCHAR(MAX) = ''
SELECT @sql = @sql + 'USE ' + QUOTENAME(name) + '; INSERT @results SELECT dp.name, DB_NAME() FROM sys.database_principals dp LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid WHERE dp.type IN (''S'',''U'') AND dp.name NOT IN (''dbo'',''guest'',''INFORMATION_SCHEMA'',''sys'') AND dp.name NOT LIKE ''##%'' AND sp.sid IS NULL AND dp.authentication_type <> 0; '
FROM sys.databases WHERE database_id > 4 AND state = 0
EXEC sp_executesql @sql
SELECT UserName, DatabaseName FROM @results
"@
        if ($orphaned) {
            $userNames = @($orphaned) | ForEach-Object { $_.UserName }
            $uniqueNames = $userNames | Select-Object -Unique
            [void]$findings.Add([PSCustomObject]@{
                Finding      = 'Orphaned database users found'
                Severity     = 'Warning'
                CurrentValue = "$($uniqueNames.Count) orphaned user(s)"
                Detail       = "Users with no matching server login: $($uniqueNames -join ', ')"
                Remediation  = 'DROP USER [username]; -- or remap: ALTER USER [username] WITH LOGIN = [loginname];'
            })
        }
    }
    catch {
        # Orphaned user check may fail on some databases, not critical
        Write-Log "    Security assessment - orphaned users check failed: $_" -Level Warning
    }

    # --- Check 10: SQL logins without password policy ---
    try {
        $weakLogins = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT name AS LoginName
FROM sys.sql_logins
WHERE is_policy_checked = 0
AND name NOT LIKE '##%'
AND name <> 'sa'
AND is_disabled = 0
"@
        if ($weakLogins) {
            $loginNames = @($weakLogins) | ForEach-Object { $_.LoginName }
            [void]$findings.Add([PSCustomObject]@{
                Finding      = 'SQL logins without password policy'
                Severity     = 'Warning'
                CurrentValue = "$($loginNames.Count) login(s)"
                Detail       = "Logins not enforcing password complexity: $($loginNames -join ', ')"
                Remediation  = 'ALTER LOGIN [loginname] WITH CHECK_POLICY = ON;'
            })
        }
    }
    catch {
        Write-Log "    Security assessment - weak login check failed: $_" -Level Warning
    }

    Write-Log "    Security assessment complete: $($findings.Count) finding(s)" -Level $(if ($findings.Count -eq 0) { "Success" } else { "Warning" })
    return $findings
}

function Get-SQLKillChainAssessment {
    param(
        [Parameter(Mandatory)]
        [string]$Computer,

        [Parameter(Mandatory)]
        [string]$InstanceName,

        [System.Management.Automation.PSCredential]$WinCredential,

        [array]$SecurityFindings,

        [hashtable]$ServerConfig,

        [hashtable]$ServerSecurity,

        [hashtable]$DatabaseSecurity,

        [array]$AgentJobs
    )

    $attackPaths = [System.Collections.ArrayList]::new()
    $queryParams = @{
        Computer     = $Computer
        InstanceName = $InstanceName
    }
    if ($WinCredential) { $queryParams.WinCredential = $WinCredential }

    # ================================================================
    # Collect additional data not in existing inventory
    # ================================================================

    # Query 1: Linked Servers
    $linkedServers = $null
    try {
        $linkedServers = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    s.server_id,
    s.name AS LinkedServerName,
    s.product AS Product,
    s.provider AS Provider,
    s.data_source AS DataSource,
    CASE WHEN s.is_rpc_out_enabled = 1 THEN 'Yes' ELSE 'No' END AS RpcOutEnabled,
    CASE WHEN s.is_data_access_enabled = 1 THEN 'Yes' ELSE 'No' END AS DataAccessEnabled,
    CASE WHEN ll.uses_self_credential = 1 THEN 'Yes' ELSE 'No' END AS UsesSelfCredential,
    ll.remote_name AS RemoteLoginName,
    ISNULL(sp.name, '** All logins **') AS LocalLogin
FROM sys.servers s
LEFT JOIN sys.linked_logins ll ON s.server_id = ll.server_id
LEFT JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id
WHERE s.server_id > 0
ORDER BY s.name
"@
    }
    catch {
        Write-Log "    Kill chain - linked server query failed: $_" -Level Warning
    }

    # Query 2: Agent Job Steps (dangerous types)
    $dangerousJobSteps = $null
    try {
        $dangerousJobSteps = Invoke-RemoteSQLQuery @queryParams -Database "msdb" -Query @"
SELECT
    j.name AS JobName,
    CASE WHEN j.enabled = 1 THEN 'Yes' ELSE 'No' END AS JobEnabled,
    SUSER_SNAME(j.owner_sid) AS JobOwner,
    js.step_id AS StepID,
    js.step_name AS StepName,
    js.subsystem AS StepType,
    LEFT(js.command, 500) AS StepCommand,
    js.proxy_id AS ProxyID
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobsteps js ON j.job_id = js.job_id
WHERE js.subsystem IN ('CmdExec', 'PowerShell', 'SSIS', 'ActiveScripting')
   OR js.command LIKE '%xp_cmdshell%'
   OR js.command LIKE '%sp_OACreate%'
ORDER BY j.name, js.step_id
"@
    }
    catch {
        Write-Log "    Kill chain - agent job steps query failed: $_" -Level Warning
    }

    # Query 3: Server-Level Impersonation Permissions
    $impersonationPerms = $null
    try {
        $impersonationPerms = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    grantee.name AS GranteeName,
    grantee.type_desc AS GranteeType,
    grantor.name AS ImpersonateTarget,
    perm.state_desc AS PermState,
    CASE WHEN EXISTS (
        SELECT 1 FROM sys.server_role_members srm
        JOIN sys.server_principals sr ON srm.role_principal_id = sr.principal_id
        WHERE srm.member_principal_id = grantor.principal_id
        AND sr.name = 'sysadmin'
    ) THEN 'Yes' ELSE 'No' END AS TargetIsSysadmin
FROM sys.server_permissions perm
JOIN sys.server_principals grantee ON perm.grantee_principal_id = grantee.principal_id
JOIN sys.server_principals grantor ON perm.major_id = grantor.principal_id
WHERE perm.permission_name = 'IMPERSONATE'
AND perm.class_desc = 'SERVER_PRINCIPAL'
AND perm.state_desc IN ('GRANT', 'GRANT_WITH_GRANT_OPTION')
"@
    }
    catch {
        Write-Log "    Kill chain - impersonation query failed: $_" -Level Warning
    }

    # Query 4: Startup Procedures
    $startupProcs = $null
    try {
        $startupProcs = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    OBJECT_SCHEMA_NAME(object_id) AS SchemaName,
    name AS ProcedureName,
    create_date AS CreateDate,
    modify_date AS ModifyDate
FROM sys.procedures
WHERE OBJECTPROPERTY(object_id, 'ExecIsStartup') = 1
"@
    }
    catch {
        Write-Log "    Kill chain - startup procedures query failed: $_" -Level Warning
    }

    # Query 5: EXECUTE AS Procedures across databases
    $executeAsProcs = $null
    try {
        $executeAsProcs = Invoke-RemoteSQLQuery @queryParams -Query @"
DECLARE @results TABLE (DatabaseName SYSNAME, SchemaName NVARCHAR(128), ProcName SYSNAME, ExecuteAs NVARCHAR(256))
DECLARE @sql NVARCHAR(MAX) = ''
SELECT @sql = @sql + 'USE ' + QUOTENAME(name) + ';
INSERT @results
SELECT DB_NAME(), SCHEMA_NAME(p.schema_id), p.name,
    CASE p.execute_as_principal_id
        WHEN -2 THEN ''OWNER''
        ELSE ISNULL(USER_NAME(p.execute_as_principal_id), ''Unknown'')
    END
FROM sys.procedures p
WHERE p.execute_as_principal_id IS NOT NULL AND p.execute_as_principal_id <> 0; '
FROM sys.databases WHERE database_id > 4 AND state = 0
EXEC sp_executesql @sql
SELECT DatabaseName, SchemaName, ProcName, ExecuteAs FROM @results
"@
    }
    catch {
        Write-Log "    Kill chain - EXECUTE AS procedures query failed: $_" -Level Warning
    }

    # Query 6: Server Triggers
    $serverTriggers = $null
    try {
        $serverTriggers = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    name AS TriggerName,
    type_desc AS TriggerType,
    parent_class_desc AS TriggerScope,
    CASE WHEN is_disabled = 1 THEN 'Yes' ELSE 'No' END AS IsDisabled,
    create_date AS CreateDate
FROM sys.server_triggers
WHERE is_disabled = 0
"@
    }
    catch {
        Write-Log "    Kill chain - server triggers query failed: $_" -Level Warning
    }

    # Query 7: Database-Scoped Credentials
    $dbScopedCreds = $null
    try {
        $dbScopedCreds = Invoke-RemoteSQLQuery @queryParams -Query @"
DECLARE @results TABLE (DatabaseName SYSNAME, CredentialName SYSNAME, CredentialIdentity NVARCHAR(256))
DECLARE @sql NVARCHAR(MAX) = ''
SELECT @sql = @sql + 'USE ' + QUOTENAME(name) + ';
IF EXISTS (SELECT 1 FROM sys.all_objects WHERE name = ''database_scoped_credentials'' AND type = ''V'')
INSERT @results SELECT DB_NAME(), name, credential_identity FROM sys.database_scoped_credentials; '
FROM sys.databases WHERE database_id > 4 AND state = 0
EXEC sp_executesql @sql
SELECT DatabaseName, CredentialName, CredentialIdentity FROM @results
"@
    }
    catch {
        Write-Log "    Kill chain - database-scoped credentials query failed: $_" -Level Warning
    }

    # Query 8: xp_cmdshell EXECUTE Permissions (who can run it beyond sysadmins)
    $xpCmdShellPerms = $null
    try {
        $xpCmdShellPerms = Invoke-RemoteSQLQuery @queryParams -Query @"
SELECT
    sp.name AS PrincipalName,
    sp.type_desc AS PrincipalType,
    pe.permission_name AS Permission,
    pe.state_desc AS PermState
FROM sys.server_permissions pe
JOIN sys.server_principals sp ON pe.grantee_principal_id = sp.principal_id
WHERE pe.class_desc = 'OBJECT_OR_COLUMN'
AND OBJECT_NAME(pe.major_id) = 'xp_cmdshell'
AND pe.state_desc IN ('GRANT', 'GRANT_WITH_GRANT_OPTION')
"@
    }
    catch {
        Write-Log "    Kill chain - xp_cmdshell permissions query failed: $_" -Level Warning
    }

    # ================================================================
    # Extract data from existing inventory for cross-referencing
    # ================================================================

    # Helper: check if a security finding exists by substring match
    $hasSecFinding = {
        param([string]$Pattern)
        if (-not $SecurityFindings) { return $false }
        $match = @($SecurityFindings | Where-Object { $_.Finding -match $Pattern })
        return ($match.Count -gt 0)
    }

    # Config-based findings
    $xpCmdShellEnabled = (& $hasSecFinding 'xp_cmdshell')
    $clrEnabled = (& $hasSecFinding 'CLR')
    $oleEnabled = (& $hasSecFinding 'OLE Automation')
    $adHocEnabled = (& $hasSecFinding 'Ad Hoc Distributed')
    $dbMailEnabled = (& $hasSecFinding 'Database Mail')
    $crossDbChaining = (& $hasSecFinding 'Cross.?[Dd]atabase [Oo]wnership')
    $startupProcsScan = (& $hasSecFinding '[Ss]tartup [Pp]roc')
    $mixedMode = (& $hasSecFinding '[Mm]ixed.*[Aa]uth')
    $saEnabled = (& $hasSecFinding 'sa account.*enabled')
    $saNoPolicy = (& $hasSecFinding 'sa.*password policy')
    $trustworthyDbs = (& $hasSecFinding 'TRUSTWORTHY')
    $builtinAdmins = (& $hasSecFinding 'BUILTIN')

    # Sysadmin logins from server security data
    $sysadminLogins = @()
    if ($ServerSecurity -and $ServerSecurity.Logins) {
        $sysadminLogins = @($ServerSecurity.Logins | Where-Object { $_.ServerRoles -match 'sysadmin' })
    }
    $sysadminCount = $sysadminLogins.Count

    # Service account info
    $serviceAccount = "Unknown"
    $highPrivService = $false
    if ($ServerConfig -and $ServerConfig.Services) {
        $sqlSvc = $ServerConfig.Services | Where-Object { $_.servicename -match 'SQL Server \(' } | Select-Object -First 1
        if ($sqlSvc) {
            $serviceAccount = $sqlSvc.service_account
            $highPrivPatterns = @('LocalSystem', 'NT AUTHORITY\\SYSTEM', 'SYSTEM')
            foreach ($pattern in $highPrivPatterns) {
                if ($serviceAccount -match [regex]::Escape($pattern)) { $highPrivService = $true; break }
            }
            # Also check for domain admin patterns (contains \, not a service account pattern)
            if ($serviceAccount -match '\\' -and $serviceAccount -notmatch 'NT SERVICE' -and $serviceAccount -notmatch 'NT AUTHORITY\\(NETWORK SERVICE|LOCAL SERVICE)') {
                # Could be a domain account - flag as potentially high privilege
                $highPrivService = $true
            }
        }
    }

    # SQL Agent service status
    $agentRunning = $false
    if ($ServerConfig -and $ServerConfig.Services) {
        $agentSvc = $ServerConfig.Services | Where-Object { $_.servicename -match 'SQL Server Agent' } | Select-Object -First 1
        if ($agentSvc -and $agentSvc.status_desc -eq 'Running') { $agentRunning = $true }
    }

    # db_owner role holders in TRUSTWORTHY databases
    $trustworthyDbOwners = @()
    if ($trustworthyDbs -and $SecurityFindings -and $DatabaseSecurity) {
        $twFinding = $SecurityFindings | Where-Object { $_.Finding -match 'TRUSTWORTHY' } | Select-Object -First 1
        if ($twFinding -and $twFinding.Detail) {
            # Extract database names from the detail text
            $twDbNames = @($twFinding.Detail -split ',' | ForEach-Object { $_.Trim() })
            foreach ($twDb in $twDbNames) {
                if ($DatabaseSecurity.ContainsKey($twDb) -and $DatabaseSecurity[$twDb].Users) {
                    $dbOwnerUsers = @($DatabaseSecurity[$twDb].Users | Where-Object { $_.DatabaseRoles -match 'db_owner' })
                    foreach ($dbo in $dbOwnerUsers) {
                        $isSysadmin = $false
                        foreach ($sa in $sysadminLogins) {
                            if ($sa.LoginName -eq $dbo.UserName -or $sa.LoginName -eq $dbo.LinkedLogin) {
                                $isSysadmin = $true
                                break
                            }
                        }
                        if (-not $isSysadmin) {
                            $trustworthyDbOwners += [PSCustomObject]@{
                                Database = $twDb
                                User     = $dbo.UserName
                            }
                        }
                    }
                }
            }
        }
    }

    # ================================================================
    # Evaluate 16 Attack Paths
    # ================================================================

    # ---- EXECUTION PHASE ----

    # Attack Path 1: xp_cmdshell RCE
    $ap1Status = "Mitigated"
    $ap1State = "xp_cmdshell: Disabled"
    $ap1Prereqs = "xp_cmdshell enabled + sysadmin role or explicit EXECUTE permission"
    if ($xpCmdShellEnabled) {
        $ap1State = "xp_cmdshell: Enabled"
        $xpExecCount = if ($xpCmdShellPerms) { @($xpCmdShellPerms).Count } else { 0 }
        if ($sysadminCount -gt 0 -or $xpExecCount -gt 0) {
            $ap1Status = "Exploitable"
            $ap1State += "; $sysadminCount sysadmin(s)"
            if ($xpExecCount -gt 0) { $ap1State += "; $xpExecCount explicit EXECUTE grant(s)" }
        }
        else {
            $ap1Status = "Partially Exploitable"
            $ap1State += "; No accessible sysadmin or EXECUTE perms found"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "xp_cmdshell Remote Code Execution"
        KillChainPhase = "Execution"
        Exploitability = $ap1Status
        AuthRequired   = "Sysadmin or EXECUTE grant"
        PrivilegeLevel = "High (Sysadmin)"
        Prerequisites  = $ap1Prereqs
        CurrentState   = $ap1State
        Impact         = "Execute arbitrary OS commands on the SQL Server host as the SQL service account ($serviceAccount)"
        Remediation    = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
    })

    # Attack Path 2: OLE Automation RCE
    $ap2Status = "Mitigated"
    $ap2State = "OLE Automation: Disabled"
    $ap2Prereqs = "OLE Automation Procedures enabled + sysadmin role"
    if ($oleEnabled) {
        $ap2State = "OLE Automation: Enabled"
        if ($sysadminCount -gt 1) {
            $ap2Status = "Exploitable"
            $ap2State += "; $sysadminCount sysadmin(s) can use sp_OACreate/sp_OAMethod"
        }
        elseif ($sysadminCount -eq 1) {
            $ap2Status = "Partially Exploitable"
            $ap2State += "; Only default sa/sysadmin (limited exposure)"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "OLE Automation Procedures RCE"
        KillChainPhase = "Execution"
        Exploitability = $ap2Status
        AuthRequired   = "Sysadmin"
        PrivilegeLevel = "High (Sysadmin)"
        Prerequisites  = $ap2Prereqs
        CurrentState   = $ap2State
        Impact         = "Execute OS commands via sp_OACreate/sp_OAMethod (file system, WScript.Shell, network access)"
        Remediation    = "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;"
    })

    # Attack Path 3: CLR Assembly Execution
    $ap3Status = "Mitigated"
    $ap3State = "CLR: Disabled"
    $ap3Prereqs = "CLR enabled + TRUSTWORTHY database + db_owner role in that database"
    if ($clrEnabled) {
        $ap3State = "CLR: Enabled"
        if ($trustworthyDbs -and $trustworthyDbOwners.Count -gt 0) {
            $ap3Status = "Exploitable"
            $dbList = ($trustworthyDbOwners | ForEach-Object { "$($_.Database):$($_.User)" }) -join ', '
            $ap3State += "; TRUSTWORTHY db_owner(s): $dbList"
        }
        elseif ($trustworthyDbs) {
            $ap3Status = "Partially Exploitable"
            $ap3State += "; TRUSTWORTHY DBs exist but no non-sysadmin db_owner found"
        }
        else {
            $ap3Status = "Partially Exploitable"
            $ap3State += "; No TRUSTWORTHY databases (needs sysadmin to load assemblies)"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "CLR Assembly Code Execution"
        KillChainPhase = "Execution"
        Exploitability = $ap3Status
        AuthRequired   = "db_owner on TRUSTWORTHY DB"
        PrivilegeLevel = "Medium (db_owner)"
        Prerequisites  = $ap3Prereqs
        CurrentState   = $ap3State
        Impact         = "Load and execute arbitrary .NET code inside SQL Server process (full RCE)"
        Remediation    = "EXEC sp_configure 'clr enabled', 0; RECONFIGURE; ALTER DATABASE [db] SET TRUSTWORTHY OFF;"
    })

    # Attack Path 4: Agent Job Command Execution
    $ap4Status = "Mitigated"
    $ap4State = "No dangerous job steps found"
    $ap4Prereqs = "SQL Agent running + CmdExec/PowerShell job steps + sysadmin-owned jobs"
    $dangerousStepCount = if ($dangerousJobSteps) { @($dangerousJobSteps).Count } else { 0 }
    if ($dangerousStepCount -gt 0) {
        $sysadminOwned = @($dangerousJobSteps | Where-Object {
            $owner = $_.JobOwner
            $isSa = $false
            foreach ($sa in $sysadminLogins) { if ($sa.LoginName -eq $owner) { $isSa = $true; break } }
            $isSa
        })
        if ($sysadminOwned.Count -gt 0 -and $agentRunning) {
            $ap4Status = "Exploitable"
            $jobNames = ($sysadminOwned | Select-Object -ExpandProperty JobName -Unique) -join ', '
            $ap4State = "$($sysadminOwned.Count) dangerous step(s) in sysadmin-owned jobs: $jobNames"
        }
        elseif ($agentRunning) {
            $ap4Status = "Partially Exploitable"
            $ap4State = "$dangerousStepCount dangerous step(s) found but not owned by sysadmin"
        }
        else {
            $ap4Status = "Partially Exploitable"
            $ap4State = "$dangerousStepCount dangerous step(s) found but SQL Agent not running"
        }
    }
    elseif ($agentRunning -and $sysadminCount -gt 1) {
        $ap4Status = "Partially Exploitable"
        $ap4State = "No dangerous steps yet but Agent running + $sysadminCount sysadmins could create them"
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "SQL Agent Job Command Execution"
        KillChainPhase = "Execution"
        Exploitability = $ap4Status
        AuthRequired   = "Sysadmin or SQLAgentOperatorRole"
        PrivilegeLevel = "High (Sysadmin)"
        Prerequisites  = $ap4Prereqs
        CurrentState   = $ap4State
        Impact         = "Execute OS commands (CmdExec/PowerShell) via SQL Agent as the Agent service account"
        Remediation    = "Review and remove CmdExec/PowerShell job steps; restrict SQLAgentOperatorRole membership; use proxy accounts with least privilege"
    })

    # ---- PRIVILEGE ESCALATION PHASE ----

    # Attack Path 5: TRUSTWORTHY db_owner to sysadmin
    $ap5Status = "Mitigated"
    $ap5State = "No TRUSTWORTHY user databases"
    $ap5Prereqs = "TRUSTWORTHY database + non-sysadmin user with db_owner role"
    if ($trustworthyDbs) {
        if ($trustworthyDbOwners.Count -gt 0) {
            $ap5Status = "Exploitable"
            $dbList = ($trustworthyDbOwners | ForEach-Object { "$($_.Database) ($($_.User))" }) -join ', '
            $ap5State = "TRUSTWORTHY with non-sysadmin db_owner: $dbList"
        }
        else {
            $ap5Status = "Partially Exploitable"
            $ap5State = "TRUSTWORTHY databases exist but all db_owners are already sysadmin"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "TRUSTWORTHY Database Privilege Escalation"
        KillChainPhase = "Privilege Escalation"
        Exploitability = $ap5Status
        AuthRequired   = "db_owner on TRUSTWORTHY DB"
        PrivilegeLevel = "Medium (db_owner)"
        Prerequisites  = $ap5Prereqs
        CurrentState   = $ap5State
        Impact         = "db_owner can create a stored procedure or CLR assembly that runs as sysadmin, gaining full server control"
        Remediation    = "ALTER DATABASE [db] SET TRUSTWORTHY OFF; Review db_owner role membership"
    })

    # Attack Path 6: Impersonation to sysadmin
    $ap6Status = "Mitigated"
    $ap6State = "No IMPERSONATE permissions found"
    $ap6Prereqs = "IMPERSONATE permission on a sysadmin login"
    $impCount = if ($impersonationPerms) { @($impersonationPerms).Count } else { 0 }
    if ($impCount -gt 0) {
        $sysadminTargets = @($impersonationPerms | Where-Object { $_.TargetIsSysadmin -eq 'Yes' })
        if ($sysadminTargets.Count -gt 0) {
            $ap6Status = "Exploitable"
            $details = ($sysadminTargets | ForEach-Object { "$($_.GranteeName) can impersonate $($_.ImpersonateTarget)" }) -join '; '
            $ap6State = "$($sysadminTargets.Count) impersonation path(s) to sysadmin: $details"
        }
        else {
            $ap6Status = "Partially Exploitable"
            $ap6State = "$impCount IMPERSONATE permission(s) but none target sysadmin logins"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "Login Impersonation to Sysadmin"
        KillChainPhase = "Privilege Escalation"
        Exploitability = $ap6Status
        AuthRequired   = "Any SQL Login with IMPERSONATE"
        PrivilegeLevel = "Low (Any Login)"
        Prerequisites  = $ap6Prereqs
        CurrentState   = $ap6State
        Impact         = "EXECUTE AS LOGIN allows full sysadmin access without knowing the target password"
        Remediation    = "REVOKE IMPERSONATE ON LOGIN::[target] FROM [grantee]; Review all IMPERSONATE grants"
    })

    # Attack Path 7: Service Account Exploitation
    $ap7Status = "Mitigated"
    $ap7State = "Service account: $serviceAccount"
    $ap7Prereqs = "SQL service running as high-privilege account + code execution capability (xp_cmdshell/CLR)"
    if ($highPrivService) {
        if ($xpCmdShellEnabled -or $clrEnabled) {
            $ap7Status = "Exploitable"
            $execMethod = if ($xpCmdShellEnabled -and $clrEnabled) { "xp_cmdshell AND CLR" }
                          elseif ($xpCmdShellEnabled) { "xp_cmdshell" }
                          else { "CLR" }
            $ap7State = "High-privilege service ($serviceAccount) + $execMethod enabled"
        }
        else {
            $ap7Status = "Partially Exploitable"
            $ap7State = "High-privilege service ($serviceAccount) but no code execution path enabled"
        }
    }
    else {
        $ap7State = "Low-privilege service account ($serviceAccount)"
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "Service Account Exploitation"
        KillChainPhase = "Privilege Escalation"
        Exploitability = $ap7Status
        AuthRequired   = "Sysadmin (code execution needed)"
        PrivilegeLevel = "High (Sysadmin)"
        Prerequisites  = $ap7Prereqs
        CurrentState   = $ap7State
        Impact         = "OS commands run as the SQL service account; if high-privilege, full domain/host compromise"
        Remediation    = "Run SQL Server under a low-privilege managed service account (gMSA or virtual account); disable xp_cmdshell and CLR"
    })

    # Attack Path 8: Ownership Chaining
    $ap8Status = "Mitigated"
    $ap8State = "Cross-DB ownership chaining: Disabled"
    $ap8Prereqs = "Cross-database ownership chaining enabled + EXECUTE AS OWNER stored procedures"
    $execAsCount = if ($executeAsProcs) { @($executeAsProcs).Count } else { 0 }
    if ($crossDbChaining) {
        $ap8State = "Cross-DB ownership chaining: Enabled"
        if ($execAsCount -gt 0) {
            $ownerProcs = @($executeAsProcs | Where-Object { $_.ExecuteAs -eq 'OWNER' })
            if ($ownerProcs.Count -gt 0) {
                $ap8Status = "Exploitable"
                $procList = ($ownerProcs | ForEach-Object { "$($_.DatabaseName).$($_.SchemaName).$($_.ProcName)" }) -join ', '
                $ap8State += "; $($ownerProcs.Count) EXECUTE AS OWNER proc(s): $procList"
            }
            else {
                $ap8Status = "Partially Exploitable"
                $ap8State += "; $execAsCount EXECUTE AS proc(s) found but none use OWNER context"
            }
        }
        else {
            $ap8Status = "Partially Exploitable"
            $ap8State += "; No EXECUTE AS procedures found (chaining still a risk)"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "Cross-Database Ownership Chaining"
        KillChainPhase = "Privilege Escalation"
        Exploitability = $ap8Status
        AuthRequired   = "EXECUTE on cross-DB procedure"
        PrivilegeLevel = "Low (Any Login)"
        Prerequisites  = $ap8Prereqs
        CurrentState   = $ap8State
        Impact         = "Bypass database-level permission checks; access objects across databases without explicit grants"
        Remediation    = "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE; Review EXECUTE AS OWNER procedures"
    })

    # ---- LATERAL MOVEMENT PHASE ----

    # Attack Path 9: Linked Server Pivot
    $ap9Status = "Mitigated"
    $ap9State = "No linked servers configured"
    $ap9Prereqs = "Linked servers with RPC out enabled + saved credentials or self-credential passthrough"
    $linkedCount = if ($linkedServers) { @($linkedServers).Count } else { 0 }
    if ($linkedCount -gt 0) {
        $rpcOutServers = @($linkedServers | Where-Object { $_.RpcOutEnabled -eq 'Yes' })
        $savedCredServers = @($linkedServers | Where-Object { $_.RemoteLoginName -and $_.RemoteLoginName -ne '' })
        $selfCredServers = @($linkedServers | Where-Object { $_.UsesSelfCredential -eq 'Yes' })
        $exploitableLinked = @($rpcOutServers | Where-Object {
            ($_.RemoteLoginName -and $_.RemoteLoginName -ne '') -or $_.UsesSelfCredential -eq 'Yes'
        })

        if ($exploitableLinked.Count -gt 0) {
            $ap9Status = "Exploitable"
            $names = ($exploitableLinked | Select-Object -ExpandProperty LinkedServerName -Unique) -join ', '
            $ap9State = "$($exploitableLinked.Count) linked server(s) with RPC out + credentials: $names"
        }
        elseif ($rpcOutServers.Count -gt 0) {
            $ap9Status = "Partially Exploitable"
            $ap9State = "$($rpcOutServers.Count) linked server(s) with RPC out but no saved/self credentials"
        }
        else {
            $ap9Status = "Partially Exploitable"
            $names = ($linkedServers | Select-Object -ExpandProperty LinkedServerName -Unique) -join ', '
            $ap9State = "$linkedCount linked server(s) configured (RPC out disabled): $names"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "Linked Server Pivot"
        KillChainPhase = "Lateral Movement"
        Exploitability = $ap9Status
        AuthRequired   = "Any SQL Session"
        PrivilegeLevel = "Low (Any Login)"
        Prerequisites  = $ap9Prereqs
        CurrentState   = $ap9State
        Impact         = "Execute queries and commands on remote SQL Server instances using stored or passthrough credentials"
        Remediation    = "Remove unnecessary linked servers; disable RPC out; use least-privilege mapped logins instead of self-credential"
    })

    # Attack Path 10: Ad Hoc Distributed Queries
    $ap10Status = "Mitigated"
    $ap10State = "Ad Hoc Distributed Queries: Disabled"
    $ap10Prereqs = "Ad Hoc Distributed Queries enabled + sysadmin or CONTROL SERVER permission"
    if ($adHocEnabled) {
        $ap10State = "Ad Hoc Distributed Queries: Enabled"
        if ($sysadminCount -gt 0) {
            $ap10Status = "Exploitable"
            $ap10State += "; $sysadminCount sysadmin(s) can use OPENROWSET/OPENDATASOURCE to any remote server"
        }
        else {
            $ap10Status = "Partially Exploitable"
            $ap10State += "; Enabled but no sysadmin access detected"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "Ad Hoc Distributed Queries"
        KillChainPhase = "Lateral Movement"
        Exploitability = $ap10Status
        AuthRequired   = "Sysadmin or CONTROL SERVER"
        PrivilegeLevel = "High (Sysadmin)"
        Prerequisites  = $ap10Prereqs
        CurrentState   = $ap10State
        Impact         = "Query arbitrary remote SQL Server, OLE DB, or ODBC data sources without linked server configuration (OPENROWSET/OPENDATASOURCE)"
        Remediation    = "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;"
    })

    # Attack Path 11: Database Mail Exfiltration
    $ap11Status = "Mitigated"
    $ap11State = "Database Mail: Disabled"
    $ap11Prereqs = "Database Mail XPs enabled + EXECUTE permission on sp_send_dbmail or sysadmin"
    if ($dbMailEnabled) {
        $ap11State = "Database Mail: Enabled"
        if ($sysadminCount -gt 0) {
            $ap11Status = "Exploitable"
            $ap11State += "; $sysadminCount sysadmin(s) can send email with query results attached"
        }
        else {
            $ap11Status = "Partially Exploitable"
            $ap11State += "; Enabled but no sysadmin (check DatabaseMailUserRole membership)"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "Database Mail Data Exfiltration"
        KillChainPhase = "Lateral Movement"
        Exploitability = $ap11Status
        AuthRequired   = "DatabaseMailUserRole or Sysadmin"
        PrivilegeLevel = "Medium (DB Role)"
        Prerequisites  = $ap11Prereqs
        CurrentState   = $ap11State
        Impact         = "Send query results and attachments via email (data exfiltration via SMTP out-of-band channel)"
        Remediation    = "EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE; Remove unnecessary DatabaseMailUserRole members"
    })

    # ---- PERSISTENCE PHASE ----

    # Attack Path 12: Startup Procedure Persistence
    $ap12Status = "Mitigated"
    $ap12State = "Startup procedure scanning: Disabled"
    $ap12Prereqs = "scan for startup procs enabled + existing or createable startup procedures"
    $startupCount = if ($startupProcs) { @($startupProcs).Count } else { 0 }
    if ($startupProcsScan) {
        $ap12State = "Startup procedure scanning: Enabled"
        if ($startupCount -gt 0) {
            $ap12Status = "Exploitable"
            $procNames = ($startupProcs | ForEach-Object { "$($_.SchemaName).$($_.ProcedureName)" }) -join ', '
            $ap12State += "; $startupCount startup proc(s): $procNames"
        }
        elseif ($sysadminCount -gt 1) {
            $ap12Status = "Partially Exploitable"
            $ap12State += "; No startup procs yet but $sysadminCount sysadmins could create them"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "Startup Procedure Persistence"
        KillChainPhase = "Persistence"
        Exploitability = $ap12Status
        AuthRequired   = "Sysadmin"
        PrivilegeLevel = "High (Sysadmin)"
        Prerequisites  = $ap12Prereqs
        CurrentState   = $ap12State
        Impact         = "Stored procedure executes automatically every time SQL Server starts (persistent backdoor)"
        Remediation    = "EXEC sp_configure 'scan for startup procs', 0; RECONFIGURE; Review: SELECT * FROM sys.procedures WHERE OBJECTPROPERTY(object_id,'ExecIsStartup')=1"
    })

    # Attack Path 13: Agent Job Persistence
    $ap13Status = "Mitigated"
    $ap13State = "SQL Agent: Not running"
    $ap13Prereqs = "SQL Agent running + sysadmin or SQLAgentOperatorRole to create/modify jobs"
    if ($agentRunning) {
        $ap13State = "SQL Agent: Running"
        if ($sysadminCount -gt 1) {
            $ap13Status = "Exploitable"
            $ap13State += "; $sysadminCount sysadmins can create scheduled jobs for persistent execution"
        }
        elseif ($sysadminCount -eq 1) {
            $ap13Status = "Partially Exploitable"
            $ap13State += "; Only 1 sysadmin (limited job creation surface)"
        }
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "SQL Agent Job Persistence"
        KillChainPhase = "Persistence"
        Exploitability = $ap13Status
        AuthRequired   = "Sysadmin or SQLAgentOperatorRole"
        PrivilegeLevel = "High (Sysadmin)"
        Prerequisites  = $ap13Prereqs
        CurrentState   = $ap13State
        Impact         = "Create or modify SQL Agent jobs to execute malicious commands on a schedule (survives reboots)"
        Remediation    = "Restrict sysadmin membership; audit SQL Agent job creation and modification; use job step proxies with least privilege"
    })

    # Attack Path 14: Trigger-based Persistence
    $ap14Status = "Mitigated"
    $ap14State = "No enabled server triggers found"
    $ap14Prereqs = "CREATE/ALTER trigger permission + DDL/DML triggers on server or database objects"
    $triggerCount = if ($serverTriggers) { @($serverTriggers).Count } else { 0 }
    if ($triggerCount -gt 0) {
        $ap14Status = "Exploitable"
        $trigNames = ($serverTriggers | ForEach-Object { $_.TriggerName }) -join ', '
        $ap14State = "$triggerCount enabled server trigger(s): $trigNames"
    }
    elseif ($sysadminCount -gt 1) {
        $ap14Status = "Partially Exploitable"
        $ap14State = "No server triggers but $sysadminCount sysadmins could create them"
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "Trigger-based Persistence"
        KillChainPhase = "Persistence"
        Exploitability = $ap14Status
        AuthRequired   = "Sysadmin"
        PrivilegeLevel = "High (Sysadmin)"
        Prerequisites  = $ap14Prereqs
        CurrentState   = $ap14State
        Impact         = "DDL/DML triggers execute automatically on database events (CREATE, ALTER, INSERT, etc.) for covert persistence"
        Remediation    = "Review server triggers: SELECT * FROM sys.server_triggers; Remove unauthorized triggers; restrict CREATE DDL TRIGGER permission"
    })

    # ---- CREDENTIAL ACCESS PHASE ----

    # Attack Path 15: sa Brute Force
    $ap15Status = "Mitigated"
    $ap15State = "sa account: Disabled or Windows-only auth"
    $ap15Prereqs = "sa account enabled + mixed mode authentication + weak/no password policy"
    if ($saEnabled -and $mixedMode) {
        if ($saNoPolicy) {
            $ap15Status = "Exploitable"
            $ap15State = "sa enabled + mixed mode + NO password policy (brute force viable)"
        }
        else {
            $ap15Status = "Partially Exploitable"
            $ap15State = "sa enabled + mixed mode but password policy is enforced"
        }
    }
    elseif ($saEnabled) {
        $ap15Status = "Partially Exploitable"
        $ap15State = "sa enabled but Windows-only authentication (network access limited)"
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "SA Account Brute Force"
        KillChainPhase = "Credential Access"
        Exploitability = $ap15Status
        AuthRequired   = "No Auth Required"
        PrivilegeLevel = "None (Unauthenticated)"
        Prerequisites  = $ap15Prereqs
        CurrentState   = $ap15State
        Impact         = "Full sysadmin access via the well-known sa account (default target for attackers)"
        Remediation    = "ALTER LOGIN sa DISABLE; Switch to Windows authentication only; if sa must be enabled, enforce strong password policy"
    })

    # Attack Path 16: Credential Harvesting
    $ap16Status = "Mitigated"
    $ap16State = "No stored credentials found"
    $ap16Prereqs = "Linked server saved credentials OR agent job embedded credentials OR database-scoped credentials"
    $credSources = @()
    # Check linked server saved credentials
    $savedCredCount = if ($linkedServers) { @($linkedServers | Where-Object { $_.RemoteLoginName -and $_.RemoteLoginName -ne '' }).Count } else { 0 }
    if ($savedCredCount -gt 0) { $credSources += "$savedCredCount linked server saved login(s)" }
    # Check database-scoped credentials
    $dbCredCount = if ($dbScopedCreds) { @($dbScopedCreds).Count } else { 0 }
    if ($dbCredCount -gt 0) { $credSources += "$dbCredCount database-scoped credential(s)" }
    # Check agent job steps for embedded credentials (connection strings, passwords)
    $suspiciousSteps = 0
    if ($dangerousJobSteps) {
        foreach ($step in @($dangerousJobSteps)) {
            if ($step.StepCommand -match '(?i)(password|pwd)\s*=' -or $step.StepCommand -match '(?i)credential') {
                $suspiciousSteps++
            }
        }
    }
    if ($suspiciousSteps -gt 0) { $credSources += "$suspiciousSteps job step(s) with possible embedded credentials" }

    if ($credSources.Count -gt 0) {
        $ap16Status = "Exploitable"
        $ap16State = ($credSources -join '; ')
    }
    [void]$attackPaths.Add([PSCustomObject]@{
        AttackPath     = "Credential Harvesting"
        KillChainPhase = "Credential Access"
        Exploitability = $ap16Status
        AuthRequired   = "Any SQL Session"
        PrivilegeLevel = "Low (Any Login)"
        Prerequisites  = $ap16Prereqs
        CurrentState   = $ap16State
        Impact         = "Extract stored credentials from linked servers, agent jobs, or database-scoped credentials for further compromise"
        Remediation    = "Remove saved passwords from linked servers (use integrated auth); use SQL Agent proxies instead of embedding credentials; rotate and audit database-scoped credentials"
    })

    # ================================================================
    # Build Kill Chain Phase Summary
    # ================================================================
    $phases = @("Execution", "Privilege Escalation", "Lateral Movement", "Persistence", "Credential Access")
    $phaseSummary = foreach ($phase in $phases) {
        $pathsInPhase = @($attackPaths | Where-Object { $_.KillChainPhase -eq $phase })
        $exploitable = @($pathsInPhase | Where-Object { $_.Exploitability -eq 'Exploitable' }).Count
        $partial = @($pathsInPhase | Where-Object { $_.Exploitability -eq 'Partially Exploitable' }).Count
        $mitigated = @($pathsInPhase | Where-Object { $_.Exploitability -eq 'Mitigated' }).Count
        $risk = if ($exploitable -gt 0) { 'Critical' }
                elseif ($partial -gt 0) { 'Warning' }
                else { 'Info' }
        $keyNames = @($pathsInPhase | Where-Object { $_.Exploitability -ne 'Mitigated' } | ForEach-Object { $_.AttackPath })
        $keyNamesStr = if ($keyNames.Count -gt 0) { $keyNames -join ', ' } else { 'None' }

        # Determine lowest privilege among non-mitigated paths in this phase
        $activePaths = @($pathsInPhase | Where-Object { $_.Exploitability -ne 'Mitigated' })
        $privOrder = @('None (Unauthenticated)', 'Low (Any Login)', 'Medium (db_owner)', 'Medium (DB Role)', 'High (Sysadmin)')
        $lowestPriv = 'N/A'
        foreach ($p in $privOrder) {
            $matchFound = @($activePaths | Where-Object { $_.PrivilegeLevel -eq $p })
            if ($matchFound.Count -gt 0) {
                $lowestPriv = $p
                break
            }
        }

        [PSCustomObject]@{
            Phase            = $phase
            ExploitableCount = $exploitable
            PartialCount     = $partial
            MitigatedCount   = $mitigated
            OverallRisk      = $risk
            LowestPrivilege  = $lowestPriv
            KeyFindings      = $keyNamesStr
        }
    }

    $exploitableTotal = @($attackPaths | Where-Object { $_.Exploitability -eq 'Exploitable' }).Count
    $logLevel = if ($exploitableTotal -gt 0) { "Warning" } else { "Success" }
    Write-Log "    Kill chain assessment complete: $exploitableTotal exploitable path(s) of $($attackPaths.Count) evaluated" -Level $logLevel

    return @{
        AttackPaths     = $attackPaths
        KillChainPhases = $phaseSummary
    }
}

#endregion

#region ==================== HTML REPORT GENERATION ====================

function ConvertTo-HtmlTable {
    param(
        $Data,

        [string[]]$Properties,

        [string]$EmptyMessage = "No data available"
    )

    if (-not $Data -or @($Data).Count -eq 0) {
        return "<p class='no-data'>$EmptyMessage</p>"
    }

    $rows = @($Data)
    if (-not $Properties) {
        $Properties = $rows[0].PSObject.Properties.Name |
            Where-Object { $_ -notin @("PSComputerName", "RunspaceId", "PSShowComputerName", "RowError", "RowState", "Table", "ItemArray", "HasErrors") }
    }

    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine("<table>")
    [void]$html.AppendLine("<thead><tr>")
    foreach ($prop in $Properties) {
        $header = $prop -replace "([a-z])([A-Z])", '$1 $2'
        [void]$html.AppendLine("<th>$([System.Web.HttpUtility]::HtmlEncode($header))</th>")
    }
    [void]$html.AppendLine("</tr></thead>")
    [void]$html.AppendLine("<tbody>")

    foreach ($row in $rows) {
        [void]$html.AppendLine("<tr>")
        foreach ($prop in $Properties) {
            $val = $row.$prop
            $cellClass = ""

            # Color coding for backup days
            if ($prop -eq "DaysSinceFullBackup" -and $val -ne $null) {
                if ($val -lt 0) { $cellClass = " class='status-critical'" ; $val = "Never" }
                elseif ($val -le 1) { $cellClass = " class='status-ok'" }
                elseif ($val -le 7) { $cellClass = " class='status-warning'" }
                else { $cellClass = " class='status-critical'" }
            }

            # Color coding for job status
            if ($prop -eq "LastRunOutcome") {
                if ($val -eq "Succeeded") { $cellClass = " class='status-ok'" }
                elseif ($val -eq "Failed") { $cellClass = " class='status-critical'" }
                elseif ($val -eq "Unknown") { $cellClass = " class='status-warning'" }
            }

            # Color coding for disabled items
            if ($prop -eq "IsDisabled" -and $val -eq "Yes") {
                $cellClass = " class='status-warning'"
            }

            # Color coding for security assessment severity
            if ($prop -eq "Severity") {
                if ($val -eq "Critical") { $cellClass = " class='status-critical'" }
                elseif ($val -eq "Warning") { $cellClass = " class='status-warning'" }
                elseif ($val -eq "Info") { $cellClass = " class='status-ok'" }
            }

            # Color coding for kill chain exploitability status
            if ($prop -eq "Exploitability") {
                if ($val -eq "Exploitable") { $cellClass = " class='status-critical'" }
                elseif ($val -eq "Partially Exploitable") { $cellClass = " class='status-warning'" }
                elseif ($val -eq "Mitigated") { $cellClass = " class='status-ok'" }
            }

            # Color coding for kill chain phase overall risk
            if ($prop -eq "OverallRisk") {
                if ($val -eq "Critical") { $cellClass = " class='status-critical'" }
                elseif ($val -eq "Warning") { $cellClass = " class='status-warning'" }
                elseif ($val -eq "Info") { $cellClass = " class='status-ok'" }
            }

            # Color coding for privilege level (lower privilege = higher risk to defenders)
            if ($prop -eq "PrivilegeLevel" -or $prop -eq "LowestPrivilege") {
                if ($val -match "^None") { $cellClass = " class='status-critical'" }
                elseif ($val -match "^Low") { $cellClass = " class='status-critical'" }
                elseif ($val -match "^Medium") { $cellClass = " class='status-warning'" }
                elseif ($val -match "^High") { $cellClass = " class='status-ok'" }
            }

            # Color coding for auth required (highlight unauthenticated)
            if ($prop -eq "AuthRequired") {
                if ($val -eq "No Auth Required") { $cellClass = " class='status-critical'" }
            }

            $displayVal = if ($null -eq $val) { "" }
                          elseif ($val -is [datetime]) { $val.ToString("yyyy-MM-dd HH:mm:ss") }
                          else { [System.Web.HttpUtility]::HtmlEncode($val.ToString()) }

            [void]$html.AppendLine("<td$cellClass>$displayVal</td>")
        }
        [void]$html.AppendLine("</tr>")
    }

    [void]$html.AppendLine("</tbody></table>")
    return $html.ToString()
}

function Get-HtmlHeader {
    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #f0f2f5;
        color: #333;
        padding: 20px;
    }
    .container {
        max-width: 1400px;
        margin: 0 auto;
        background: #fff;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        overflow: hidden;
    }
    .report-header {
        background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
        color: white;
        padding: 30px 40px;
    }
    .report-header h1 {
        font-size: 28px;
        font-weight: 300;
        margin-bottom: 5px;
    }
    .report-header .subtitle {
        font-size: 14px;
        opacity: 0.8;
    }
    .header-info {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin-top: 20px;
    }
    .header-info-item {
        background: rgba(255,255,255,0.1);
        border-radius: 6px;
        padding: 12px 16px;
    }
    .header-info-label {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1px;
        opacity: 0.7;
    }
    .header-info-value {
        font-size: 16px;
        font-weight: 500;
        margin-top: 4px;
    }
    .content { padding: 20px 40px 40px; }
    .metrics-row {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 15px;
        margin: 20px 0 30px;
    }
    .metric-card {
        background: #f8f9fa;
        border: 1px solid #e9ecef;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
    }
    .metric-value {
        font-size: 32px;
        font-weight: 700;
        color: #1a237e;
    }
    .metric-label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #6c757d;
        margin-top: 5px;
    }
    .section {
        margin-bottom: 10px;
        border: 1px solid #e9ecef;
        border-radius: 6px;
        overflow: hidden;
    }
    .section-header {
        background: #f8f9fa;
        padding: 15px 20px;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 16px;
        font-weight: 600;
        color: #1a237e;
        border-left: 4px solid #1a237e;
        user-select: none;
    }
    .section-header:hover { background: #e9ecef; }
    .section-header .toggle { font-size: 12px; color: #6c757d; transition: transform 0.2s; }
    .section-header.active .toggle { transform: rotate(90deg); }
    .section-content {
        display: none;
        padding: 20px;
        border-top: 1px solid #e9ecef;
    }
    .section-content.active { display: block; }
    .sub-section { margin: 20px 0; }
    .sub-section h3 {
        font-size: 14px;
        color: #495057;
        margin-bottom: 10px;
        padding-bottom: 5px;
        border-bottom: 1px solid #e9ecef;
    }
    .table-scroll {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        margin: 10px 0;
    }
    .table-scroll table {
        min-width: 1200px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
        margin: 10px 0;
    }
    thead th {
        background: #343a40;
        color: white;
        padding: 10px 12px;
        text-align: left;
        font-weight: 600;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        white-space: nowrap;
    }
    tbody td {
        padding: 8px 12px;
        border-bottom: 1px solid #e9ecef;
        vertical-align: top;
    }
    tbody tr:hover { background: #f8f9fa; }
    tbody tr:nth-child(even) { background: #fdfdfe; }
    tbody tr:nth-child(even):hover { background: #f8f9fa; }
    .status-ok { color: #28a745; font-weight: 600; }
    .status-warning { color: #ffc107; font-weight: 600; }
    .status-critical { color: #dc3545; font-weight: 600; }
    .no-data {
        text-align: center;
        color: #6c757d;
        padding: 30px;
        font-style: italic;
    }
    .errors-section {
        background: #fff3cd;
        border: 1px solid #ffc107;
        border-radius: 6px;
        padding: 15px 20px;
        margin: 20px 0;
    }
    .errors-section h3 { color: #856404; margin-bottom: 10px; }
    .errors-section li { color: #856404; margin: 5px 0; font-size: 13px; }
    .footer {
        text-align: center;
        padding: 20px;
        color: #6c757d;
        font-size: 12px;
        border-top: 1px solid #e9ecef;
        margin-top: 20px;
    }
    a { color: #1a237e; text-decoration: none; }
    a:hover { text-decoration: underline; }
    @media print {
        .section-content { display: block !important; }
        .section-header .toggle { display: none; }
        body { background: white; padding: 0; }
        .container { box-shadow: none; }
    }
</style>
<script>
function toggleSection(id) {
    var content = document.getElementById(id);
    var header = content.previousElementSibling;
    content.classList.toggle('active');
    header.classList.toggle('active');
}
function expandAll() {
    document.querySelectorAll('.section-content').forEach(function(el) {
        el.classList.add('active');
        el.previousElementSibling.classList.add('active');
    });
}
function collapseAll() {
    document.querySelectorAll('.section-content').forEach(function(el) {
        el.classList.remove('active');
        el.previousElementSibling.classList.remove('active');
    });
}
</script>
"@
}

function New-ServerReport {
    param(
        [Parameter(Mandatory)]
        [string]$Computer,

        [Parameter(Mandatory)]
        [hashtable]$InventoryData,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $scanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $props = if ($InventoryData.Config) { $InventoryData.Config.ServerProperties } else { $null }
    $uptime = if ($InventoryData.Config) { $InventoryData.Config.Uptime } else { $null }

    $serverName = if ($props) { $props.ServerName } else { $Computer }
    $version = if ($props) { "$($props.ProductVersion) $($props.ProductLevel)" } else { "Unknown" }
    $edition = if ($props) { $props.Edition } else { "Unknown" }
    $clustered = if ($props -and $props.IsClustered -eq 1) { "Yes" } else { "No" }
    $hadr = if ($props -and $props.IsHadrEnabled -eq 1) { "Yes" } else { "No" }
    $collation = if ($props) { $props.ServerCollation } else { "Unknown" }

    $dbCount = if ($InventoryData.Databases) { ($InventoryData.Databases | Measure-Object).Count } else { 0 }
    $totalSizeMB = if ($InventoryData.Databases) { ($InventoryData.Databases | Measure-Object -Property TotalSizeMB -Sum).Sum } else { 0 }
    $totalSizeGB = [math]::Round($totalSizeMB / 1024, 2)
    $uptimeDays = if ($uptime) { $uptime.UptimeDays } else { "N/A" }
    $configSettings = if ($InventoryData.Config) { $InventoryData.Config.Settings } else { $null }
    $maxMemory = if ($configSettings) {
        ($configSettings | Where-Object { $_.ConfigName -eq "max server memory (MB)" }).ValueInUse
    } else { "N/A" }

    # Security assessment counts
    $secFindings = @($InventoryData.SecurityAssessment)
    $secCritical = if ($InventoryData.SecurityAssessment) { @($secFindings | Where-Object { $_.Severity -eq 'Critical' }).Count } else { 0 }
    $secWarning = if ($InventoryData.SecurityAssessment) { @($secFindings | Where-Object { $_.Severity -eq 'Warning' }).Count } else { 0 }
    $secInfo = if ($InventoryData.SecurityAssessment) { @($secFindings | Where-Object { $_.Severity -eq 'Info' }).Count } else { 0 }
    $secTotal = $secCritical + $secWarning + $secInfo
    $secColor = if ($secCritical -gt 0) { '#dc3545' } elseif ($secWarning -gt 0) { '#ffc107' } else { '#28a745' }

    # Kill chain assessment counts
    $kcExploitable = 0
    $kcPartial = 0
    if ($InventoryData.KillChainAssessment -and $InventoryData.KillChainAssessment.AttackPaths) {
        $kcPaths = @($InventoryData.KillChainAssessment.AttackPaths)
        $kcExploitable = @($kcPaths | Where-Object { $_.Exploitability -eq 'Exploitable' }).Count
        $kcPartial = @($kcPaths | Where-Object { $_.Exploitability -eq 'Partially Exploitable' }).Count
    }
    $kcColor = if ($kcExploitable -gt 0) { '#dc3545' } elseif ($kcPartial -gt 0) { '#ffc107' } else { '#28a745' }

    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine((Get-HtmlHeader))
    [void]$html.AppendLine("<title>SQL Inventory - $([System.Web.HttpUtility]::HtmlEncode($serverName))</title>")
    [void]$html.AppendLine("</head>")

    # Body and header
    [void]$html.AppendLine(@"
<body>
<div class="container">
    <div class="report-header">
        <h1>SQL Server Inventory Report</h1>
        <div class="subtitle">Generated by DBExplorer</div>
        <div class="header-info">
            <div class="header-info-item">
                <div class="header-info-label">Server</div>
                <div class="header-info-value">$([System.Web.HttpUtility]::HtmlEncode($serverName))</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Version</div>
                <div class="header-info-value">$([System.Web.HttpUtility]::HtmlEncode($version))</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Edition</div>
                <div class="header-info-value">$([System.Web.HttpUtility]::HtmlEncode($edition))</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Host OS</div>
                <div class="header-info-value">$([System.Web.HttpUtility]::HtmlEncode($(if ($InventoryData.OperatingSystem -and $InventoryData.OperatingSystem -ne 'Unknown') { $InventoryData.OperatingSystem } else { 'N/A' })))</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Clustered</div>
                <div class="header-info-value">$clustered</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">AlwaysOn</div>
                <div class="header-info-value">$hadr</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Scan Date</div>
                <div class="header-info-value">$scanDate</div>
            </div>
        </div>
    </div>
    <div class="content">
        <div style="text-align: right; margin-bottom: 10px;">
            <a href="javascript:expandAll()">Expand All</a> | <a href="javascript:collapseAll()">Collapse All</a>
        </div>

        <div class="metrics-row">
            <div class="metric-card">
                <div class="metric-value">$dbCount</div>
                <div class="metric-label">Databases</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$totalSizeGB GB</div>
                <div class="metric-label">Total Size</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$uptimeDays</div>
                <div class="metric-label">Uptime (Days)</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$maxMemory</div>
                <div class="metric-label">Max Memory (MB)</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: $secColor">$secTotal</div>
                <div class="metric-label">Security Findings</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: $kcColor">$kcExploitable</div>
                <div class="metric-label">Exploitable Paths</div>
            </div>
        </div>
"@)

    # Section: Security Assessment
    $secActiveClass = if ($secCritical -gt 0) { " active" } else { "" }
    $secHeaderActive = if ($secCritical -gt 0) { " active" } else { "" }
    $secSummaryText = if ($secTotal -eq 0) { "No issues found" } else { "$secCritical Critical, $secWarning Warning, $secInfo Info" }

    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header$secHeaderActive" onclick="toggleSection('sec-assessment')">
                Security Assessment ($secSummaryText) <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-assessment" class="section-content$secActiveClass">
                $(ConvertTo-HtmlTable -Data $InventoryData.SecurityAssessment -Properties @('Finding','Severity','CurrentValue','Detail','Remediation') -EmptyMessage 'No security findings - all checks passed')
            </div>
        </div>
"@)

    # Section: Kill Chain Assessment
    $kcActiveClass = if ($kcExploitable -gt 0) { " active" } else { "" }
    $kcHeaderActive = if ($kcExploitable -gt 0) { " active" } else { "" }
    $kcSummaryText = if ($kcExploitable -gt 0) { "$kcExploitable Exploitable, $kcPartial Partial" }
                     elseif ($kcPartial -gt 0) { "$kcPartial Partially Exploitable" }
                     else { "All paths mitigated" }

    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header$kcHeaderActive" onclick="toggleSection('sec-killchain')">
                Kill Chain Assessment ($kcSummaryText) <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-killchain" class="section-content$kcActiveClass">
                <div class="sub-section">
                    <h3>Kill Chain Phase Summary</h3>
                    <div class="table-scroll">
                    $(ConvertTo-HtmlTable -Data $(if ($InventoryData.KillChainAssessment) { $InventoryData.KillChainAssessment.KillChainPhases } else { $null }) -Properties @('Phase','ExploitableCount','PartialCount','MitigatedCount','OverallRisk','LowestPrivilege','KeyFindings') -EmptyMessage 'Kill chain assessment not available')
                    </div>
                </div>
                <div class="sub-section">
                    <h3>Attack Path Details</h3>
                    <div class="table-scroll">
                    $(ConvertTo-HtmlTable -Data $(if ($InventoryData.KillChainAssessment) { $InventoryData.KillChainAssessment.AttackPaths } else { $null }) -Properties @('AttackPath','KillChainPhase','Exploitability','AuthRequired','PrivilegeLevel','Prerequisites','CurrentState','Impact','Remediation') -EmptyMessage 'No attack paths evaluated')
                    </div>
                </div>
            </div>
        </div>
"@)

    # Section: Server Configuration
    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header" onclick="toggleSection('sec-config')">
                Server Configuration <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-config" class="section-content active">
                <div class="sub-section">
                    <h3>Configuration Settings</h3>
                    $(ConvertTo-HtmlTable -Data $(if ($InventoryData.Config) { $InventoryData.Config.Settings } else { $null }) -Properties @('ConfigName','ValueInUse','Description') -EmptyMessage 'Could not retrieve configuration settings (insufficient permissions on master database)')
                </div>
                <div class="sub-section">
                    <h3>SQL Services</h3>
                    $(ConvertTo-HtmlTable -Data $(if ($InventoryData.Config) { $InventoryData.Config.Services } else { $null }) -Properties @('servicename','service_account','startup_type_desc','status_desc') -EmptyMessage 'Could not retrieve service information (insufficient permissions or DMV access denied)')
                </div>
            </div>
        </div>
"@)

    # Section: Database Inventory
    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header" onclick="toggleSection('sec-databases')">
                Database Inventory ($dbCount databases) <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-databases" class="section-content">
                $(ConvertTo-HtmlTable -Data $InventoryData.Databases -Properties @('DatabaseName','State','RecoveryModel','CompatibilityLevel','TotalSizeMB','DataSizeMB','LogSizeMB','IsReadOnly','AutoClose','AutoShrink','CreateDate') -EmptyMessage 'Could not retrieve database information')
            </div>
        </div>
"@)

    # Section: Backup Status
    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header" onclick="toggleSection('sec-backups')">
                Backup Status <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-backups" class="section-content">
                $(ConvertTo-HtmlTable -Data $InventoryData.Backups -Properties @('DatabaseName','LastFullBackup','LastDiffBackup','LastLogBackup','DaysSinceFullBackup','LastFullSizeMB') -EmptyMessage 'Could not retrieve backup information')
            </div>
        </div>
"@)

    # Section: Security - Server Logins
    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header" onclick="toggleSection('sec-logins')">
                Security &mdash; Server Logins <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-logins" class="section-content">
                $(ConvertTo-HtmlTable -Data $(if ($InventoryData.Security) { $InventoryData.Security.Logins } else { $null }) -Properties @('LoginName','LoginType','IsDisabled','ServerRoles','CreateDate','ModifyDate') -EmptyMessage 'Could not retrieve login information (insufficient permissions)')
                <div class="sub-section">
                    <h3>Server-Level Permissions</h3>
                    $(ConvertTo-HtmlTable -Data $(if ($InventoryData.Security) { $InventoryData.Security.ServerPermissions } else { $null }) -Properties @('PrincipalName','PrincipalType','Permission','PermissionState','PermissionClass') -EmptyMessage 'No explicit server-level permissions found')
                </div>
            </div>
        </div>
"@)

    # Section: Security - Per-Database
    $dbSecurityHtml = [System.Text.StringBuilder]::new()
    if ($InventoryData.DatabaseSecurity -and $InventoryData.DatabaseSecurity.Count -gt 0) {
        foreach ($dbName in ($InventoryData.DatabaseSecurity.Keys | Sort-Object)) {
            $dbSec = $InventoryData.DatabaseSecurity[$dbName]
            [void]$dbSecurityHtml.AppendLine("<div class='sub-section'>")
            [void]$dbSecurityHtml.AppendLine("<h3>$([System.Web.HttpUtility]::HtmlEncode($dbName))</h3>")
            [void]$dbSecurityHtml.AppendLine("<h4 style='font-size:13px;color:#666;margin:8px 0;'>Users &amp; Role Memberships</h4>")
            $dbUsers = if ($dbSec) { $dbSec.Users } else { $null }
            [void]$dbSecurityHtml.AppendLine((ConvertTo-HtmlTable -Data $dbUsers -Properties @('UserName','UserType','DatabaseRoles','LinkedLogin','CreateDate') -EmptyMessage "No custom users in $dbName (access may be denied)"))
            [void]$dbSecurityHtml.AppendLine("<h4 style='font-size:13px;color:#666;margin:8px 0;'>Explicit Permissions</h4>")
            $dbPerms = if ($dbSec) { $dbSec.Permissions } else { $null }
            [void]$dbSecurityHtml.AppendLine((ConvertTo-HtmlTable -Data $dbPerms -Properties @('PrincipalName','Permission','PermissionState','PermissionClass','ObjectName') -EmptyMessage "No explicit permissions in $dbName"))
            [void]$dbSecurityHtml.AppendLine("</div>")
        }
    }
    else {
        [void]$dbSecurityHtml.AppendLine("<p class='no-data'>No per-database security data collected</p>")
    }

    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header" onclick="toggleSection('sec-dbsecurity')">
                Security &mdash; Database Users &amp; Permissions <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-dbsecurity" class="section-content">
                $($dbSecurityHtml.ToString())
            </div>
        </div>
"@)

    # Section: SQL Agent Jobs
    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header" onclick="toggleSection('sec-jobs')">
                SQL Agent Jobs <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-jobs" class="section-content">
                $(ConvertTo-HtmlTable -Data $InventoryData.AgentJobs -Properties @('JobName','IsEnabled','JobOwner','LastRunDate','LastRunOutcome','Description') -EmptyMessage 'No SQL Agent jobs found or could not retrieve')
            </div>
        </div>
"@)

    # Errors section
    if ($InventoryData.Errors -and $InventoryData.Errors.Count -gt 0) {
        [void]$html.AppendLine("<div class='errors-section'><h3>Warnings &amp; Errors During Collection</h3><ul>")
        foreach ($err in $InventoryData.Errors) {
            [void]$html.AppendLine("<li>$([System.Web.HttpUtility]::HtmlEncode($err))</li>")
        }
        [void]$html.AppendLine("</ul></div>")
    }

    # Footer
    [void]$html.AppendLine(@"
        <div class="footer">
            Report generated by DBExplorer.ps1 on $scanDate | Collation: $([System.Web.HttpUtility]::HtmlEncode($collation))
        </div>
    </div>
</div>
</body>
</html>
"@)

    $fileName = "$($Computer -replace '[\\/:*?"<>|]', '_')_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $filePath = Join-Path $OutputPath $fileName
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($filePath, $html.ToString(), $utf8NoBom)
    Write-Log "  Report saved: $filePath" -Level Success
    return $filePath
}

function New-SummaryReport {
    param(
        [Parameter(Mandatory)]
        [array]$ServerResults,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [int]$TotalScanned,
        [int]$SQLHostsFound,
        [array]$FailedServers,
        [array]$LegacyHosts
    )

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $scanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalDatabases = ($ServerResults | ForEach-Object { if ($_.Databases) { ($_.Databases | Measure-Object).Count } else { 0 } } | Measure-Object -Sum).Sum
    $totalSizeGB = [math]::Round(($ServerResults | ForEach-Object { if ($_.Databases) { ($_.Databases | Measure-Object -Property TotalSizeMB -Sum).Sum } else { 0 } } | Measure-Object -Sum).Sum / 1024, 2)
    $totalSecFindings = ($ServerResults | ForEach-Object { if ($_.SecurityAssessment) { @($_.SecurityAssessment).Count } else { 0 } } | Measure-Object -Sum).Sum
    $totalSecCritical = ($ServerResults | ForEach-Object { if ($_.SecurityAssessment) { @($_.SecurityAssessment | Where-Object { $_.Severity -eq 'Critical' }).Count } else { 0 } } | Measure-Object -Sum).Sum
    $summarySecColor = if ($totalSecCritical -gt 0) { '#dc3545' } elseif ($totalSecFindings -gt 0) { '#ffc107' } else { '#28a745' }

    # Kill chain aggregate metrics
    $totalExploitable = ($ServerResults | ForEach-Object {
        if ($_.KillChainAssessment -and $_.KillChainAssessment.AttackPaths) {
            @($_.KillChainAssessment.AttackPaths | Where-Object { $_.Exploitability -eq 'Exploitable' }).Count
        } else { 0 }
    } | Measure-Object -Sum).Sum
    $summaryKcColor = if ($totalExploitable -gt 0) { '#dc3545' } else { '#28a745' }

    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine((Get-HtmlHeader))
    [void]$html.AppendLine("<title>DBExplorer - Summary Report</title>")
    [void]$html.AppendLine("</head>")

    [void]$html.AppendLine(@"
<body>
<div class="container">
    <div class="report-header">
        <h1>DBExplorer Summary Report</h1>
        <div class="subtitle">Active Directory MSSQL Discovery &amp; Inventory</div>
        <div class="header-info">
            <div class="header-info-item">
                <div class="header-info-label">Computers Scanned</div>
                <div class="header-info-value">$TotalScanned</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">SQL Hosts Found</div>
                <div class="header-info-value">$SQLHostsFound</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Successfully Inventoried</div>
                <div class="header-info-value">$($ServerResults.Count)</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Scan Date</div>
                <div class="header-info-value">$scanDate</div>
            </div>
        </div>
    </div>
    <div class="content">
        <div class="metrics-row">
            <div class="metric-card">
                <div class="metric-value">$($ServerResults.Count)</div>
                <div class="metric-label">SQL Servers</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$totalDatabases</div>
                <div class="metric-label">Total Databases</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$totalSizeGB GB</div>
                <div class="metric-label">Total Data Size</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($FailedServers.Count)</div>
                <div class="metric-label">Failed / Skipped</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: $(if ($LegacyHosts -and $LegacyHosts.Count -gt 0) { '#dc3545' } else { '#28a745' })">$(if ($LegacyHosts) { $LegacyHosts.Count } else { 0 })</div>
                <div class="metric-label">Legacy OS</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: $summarySecColor">$totalSecFindings</div>
                <div class="metric-label">Security Findings</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: $summaryKcColor">$totalExploitable</div>
                <div class="metric-label">Exploitable Kill Chains</div>
            </div>
        </div>
"@)

    # Server inventory table
    $summaryRows = foreach ($srv in $ServerResults) {
        $props = if ($srv.Config) { $srv.Config.ServerProperties } else { $null }
        $dbCount = if ($srv.Databases) { ($srv.Databases | Measure-Object).Count } else { 0 }
        $sizeMB = if ($srv.Databases) { ($srv.Databases | Measure-Object -Property TotalSizeMB -Sum).Sum } else { 0 }
        $sizeGB = [math]::Round($sizeMB / 1024, 2)

        # Backup health: check worst-case days since full
        $worstBackup = if ($srv.Backups) {
            ($srv.Backups | Measure-Object -Property DaysSinceFullBackup -Maximum).Maximum
        } else { -1 }
        $backupHealth = if ($worstBackup -lt 0) { "Unknown" }
                        elseif ($worstBackup -le 1) { "Good" }
                        elseif ($worstBackup -le 7) { "Warning" }
                        else { "Critical" }

        $srvVersion = if ($props) { $props.ProductVersion } else { "N/A" }
        $srvEdition = if ($props) { $props.Edition } else { "N/A" }

        $srvSecCritical = if ($srv.SecurityAssessment) { @($srv.SecurityAssessment | Where-Object { $_.Severity -eq 'Critical' }).Count } else { 0 }
        $srvSecWarning = if ($srv.SecurityAssessment) { @($srv.SecurityAssessment | Where-Object { $_.Severity -eq 'Warning' }).Count } else { 0 }
        $srvSecStatus = if ($srvSecCritical -gt 0) { "$srvSecCritical Critical" }
                        elseif ($srvSecWarning -gt 0) { "$srvSecWarning Warning" }
                        else { "Clean" }

        $srvExploitable = if ($srv.KillChainAssessment -and $srv.KillChainAssessment.AttackPaths) {
            @($srv.KillChainAssessment.AttackPaths | Where-Object { $_.Exploitability -eq 'Exploitable' }).Count
        } else { 0 }

        $srvHostOS = if ($srv.OperatingSystem -and $srv.OperatingSystem -ne "Unknown") { $srv.OperatingSystem } else { "N/A" }

        [PSCustomObject]@{
            Server           = $srv.Computer
            HostOS           = $srvHostOS
            Version          = $srvVersion
            Edition          = $srvEdition
            Databases        = $dbCount
            "Size (GB)"      = $sizeGB
            BackupHealth     = $backupHealth
            SecurityStatus   = $srvSecStatus
            ExploitablePaths = $srvExploitable
            ReportFile       = $srv.ReportFile
        }
    }

    # Build table manually to include links
    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header active" onclick="toggleSection('sec-servers')">
                Inventoried SQL Servers <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-servers" class="section-content active">
                <table>
                    <thead><tr>
                        <th>Server</th><th>Host OS</th><th>Version</th><th>Edition</th>
                        <th>Databases</th><th>Size (GB)</th><th>Backup Health</th><th>Security</th><th>Kill Chains</th><th>Report</th>
                    </tr></thead>
                    <tbody>
"@)

    foreach ($row in $summaryRows) {
        $healthClass = switch ($row.BackupHealth) {
            "Good"     { "status-ok" }
            "Warning"  { "status-warning" }
            "Critical" { "status-critical" }
            default    { "status-warning" }
        }
        $secClass = if ($row.SecurityStatus -match 'Critical') { "status-critical" }
                    elseif ($row.SecurityStatus -match 'Warning') { "status-warning" }
                    else { "status-ok" }
        $kcClass = if ($row.ExploitablePaths -gt 0) { "status-critical" } else { "status-ok" }
        $kcDisplay = if ($row.ExploitablePaths -gt 0) { "$($row.ExploitablePaths) Exploitable" } else { "None" }
        $reportLink = if ($row.ReportFile) {
            $fileName = Split-Path $row.ReportFile -Leaf
            "<a href='$([System.Web.HttpUtility]::HtmlEncode($fileName))'>View Report</a>"
        } else { "N/A" }

        [void]$html.AppendLine(@"
                    <tr>
                        <td><strong>$([System.Web.HttpUtility]::HtmlEncode($row.Server))</strong></td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($row.HostOS))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($row.Version))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($row.Edition))</td>
                        <td>$($row.Databases)</td>
                        <td>$($row.'Size (GB)')</td>
                        <td class='$healthClass'>$($row.BackupHealth)</td>
                        <td class='$secClass'>$($row.SecurityStatus)</td>
                        <td class='$kcClass'>$kcDisplay</td>
                        <td>$reportLink</td>
                    </tr>
"@)
    }

    [void]$html.AppendLine("</tbody></table></div></div>")

    # Failed servers section
    if ($FailedServers -and $FailedServers.Count -gt 0) {
        [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header" onclick="toggleSection('sec-failed')">
                Failed / Skipped Servers ($($FailedServers.Count)) <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-failed" class="section-content">
                <table>
                    <thead><tr><th>Server</th><th>Reason</th></tr></thead>
                    <tbody>
"@)
        foreach ($fail in $FailedServers) {
            [void]$html.AppendLine("<tr><td>$([System.Web.HttpUtility]::HtmlEncode($fail.Computer))</td><td>$([System.Web.HttpUtility]::HtmlEncode($fail.Reason))</td></tr>")
        }
        [void]$html.AppendLine("</tbody></table></div></div>")
    }

    # Legacy OS section
    if ($LegacyHosts -and $LegacyHosts.Count -gt 0) {
        [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header active" style="border-left-color: #dc3545;" onclick="toggleSection('sec-legacy')">
                <span style="color: #dc3545;">&#9888; SQL Server on Legacy OS ($($LegacyHosts.Count))</span> <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-legacy" class="section-content active">
                <p style="color: #856404; background: #fff3cd; padding: 12px; border-radius: 4px; margin-bottom: 15px;">
                    The following hosts have SQL Server ports open but are running operating systems that do not support WinRM remoting.
                    These servers could not be inventoried and represent a significant security risk as legacy operating systems no longer receive security updates.
                </p>
                <table>
                    <thead><tr><th>Server</th><th>Operating System</th><th>OS Version</th><th>Reason</th></tr></thead>
                    <tbody>
"@)
        foreach ($lh in $LegacyHosts) {
            [void]$html.AppendLine("<tr><td><strong>$([System.Web.HttpUtility]::HtmlEncode($lh.Computer))</strong></td><td class='status-critical'>$([System.Web.HttpUtility]::HtmlEncode($lh.OperatingSystem))</td><td>$([System.Web.HttpUtility]::HtmlEncode($lh.OSVersion))</td><td>$([System.Web.HttpUtility]::HtmlEncode($lh.Reason))</td></tr>")
        }
        [void]$html.AppendLine("</tbody></table></div></div>")
    }

    # Footer
    [void]$html.AppendLine(@"
        <div class="footer">
            Summary generated by DBExplorer.ps1 on $scanDate
        </div>
    </div>
</div>
</body>
</html>
"@)

    $filePath = Join-Path $OutputPath "Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($filePath, $html.ToString(), $utf8NoBom)
    Write-Log "Summary report saved: $filePath" -Level Success
    return $filePath
}

#endregion

#region ==================== SQL MAP REPORT ====================

function New-SQLMapReport {
    param(
        [Parameter(Mandatory)]
        [array]$ServerResults,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [array]$LegacyHosts
    )

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $scanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine((Get-HtmlHeader))
    [void]$html.AppendLine("<title>DBExplorer - SQL Server Map</title>")

    # Additional CSS for folder-tree view
    [void]$html.AppendLine(@"
<style>
    .tree { list-style: none; padding-left: 0; }
    .tree ul { list-style: none; padding-left: 0; margin: 0; }
    .tree-node { margin: 2px 0; }
    .tree-toggle {
        cursor: pointer;
        padding: 8px 14px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 14px;
        user-select: none;
        transition: background 0.15s;
    }
    .tree-toggle:hover { background: #e9ecef; }
    .tree-icon {
        font-size: 16px;
        width: 22px;
        text-align: center;
        flex-shrink: 0;
    }
    .tree-label { font-weight: 600; color: #1a237e; }
    .tree-meta {
        font-size: 12px;
        color: #6c757d;
        margin-left: auto;
        white-space: nowrap;
    }
    .tree-children {
        display: none;
        padding-left: 24px;
        border-left: 2px solid #e9ecef;
        margin-left: 18px;
    }
    .tree-children.open { display: block; }
    .tree-leaf {
        padding: 4px 14px 4px 46px;
        font-size: 13px;
        color: #495057;
        display: flex;
        gap: 8px;
        align-items: baseline;
    }
    .tree-leaf .leaf-icon { color: #6c757d; font-size: 11px; width: 16px; text-align: center; flex-shrink: 0; }
    .tree-leaf .leaf-key { color: #6c757d; min-width: 110px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.3px; }
    .tree-leaf .leaf-val { color: #333; }

    /* Server-level node styling */
    .node-server > .tree-toggle { background: #f8f9fa; border: 1px solid #e9ecef; font-size: 15px; }
    .node-server > .tree-toggle:hover { background: #e3e7eb; }
    .node-port > .tree-toggle { font-size: 13px; }
    .node-db > .tree-toggle { font-size: 13px; }
    .node-db > .tree-toggle .tree-label { color: #495057; font-weight: 500; }

    /* Tag badges */
    .tag {
        display: inline-block;
        padding: 1px 8px;
        border-radius: 10px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.3px;
    }
    .tag-online { background: #d4edda; color: #155724; }
    .tag-offline { background: #f8d7da; color: #721c24; }
    .tag-port { background: #d1ecf1; color: #0c5460; }
    .tag-legacy { background: #f8d7da; color: #721c24; }
    .tag-size { background: #e2e3e5; color: #383d41; }

    /* Expand/Collapse bar */
    .tree-controls {
        display: flex;
        gap: 12px;
        margin-bottom: 15px;
        justify-content: flex-end;
    }
    .tree-controls a {
        font-size: 13px;
        cursor: pointer;
        color: #1a237e;
        text-decoration: none;
    }
    .tree-controls a:hover { text-decoration: underline; }
</style>
"@)

    [void]$html.AppendLine("</head>")

    # JavaScript for tree toggle
    [void]$html.AppendLine(@"
<body>
<div class="container">
    <div class="report-header">
        <h1>SQL Server Map</h1>
        <div class="subtitle">Infrastructure Discovery View &mdash; Generated by DBExplorer</div>
        <div class="header-info">
            <div class="header-info-item">
                <div class="header-info-label">Servers</div>
                <div class="header-info-value">$($ServerResults.Count)</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Total Databases</div>
                <div class="header-info-value">$(($ServerResults | ForEach-Object { if ($_.Databases) { @($_.Databases).Count } else { 0 } } | Measure-Object -Sum).Sum)</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Legacy OS Hosts</div>
                <div class="header-info-value" style="color: $(if ($LegacyHosts -and $LegacyHosts.Count -gt 0) { '#dc3545' } else { '#28a745' })">$(if ($LegacyHosts) { $LegacyHosts.Count } else { 0 })</div>
            </div>
            <div class="header-info-item">
                <div class="header-info-label">Scan Date</div>
                <div class="header-info-value">$scanDate</div>
            </div>
        </div>
    </div>
    <div class="content">
        <div class="tree-controls">
            <a onclick="document.querySelectorAll('.tree-children').forEach(function(el){el.classList.add('open')})">Expand All</a>
            <span style="color:#ccc">|</span>
            <a onclick="document.querySelectorAll('.tree-children').forEach(function(el){el.classList.remove('open')})">Collapse All</a>
        </div>

        <ul class="tree">
"@)

    # Script for toggling tree nodes
    $toggleScript = "this.parentElement.querySelector('.tree-children').classList.toggle('open'); var ico=this.querySelector('.tree-icon'); ico.innerHTML = ico.innerHTML.indexOf('9658')>-1 ? '&#9660;' : '&#9658;';"

    # ---- Inventoried servers ----
    $srvIdx = 0
    foreach ($srv in $ServerResults) {
        $srvIdx++
        $srvComputer = [System.Web.HttpUtility]::HtmlEncode($srv.Computer)
        $srvIP       = [System.Web.HttpUtility]::HtmlEncode($(if ($srv.IPv4Address -and $srv.IPv4Address -ne "N/A") { $srv.IPv4Address } else { "IP Unknown" }))
        $srvOS       = [System.Web.HttpUtility]::HtmlEncode($(if ($srv.OperatingSystem -and $srv.OperatingSystem -ne "Unknown") { $srv.OperatingSystem } else { "OS Unknown" }))
        $srvPorts    = if ($srv.OpenPorts) { ($srv.OpenPorts | Sort-Object) -join ", " } else { "N/A" }
        $dbCount     = if ($srv.Databases) { @($srv.Databases).Count } else { 0 }
        $totalSizeMB = if ($srv.Databases) { ($srv.Databases | Measure-Object -Property TotalSizeMB -Sum).Sum } else { 0 }
        $totalSizeDisplay = if ($totalSizeMB -ge 1024) { "$([math]::Round($totalSizeMB / 1024, 2)) GB" } else { "$([math]::Round($totalSizeMB, 1)) MB" }

        # Get SQL version from config
        $srvProps = if ($srv.Config) { $srv.Config.ServerProperties } else { $null }
        $sqlVersion = if ($srvProps) { "$($srvProps.ProductVersion) $($srvProps.Edition)" } else { "Unknown" }
        $sqlVersion = [System.Web.HttpUtility]::HtmlEncode($sqlVersion)

        # Server node (collapsed by default)
        [void]$html.AppendLine(@"
            <li class="tree-node node-server">
                <div class="tree-toggle" onclick="$toggleScript">
                    <span class="tree-icon">&#9658;</span>
                    <span class="tree-label">&#128429; $srvComputer</span>
                    <span class="tree-meta">$dbCount DB(s) &bull; $totalSizeDisplay &bull; Ports: $srvPorts</span>
                </div>
                <div class="tree-children">
                    <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">IP Address</span><span class="leaf-val">$srvIP</span></div>
                    <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Host OS</span><span class="leaf-val">$srvOS</span></div>
                    <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">SQL Version</span><span class="leaf-val">$sqlVersion</span></div>
                    <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Open Ports</span><span class="leaf-val">$(($srv.OpenPorts | Sort-Object | ForEach-Object { "<span class='tag tag-port'>$_</span>" }) -join ' ')</span></div>
                    <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Total Size</span><span class="leaf-val"><span class="tag tag-size">$totalSizeDisplay</span></span></div>
"@)

        # Report link
        if ($srv.ReportFile) {
            $reportFileName = [System.Web.HttpUtility]::HtmlEncode((Split-Path $srv.ReportFile -Leaf))
            [void]$html.AppendLine("                    <div class='tree-leaf'><span class='leaf-icon'>&#9656;</span><span class='leaf-key'>Full Report</span><span class='leaf-val'><a href='$reportFileName'>View Detail Report</a></span></div>")
        }

        # ---- Databases sub-tree ----
        if ($srv.Databases -and @($srv.Databases).Count -gt 0) {
            [void]$html.AppendLine(@"
                    <ul>
                        <li class="tree-node node-port">
                            <div class="tree-toggle" onclick="$toggleScript">
                                <span class="tree-icon">&#9658;</span>
                                <span class="tree-label">&#128451; Databases ($dbCount)</span>
                            </div>
                            <div class="tree-children">
"@)

            foreach ($db in ($srv.Databases | Sort-Object -Property DatabaseName)) {
                $dbName      = [System.Web.HttpUtility]::HtmlEncode($db.DatabaseName)
                $dbState     = $db.State
                $stateTag    = if ($dbState -eq "ONLINE") { "<span class='tag tag-online'>ONLINE</span>" } else { "<span class='tag tag-offline'>$([System.Web.HttpUtility]::HtmlEncode($dbState))</span>" }
                $dbSizeMB    = $db.TotalSizeMB
                $dbSizeDisp  = if ($dbSizeMB -ge 1024) { "$([math]::Round($dbSizeMB / 1024, 2)) GB" } else { "$([math]::Round($dbSizeMB, 1)) MB" }
                $dataSizeMB  = $db.DataSizeMB
                $logSizeMB   = $db.LogSizeMB
                $dataSizeDisp = if ($dataSizeMB -ge 1024) { "$([math]::Round($dataSizeMB / 1024, 2)) GB" } else { "$([math]::Round($dataSizeMB, 1)) MB" }
                $logSizeDisp  = if ($logSizeMB -ge 1024) { "$([math]::Round($logSizeMB / 1024, 2)) GB" } else { "$([math]::Round($logSizeMB, 1)) MB" }
                $recovery    = [System.Web.HttpUtility]::HtmlEncode($db.RecoveryModel)
                $compat      = $db.CompatibilityLevel
                $collation   = [System.Web.HttpUtility]::HtmlEncode($(if ($db.Collation) { $db.Collation } else { "N/A" }))
                $readOnly    = $db.IsReadOnly
                $autoClose   = $db.AutoClose
                $autoShrink  = $db.AutoShrink
                $pageVerify  = [System.Web.HttpUtility]::HtmlEncode($(if ($db.PageVerify) { $db.PageVerify } else { "N/A" }))
                $fileCount   = $db.FileCount
                $createDate  = if ($db.CreateDate -is [datetime]) { $db.CreateDate.ToString("yyyy-MM-dd") } else { $db.CreateDate }

                [void]$html.AppendLine(@"
                                <ul>
                                    <li class="tree-node node-db">
                                        <div class="tree-toggle" onclick="$toggleScript">
                                            <span class="tree-icon">&#9658;</span>
                                            <span class="tree-label">&#128462; $dbName</span>
                                            <span class="tree-meta">$stateTag &nbsp; <span class="tag tag-size">$dbSizeDisp</span> &nbsp; $recovery</span>
                                        </div>
                                        <div class="tree-children">
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">State</span><span class="leaf-val">$stateTag</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Recovery Model</span><span class="leaf-val">$recovery</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Compatibility</span><span class="leaf-val">$compat</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Collation</span><span class="leaf-val">$collation</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Data Size</span><span class="leaf-val">$dataSizeDisp</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Log Size</span><span class="leaf-val">$logSizeDisp</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">File Count</span><span class="leaf-val">$fileCount</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Page Verify</span><span class="leaf-val">$pageVerify</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Read Only</span><span class="leaf-val">$readOnly</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Auto Close</span><span class="leaf-val">$autoClose</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Auto Shrink</span><span class="leaf-val">$autoShrink</span></div>
                                            <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Created</span><span class="leaf-val">$createDate</span></div>
                                        </div>
                                    </li>
                                </ul>
"@)
            }

            [void]$html.AppendLine("                            </div>")
            [void]$html.AppendLine("                        </li>")
            [void]$html.AppendLine("                    </ul>")
        }
        else {
            [void]$html.AppendLine("                    <div class='tree-leaf'><span class='leaf-icon'>&#9656;</span><span class='leaf-key'>Databases</span><span class='leaf-val' style='color:#6c757d;font-style:italic'>No databases retrieved (insufficient permissions)</span></div>")
        }

        [void]$html.AppendLine("                </div>")
        [void]$html.AppendLine("            </li>")
    }

    # ---- Legacy OS hosts (cannot be inventoried) ----
    if ($LegacyHosts -and $LegacyHosts.Count -gt 0) {
        foreach ($lh in $LegacyHosts) {
            $lhComputer = [System.Web.HttpUtility]::HtmlEncode($lh.Computer)
            $lhIP       = [System.Web.HttpUtility]::HtmlEncode($(if ($lh.IPv4Address -and $lh.IPv4Address -ne "N/A") { $lh.IPv4Address } else { "IP Unknown" }))
            $lhOS       = [System.Web.HttpUtility]::HtmlEncode($lh.OperatingSystem)
            $lhPorts    = if ($lh.OpenPorts) { ($lh.OpenPorts | Sort-Object) -join ", " } else { "N/A" }

            [void]$html.AppendLine(@"
            <li class="tree-node node-server">
                <div class="tree-toggle" onclick="$toggleScript" style="border-left: 3px solid #dc3545;">
                    <span class="tree-icon">&#9658;</span>
                    <span class="tree-label">&#128429; $lhComputer</span>
                    <span class="tree-meta"><span class="tag tag-legacy">LEGACY OS</span> &bull; Ports: $lhPorts</span>
                </div>
                <div class="tree-children">
                    <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">IP Address</span><span class="leaf-val">$lhIP</span></div>
                    <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Host OS</span><span class="leaf-val" style="color:#dc3545;font-weight:600">$lhOS</span></div>
                    <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Open Ports</span><span class="leaf-val">$(($lh.OpenPorts | Sort-Object | ForEach-Object { "<span class='tag tag-port'>$_</span>" }) -join ' ')</span></div>
                    <div class="tree-leaf"><span class="leaf-icon">&#9656;</span><span class="leaf-key">Status</span><span class="leaf-val" style="color:#dc3545">Cannot inventory &mdash; $([System.Web.HttpUtility]::HtmlEncode($lh.Reason))</span></div>
                </div>
            </li>
"@)
        }
    }

    # Close tree and page
    [void]$html.AppendLine(@"
        </ul>
        <div class="footer">
            SQL Server Map generated by DBExplorer.ps1 on $scanDate
        </div>
    </div>
</div>
</body>
</html>
"@)

    $filePath = Join-Path $OutputPath "SQL_Map.html"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($filePath, $html.ToString(), $utf8NoBom)
    Write-Log "  SQL Map report saved: $filePath" -Level Success
    return $filePath
}

#endregion

#region ==================== MAIN ORCHESTRATION ====================

function Invoke-DBExplorer {

    # Banner
    Write-Host ""
    Write-Host "  ____  ____  _____            _                     " -ForegroundColor Cyan
    Write-Host " |  _ \| __ )| ____|_  ___ __ | | ___  _ __ ___ _ __ " -ForegroundColor Cyan
    Write-Host " | | | |  _ \|  _| \ \/ / '_ \| |/ _ \| '__/ _ \ '__|" -ForegroundColor Cyan
    Write-Host " | |_| | |_) | |___ >  <| |_) | | (_) | | |  __/ |   " -ForegroundColor Cyan
    Write-Host " |____/|____/|_____/_/\_\ .__/|_|\___/|_|  \___|_|   " -ForegroundColor Cyan
    Write-Host "                         |_|                          " -ForegroundColor Cyan
    Write-Host "  MSSQL Discovery & Inventory Tool" -ForegroundColor DarkCyan
    Write-Host ""

    # Initialize output directories - resolve to absolute path so .NET static methods work
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path $PWD $OutputPath
    }
    $reportDir = $OutputPath
    $logDir = Join-Path $OutputPath "Logs"

    if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

    # Resolve to full path after directory creation so .NET File methods can find it
    $reportDir = (Resolve-Path $reportDir).Path
    $logDir = (Resolve-Path $logDir).Path

    $script:LogFile = Join-Path $logDir "DBExplorer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Write-Log "DBExplorer started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Log "Output directory: $reportDir"

    # ---- Authentication Selection ----
    Write-Host ""
    Write-Host "  Authentication Configuration" -ForegroundColor Cyan
    Write-Host "  =============================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Gray
    Write-Host ""

    $authChoice = $null
    while ($authChoice -notin @("C", "A")) {
        Write-Host "  How do you want to authenticate to remote servers?" -ForegroundColor Yellow
        Write-Host "    [C] Use current running context ($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name))"
        Write-Host "    [A] Provide alternative Windows credentials"
        $authChoice = (Read-Host "  Selection").Trim().ToUpper()
    }

    $script:GlobalCredential = $null
    if ($authChoice -eq "A") {
        $script:GlobalCredential = Get-Credential -Message "Enter Windows credentials for remote SQL Server access (domain\username)"
        if (-not $script:GlobalCredential) {
            Write-Log "No credentials provided. Falling back to current running context." -Level Warning
        }
        else {
            Write-Log "Using alternate credentials: $($script:GlobalCredential.UserName)" -Level Info
        }
    }
    else {
        Write-Log "Using current running context for authentication"
    }
    Write-Host ""

    # ---- Target Scope Selection (AD discovery only) ----
    $targetScope = "Servers"
    if (-not $ComputerName) {
        Write-Host "  Target Scope" -ForegroundColor Cyan
        Write-Host "  ============" -ForegroundColor DarkCyan
        Write-Host ""

        $scopeChoice = $null
        while ($scopeChoice -notin @("S", "W", "B")) {
            Write-Host "  What systems should be scanned for SQL Server?" -ForegroundColor Yellow
            Write-Host "    [S] Servers only (recommended)"
            Write-Host "    [W] Workstations only"
            Write-Host "    [B] Both servers and workstations"
            $scopeChoice = (Read-Host "  Selection").Trim().ToUpper()
        }

        $targetScope = switch ($scopeChoice) {
            "S" { "Servers" }
            "W" { "Workstations" }
            "B" { "Both" }
        }
        Write-Log "Target scope: $targetScope"
        Write-Host ""
    }

    # ---- Phase 1: Computer Discovery ----
    $computers = @()
    if ($ComputerName) {
        $computerList = $ComputerName -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $computers = $computerList | ForEach-Object {
            [PSCustomObject]@{
                Name                   = $_
                DNSHostName            = $_
                OperatingSystem        = "Unknown"
                OperatingSystemVersion = "Unknown"
                IPv4Address            = "N/A"
            }
        }
        Write-Log "Using provided computer list: $($computers.Count) servers"
    }
    else {
        $computers = Get-ADComputerTargets -SearchBase $SearchBase -TargetScope $targetScope
        if (-not $computers -or $computers.Count -eq 0) {
            Write-Log "No computers found. Exiting." -Level Error
            return
        }
    }

    $totalScanned = $computers.Count

    # Build a lookup table to preserve OS & IP info through port scanning
    $osLookup = @{}
    foreach ($comp in $computers) {
        $hostKey = if ($comp.DNSHostName) { $comp.DNSHostName } else { $comp.Name }
        $osLookup[$hostKey.ToLower()] = @{
            OperatingSystem        = if ($comp.OperatingSystem) { $comp.OperatingSystem } else { "Unknown" }
            OperatingSystemVersion = if ($comp.OperatingSystemVersion) { $comp.OperatingSystemVersion } else { "Unknown" }
            IPv4Address            = if ($comp.IPv4Address) { $comp.IPv4Address } else { "N/A" }
        }
    }

    # ---- Phase 2: Port Scanning ----
    $computerNames = $computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } }
    $portResults = Invoke-ParallelPortScan -Computers $computerNames -Ports $Ports -Timeout $PortTimeout -MaxThreads $MaxThreads

    $sqlHostNames = @($portResults | Where-Object { $_.IsOpen } | Select-Object -ExpandProperty Computer -Unique)

    if ($sqlHostNames.Count -eq 0) {
        Write-Log "No SQL Server ports found on any scanned computers." -Level Warning
        Write-Log "Try adjusting the port list or scanning specific servers with -ComputerName"
        return
    }

    # Build per-host port lookup from scan results
    $portLookup = @{}
    foreach ($pr in $portResults) {
        if ($pr.IsOpen) {
            $pKey = $pr.Computer.ToLower()
            if (-not $portLookup.ContainsKey($pKey)) { $portLookup[$pKey] = [System.Collections.ArrayList]::new() }
            [void]$portLookup[$pKey].Add($pr.Port)
        }
    }

    # Enrich SQL hosts with OS info and classify WinRM support
    # WinRM requires Windows Server 2008 R2+ / Windows 7+ (NT 6.1+)
    # Mapping: Server 2003 = 5.2, Server 2008 = 6.0, Server 2008 R2 = 6.1,
    #          Server 2012 = 6.2, Server 2012 R2 = 6.3, Server 2016+ = 10.0
    $sqlHosts = [System.Collections.ArrayList]::new()
    $legacyHosts = [System.Collections.ArrayList]::new()

    foreach ($hostName in $sqlHostNames) {
        $osInfo = $osLookup[$hostName.ToLower()]
        $osName = if ($osInfo) { $osInfo.OperatingSystem } else { "Unknown" }
        $osVer  = if ($osInfo) { $osInfo.OperatingSystemVersion } else { "Unknown" }
        $ipAddr = if ($osInfo) { $osInfo.IPv4Address } else { "N/A" }
        $openPorts = if ($portLookup.ContainsKey($hostName.ToLower())) { @($portLookup[$hostName.ToLower()]) } else { @() }

        # Parse major.minor version for WinRM compatibility check
        $isLegacy = $false
        $legacyReason = ""
        if ($osVer -and $osVer -ne "Unknown") {
            $verParts = $osVer -split '\.'
            $majorVer = 0
            $minorVer = 0
            if ($verParts.Count -ge 1) { [int]::TryParse($verParts[0], [ref]$majorVer) | Out-Null }
            if ($verParts.Count -ge 2) { [int]::TryParse($verParts[1], [ref]$minorVer) | Out-Null }

            # NT version < 6.1 does not support modern WinRM (Server 2003/2008 non-R2)
            if ($majorVer -gt 0 -and ($majorVer -lt 6 -or ($majorVer -eq 6 -and $minorVer -lt 1))) {
                $isLegacy = $true
                $legacyReason = "OS version $osVer ($osName) does not support WinRM remoting"
            }
        }
        elseif ($osName -ne "Unknown") {
            # Fallback: check OS name string for known legacy versions
            if ($osName -match "200[03]|NT 4|XP") {
                $isLegacy = $true
                $legacyReason = "$osName does not support WinRM remoting"
            }
        }

        if ($isLegacy) {
            Write-Log "  WARNING: SQL detected on legacy OS: $hostName ($osName / $osVer)" -Level Warning
            Write-Log "    Skipping inventory - WinRM not supported on this OS" -Level Warning
            [void]$legacyHosts.Add(@{
                Computer        = $hostName
                OperatingSystem = $osName
                OSVersion       = $osVer
                IPv4Address     = $ipAddr
                OpenPorts       = $openPorts
                Reason          = $legacyReason
            })
        }
        else {
            [void]$sqlHosts.Add(@{
                Computer        = $hostName
                OperatingSystem = $osName
                OSVersion       = $osVer
                IPv4Address     = $ipAddr
                OpenPorts       = $openPorts
            })
        }
    }

    # Report legacy hosts
    if ($legacyHosts.Count -gt 0) {
        Write-Host ""
        Write-Host "  ! SQL Server detected on $($legacyHosts.Count) legacy system(s) (WinRM not supported):" -ForegroundColor Red
        foreach ($lh in $legacyHosts) {
            Write-Host "    - $($lh.Computer): $($lh.OperatingSystem)" -ForegroundColor Yellow
        }
        Write-Host "    These hosts will be flagged in the report but cannot be inventoried." -ForegroundColor DarkYellow
        Write-Host ""
    }

    if ($sqlHosts.Count -eq 0) {
        Write-Log "No WinRM-compatible SQL Server hosts found to inventory." -Level Warning
        if ($legacyHosts.Count -gt 0) {
            Write-Log "All $($legacyHosts.Count) SQL host(s) are running unsupported legacy operating systems."
        }
        return
    }

    Write-Log "SQL Server ports detected on $($sqlHosts.Count) compatible hosts. Beginning inventory..." -Level Info

    # ---- Phase 3: Inventory ----
    $serverResults = [System.Collections.ArrayList]::new()
    $failedServers = [System.Collections.ArrayList]::new()
    $serverIndex = 0

    foreach ($sqlHostInfo in $sqlHosts) {
        $sqlHost = $sqlHostInfo.Computer
        $serverIndex++
        Write-Log ""
        Write-Log "=== [$serverIndex/$($sqlHosts.Count)] Processing: $sqlHost ($($sqlHostInfo.OperatingSystem)) ==="
        Write-Progress -Activity "SQL Inventory" -Status "Processing $sqlHost ($serverIndex of $($sqlHosts.Count))" -PercentComplete (($serverIndex / $sqlHosts.Count) * 100)

        $winCred = $script:GlobalCredential
        $inventoryData = @{
            Computer         = $sqlHost
            OperatingSystem  = $sqlHostInfo.OperatingSystem
            OSVersion        = $sqlHostInfo.OSVersion
            IPv4Address      = $sqlHostInfo.IPv4Address
            OpenPorts        = $sqlHostInfo.OpenPorts
            Config           = $null
            Databases        = $null
            Backups          = $null
            Security         = $null
            DatabaseSecurity = @{}
            AgentJobs            = $null
            SecurityAssessment   = $null
            KillChainAssessment  = $null
            Errors               = [System.Collections.ArrayList]::new()
            ReportFile         = $null
        }

        # Test WinRM access (use global credential if set, otherwise current user)
        $testParams = @{ Computer = $sqlHost }
        if ($winCred) { $testParams.Credential = $winCred }
        $winrmOk = Test-WinRMAccess @testParams

        if (-not $winrmOk) {
            $credSource = if ($winCred) { "provided credentials ($($winCred.UserName))" } else { "current credentials" }
            Write-Log "  WinRM access failed with $credSource for $sqlHost" -Level Warning
            $winCred = Get-CredentialFallback -Computer $sqlHost

            if (-not $winCred) {
                Write-Log "  Skipping $sqlHost (no credentials provided)" -Level Warning
                [void]$failedServers.Add(@{ Computer = $sqlHost; Reason = "WinRM access denied / skipped by user" })
                continue
            }

            $winrmOk = Test-WinRMAccess -Computer $sqlHost -Credential $winCred
            if (-not $winrmOk) {
                Write-Log "  WinRM access still failed with provided Windows credentials" -Level Error
                [void]$failedServers.Add(@{ Computer = $sqlHost; Reason = "WinRM access denied with alternate credentials" })
                continue
            }
        }

        Write-Log "  WinRM access confirmed" -Level Success

        # Detect SQL instances
        $instances = Get-SQLInstances -Computer $sqlHost -Credential $winCred
        if (-not $instances -or ($instances | Measure-Object).Count -eq 0) {
            Write-Log "  No running SQL instances detected on $sqlHost. Assuming default instance." -Level Warning
            $instances = @([PSCustomObject]@{ InstanceName = "DEFAULT"; InternalName = "MSSQLSERVER"; Source = "Assumed" })
        }

        Write-Log "  Found $($instances.Count) SQL instance(s): $(($instances | ForEach-Object { $_.InstanceName }) -join ', ')"

        # Inventory each instance (reports per-server, not per-instance, so we merge)
        foreach ($instance in $instances) {
            $instName = $instance.InstanceName
            Write-Log "  Inventorying instance: $instName"

            $queryBaseParams = @{
                Computer      = $sqlHost
                InstanceName  = $instName
                WinCredential = $winCred
            }

            # Server config (queries master database)
            Write-Log "    Collecting server configuration..."
            try {
                $inventoryData.Config = Get-SQLServerConfig @queryBaseParams
            }
            catch {
                $errMsg = "Server config collection failed (may lack permissions on master database): $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Databases (queries master database)
            Write-Log "    Collecting database inventory..."
            try {
                $dbParams = $queryBaseParams.Clone()
                if ($IncludeSystemDatabases) { $dbParams.IncludeSystem = $true }
                $inventoryData.Databases = Get-SQLDatabases @dbParams
            }
            catch {
                $errMsg = "Database inventory failed (may lack permissions on master/sys.databases): $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Backups (queries master + msdb)
            Write-Log "    Collecting backup status..."
            try {
                $inventoryData.Backups = Get-SQLBackupStatus @queryBaseParams
            }
            catch {
                $errMsg = "Backup status collection failed (may lack permissions on msdb): $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Security - Server level (queries master)
            Write-Log "    Collecting server security..."
            try {
                $inventoryData.Security = Get-SQLServerSecurity @queryBaseParams
            }
            catch {
                $errMsg = "Server security collection failed (may lack VIEW SERVER STATE or VIEW ANY DEFINITION): $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Security - Per database
            if ($inventoryData.Databases) {
                $dbList = @($inventoryData.Databases)
                $dbIndex = 0
                foreach ($db in $dbList) {
                    $dbIndex++
                    $dbName = $db.DatabaseName
                    if ($dbName -in @("master", "model", "msdb", "tempdb") -and -not $IncludeSystemDatabases) { continue }
                    if ($db.State -ne "ONLINE") {
                        Write-Log "    Skipping security for $dbName (state: $($db.State))" -Level Warning
                        continue
                    }

                    Write-Log "    Collecting security for database: $dbName ($dbIndex/$($dbList.Count))"
                    try {
                        $inventoryData.DatabaseSecurity[$dbName] = Get-SQLDatabaseSecurity @queryBaseParams -DatabaseName $dbName
                    }
                    catch {
                        $errMsg = "Database security for '$dbName' failed (may lack permissions on this database): $_"
                        Write-Log "      $errMsg" -Level Warning
                        [void]$inventoryData.Errors.Add($errMsg)
                    }
                }
            }

            # Agent Jobs (queries msdb)
            Write-Log "    Collecting SQL Agent jobs..."
            try {
                $inventoryData.AgentJobs = Get-SQLAgentJobs @queryBaseParams
            }
            catch {
                $errMsg = "Agent jobs collection failed (may lack permissions on msdb): $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Security Assessment (queries master + cross-database)
            Write-Log "    Running security assessment..."
            try {
                $inventoryData.SecurityAssessment = Get-SQLSecurityAssessment @queryBaseParams
            }
            catch {
                $errMsg = "Security assessment failed (may lack permissions on master or target databases): $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Kill Chain Assessment
            Write-Log "    Running kill chain assessment..."
            try {
                $kcParams = @{
                    Computer         = $sqlHost
                    InstanceName     = $instName
                    WinCredential    = $winCred
                    SecurityFindings = @()
                    ServerConfig     = @{}
                }
                if ($inventoryData.SecurityAssessment) { $kcParams.SecurityFindings = $inventoryData.SecurityAssessment }
                if ($inventoryData.Config) { $kcParams.ServerConfig = $inventoryData.Config }
                if ($inventoryData.Security) { $kcParams.ServerSecurity = $inventoryData.Security }
                if ($inventoryData.DatabaseSecurity) { $kcParams.DatabaseSecurity = $inventoryData.DatabaseSecurity }
                if ($inventoryData.AgentJobs) { $kcParams.AgentJobs = $inventoryData.AgentJobs }
                $inventoryData.KillChainAssessment = Get-SQLKillChainAssessment @kcParams
            }
            catch {
                $errMsg = "Kill chain assessment failed: $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }
        }

        # Generate per-server report
        Write-Log "  Generating HTML report for $sqlHost..."
        try {
            $reportPath = New-ServerReport -Computer $sqlHost -InventoryData $inventoryData -OutputPath $reportDir
            $inventoryData.ReportFile = $reportPath
        }
        catch {
            Write-Log "  Failed to generate report for $sqlHost : $_" -Level Error
            [void]$inventoryData.Errors.Add("Report generation failed: $_")
        }

        [void]$serverResults.Add($inventoryData)
    }

    Write-Progress -Activity "SQL Inventory" -Completed

    # ---- Phase 4: Summary & Map Reports ----
    Write-Log ""
    Write-Log "=== Generating Summary Report ==="

    try {
        $summaryPath = New-SummaryReport -ServerResults $serverResults -OutputPath $reportDir `
            -TotalScanned $totalScanned -SQLHostsFound ($sqlHosts.Count + $legacyHosts.Count) `
            -FailedServers $failedServers -LegacyHosts $legacyHosts
    }
    catch {
        Write-Log "Failed to generate summary report: $_" -Level Error
    }

    Write-Log "=== Generating SQL Map Report ==="

    try {
        $mapPath = New-SQLMapReport -ServerResults $serverResults -OutputPath $reportDir -LegacyHosts $legacyHosts
    }
    catch {
        Write-Log "Failed to generate SQL Map report: $_" -Level Error
    }

    # ---- Phase 5: Summary ----
    $elapsed = (Get-Date) - $script:StartTime
    Write-Log ""
    Write-Log "============================================"
    Write-Log "  DBExplorer Complete"
    Write-Log "============================================"
    Write-Log "  Computers scanned:       $totalScanned"
    Write-Log "  SQL hosts found:         $($sqlHosts.Count + $legacyHosts.Count)"
    Write-Log "  Successfully inventoried: $($serverResults.Count)"
    Write-Log "  Failed/skipped:          $($failedServers.Count)"
    if ($legacyHosts.Count -gt 0) {
        Write-Log "  Legacy OS (skipped):     $($legacyHosts.Count)" -Level Warning
    }
    Write-Log "  Total elapsed time:      $($elapsed.ToString('hh\:mm\:ss'))"
    Write-Log "  Reports saved to:        $reportDir"
    Write-Log "============================================"

    # Open summary report
    if ($summaryPath -and (Test-Path $summaryPath)) {
        Write-Log "Opening summary report in browser..."
        try {
            Start-Process $summaryPath
        }
        catch {
            Write-Log "Could not open browser. Report is at: $summaryPath" -Level Warning
        }
    }
}

# Run
Invoke-DBExplorer

#endregion
