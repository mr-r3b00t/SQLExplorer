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
        [string]$SearchBase
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
        Properties = @("DNSHostName", "OperatingSystem", "IPv4Address")
    }

    if ($SearchBase) {
        $adParams.SearchBase = $SearchBase
        Write-Log "Scoping AD search to: $SearchBase"
    }

    try {
        $computers = @(Get-ADComputer @adParams | Where-Object {
            $_.OperatingSystem -like "*Windows Server*" -or $_.OperatingSystem -like "*Windows*"
        } | Select-Object Name, DNSHostName, OperatingSystem, IPv4Address)

        Write-Log "Found $($computers.Count) enabled Windows computers in AD" -Level Success
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

    Write-Log "Current credentials failed for $Computer. Prompting for alternate credentials..." -Level Warning

    $choice = $null
    while ($choice -notin @("W", "K")) {
        Write-Host ""
        Write-Host "Authentication failed for $Computer. Choose an option:" -ForegroundColor Yellow
        Write-Host "  [W] Enter Windows credentials (domain\user)"
        Write-Host "  [K] Skip this server"
        $choice = (Read-Host "Selection").ToUpper()
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

#endregion

#region ==================== HTML REPORT GENERATION ====================

function ConvertTo-HtmlTable {
    param(
        [Parameter(Mandatory)]
        $Data,

        [string[]]$Properties,

        [string]$EmptyMessage = "No data available"
    )

    if (-not $Data -or ($Data | Measure-Object).Count -eq 0) {
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
    $props = $InventoryData.Config.ServerProperties
    $uptime = $InventoryData.Config.Uptime

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
    $maxMemory = if ($InventoryData.Config.Settings) {
        ($InventoryData.Config.Settings | Where-Object { $_.ConfigName -eq "max server memory (MB)" }).ValueInUse
    } else { "N/A" }

    # Security assessment counts
    $secFindings = @($InventoryData.SecurityAssessment)
    $secCritical = if ($InventoryData.SecurityAssessment) { @($secFindings | Where-Object { $_.Severity -eq 'Critical' }).Count } else { 0 }
    $secWarning = if ($InventoryData.SecurityAssessment) { @($secFindings | Where-Object { $_.Severity -eq 'Warning' }).Count } else { 0 }
    $secInfo = if ($InventoryData.SecurityAssessment) { @($secFindings | Where-Object { $_.Severity -eq 'Info' }).Count } else { 0 }
    $secTotal = $secCritical + $secWarning + $secInfo
    $secColor = if ($secCritical -gt 0) { '#dc3545' } elseif ($secWarning -gt 0) { '#ffc107' } else { '#28a745' }

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

    # Section: Server Configuration
    [void]$html.AppendLine(@"
        <div class="section">
            <div class="section-header" onclick="toggleSection('sec-config')">
                Server Configuration <span class="toggle">&#9654;</span>
            </div>
            <div id="sec-config" class="section-content active">
                <div class="sub-section">
                    <h3>Configuration Settings</h3>
                    $(ConvertTo-HtmlTable -Data $InventoryData.Config.Settings -Properties @('ConfigName','ValueInUse','Description') -EmptyMessage 'Could not retrieve configuration settings')
                </div>
                <div class="sub-section">
                    <h3>SQL Services</h3>
                    $(ConvertTo-HtmlTable -Data $InventoryData.Config.Services -Properties @('servicename','service_account','startup_type_desc','status_desc') -EmptyMessage 'Could not retrieve service information')
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
                $(ConvertTo-HtmlTable -Data $InventoryData.Security.Logins -Properties @('LoginName','LoginType','IsDisabled','ServerRoles','CreateDate','ModifyDate') -EmptyMessage 'Could not retrieve login information')
                <div class="sub-section">
                    <h3>Server-Level Permissions</h3>
                    $(ConvertTo-HtmlTable -Data $InventoryData.Security.ServerPermissions -Properties @('PrincipalName','PrincipalType','Permission','PermissionState','PermissionClass') -EmptyMessage 'No explicit server-level permissions found')
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
            [void]$dbSecurityHtml.AppendLine((ConvertTo-HtmlTable -Data $dbSec.Users -Properties @('UserName','UserType','DatabaseRoles','LinkedLogin','CreateDate') -EmptyMessage "No custom users in $dbName"))
            [void]$dbSecurityHtml.AppendLine("<h4 style='font-size:13px;color:#666;margin:8px 0;'>Explicit Permissions</h4>")
            [void]$dbSecurityHtml.AppendLine((ConvertTo-HtmlTable -Data $dbSec.Permissions -Properties @('PrincipalName','Permission','PermissionState','PermissionClass','ObjectName') -EmptyMessage "No explicit permissions in $dbName"))
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
        [array]$FailedServers
    )

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $scanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalDatabases = ($ServerResults | ForEach-Object { if ($_.Databases) { ($_.Databases | Measure-Object).Count } else { 0 } } | Measure-Object -Sum).Sum
    $totalSizeGB = [math]::Round(($ServerResults | ForEach-Object { if ($_.Databases) { ($_.Databases | Measure-Object -Property TotalSizeMB -Sum).Sum } else { 0 } } | Measure-Object -Sum).Sum / 1024, 2)
    $totalSecFindings = ($ServerResults | ForEach-Object { if ($_.SecurityAssessment) { @($_.SecurityAssessment).Count } else { 0 } } | Measure-Object -Sum).Sum
    $totalSecCritical = ($ServerResults | ForEach-Object { if ($_.SecurityAssessment) { @($_.SecurityAssessment | Where-Object { $_.Severity -eq 'Critical' }).Count } else { 0 } } | Measure-Object -Sum).Sum
    $summarySecColor = if ($totalSecCritical -gt 0) { '#dc3545' } elseif ($totalSecFindings -gt 0) { '#ffc107' } else { '#28a745' }

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
                <div class="metric-value" style="color: $summarySecColor">$totalSecFindings</div>
                <div class="metric-label">Security Findings</div>
            </div>
        </div>
"@)

    # Server inventory table
    $summaryRows = foreach ($srv in $ServerResults) {
        $props = $srv.Config.ServerProperties
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

        [PSCustomObject]@{
            Server         = $srv.Computer
            Version        = $srvVersion
            Edition        = $srvEdition
            Databases      = $dbCount
            "Size (GB)"    = $sizeGB
            BackupHealth   = $backupHealth
            SecurityStatus = $srvSecStatus
            ReportFile     = $srv.ReportFile
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
                        <th>Server</th><th>Version</th><th>Edition</th>
                        <th>Databases</th><th>Size (GB)</th><th>Backup Health</th><th>Security</th><th>Report</th>
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
        $reportLink = if ($row.ReportFile) {
            $fileName = Split-Path $row.ReportFile -Leaf
            "<a href='$([System.Web.HttpUtility]::HtmlEncode($fileName))'>View Report</a>"
        } else { "N/A" }

        [void]$html.AppendLine(@"
                    <tr>
                        <td><strong>$([System.Web.HttpUtility]::HtmlEncode($row.Server))</strong></td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($row.Version))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($row.Edition))</td>
                        <td>$($row.Databases)</td>
                        <td>$($row.'Size (GB)')</td>
                        <td class='$healthClass'>$($row.BackupHealth)</td>
                        <td class='$secClass'>$($row.SecurityStatus)</td>
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

    # ---- Phase 1: Computer Discovery ----
    $computers = @()
    if ($ComputerName) {
        $computerList = $ComputerName -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $computers = $computerList | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_
                DNSHostName = $_
            }
        }
        Write-Log "Using provided computer list: $($computers.Count) servers"
    }
    else {
        $computers = Get-ADComputerTargets -SearchBase $SearchBase
        if (-not $computers -or $computers.Count -eq 0) {
            Write-Log "No computers found. Exiting." -Level Error
            return
        }
    }

    $totalScanned = $computers.Count

    # ---- Phase 2: Port Scanning ----
    $computerNames = $computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } }
    $portResults = Invoke-ParallelPortScan -Computers $computerNames -Ports $Ports -Timeout $PortTimeout -MaxThreads $MaxThreads

    $sqlHosts = @($portResults | Where-Object { $_.IsOpen } | Select-Object -ExpandProperty Computer -Unique)

    if ($sqlHosts.Count -eq 0) {
        Write-Log "No SQL Server ports found on any scanned computers." -Level Warning
        Write-Log "Try adjusting the port list or scanning specific servers with -ComputerName"
        return
    }

    Write-Log "SQL Server ports detected on $($sqlHosts.Count) hosts. Beginning inventory..." -Level Info

    # ---- Phase 3: Inventory ----
    $serverResults = [System.Collections.ArrayList]::new()
    $failedServers = [System.Collections.ArrayList]::new()
    $serverIndex = 0

    foreach ($sqlHost in $sqlHosts) {
        $serverIndex++
        Write-Log ""
        Write-Log "=== [$serverIndex/$($sqlHosts.Count)] Processing: $sqlHost ==="
        Write-Progress -Activity "SQL Inventory" -Status "Processing $sqlHost ($serverIndex of $($sqlHosts.Count))" -PercentComplete (($serverIndex / $sqlHosts.Count) * 100)

        $winCred = $null
        $inventoryData = @{
            Computer         = $sqlHost
            Config           = $null
            Databases        = $null
            Backups          = $null
            Security         = $null
            DatabaseSecurity = @{}
            AgentJobs          = $null
            SecurityAssessment = $null
            Errors             = [System.Collections.ArrayList]::new()
            ReportFile         = $null
        }

        # Test WinRM access
        $winrmOk = Test-WinRMAccess -Computer $sqlHost
        if (-not $winrmOk) {
            Write-Log "  WinRM access failed with current credentials for $sqlHost" -Level Warning
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

            # Server config
            Write-Log "    Collecting server configuration..."
            try {
                $inventoryData.Config = Get-SQLServerConfig @queryBaseParams
            }
            catch {
                $errMsg = "Server config collection failed: $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Databases
            Write-Log "    Collecting database inventory..."
            try {
                $dbParams = $queryBaseParams.Clone()
                if ($IncludeSystemDatabases) { $dbParams.IncludeSystem = $true }
                $inventoryData.Databases = Get-SQLDatabases @dbParams
            }
            catch {
                $errMsg = "Database inventory failed: $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Backups
            Write-Log "    Collecting backup status..."
            try {
                $inventoryData.Backups = Get-SQLBackupStatus @queryBaseParams
            }
            catch {
                $errMsg = "Backup status collection failed: $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Security - Server level
            Write-Log "    Collecting server security..."
            try {
                $inventoryData.Security = Get-SQLServerSecurity @queryBaseParams
            }
            catch {
                $errMsg = "Server security collection failed: $_"
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
                        $errMsg = "Database security for '$dbName' failed: $_"
                        Write-Log "      $errMsg" -Level Warning
                        [void]$inventoryData.Errors.Add($errMsg)
                    }
                }
            }

            # Agent Jobs
            Write-Log "    Collecting SQL Agent jobs..."
            try {
                $inventoryData.AgentJobs = Get-SQLAgentJobs @queryBaseParams
            }
            catch {
                $errMsg = "Agent jobs collection failed: $_"
                Write-Log "    $errMsg" -Level Warning
                [void]$inventoryData.Errors.Add($errMsg)
            }

            # Security Assessment
            Write-Log "    Running security assessment..."
            try {
                $inventoryData.SecurityAssessment = Get-SQLSecurityAssessment @queryBaseParams
            }
            catch {
                $errMsg = "Security assessment failed: $_"
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

    # ---- Phase 4: Summary Report ----
    Write-Log ""
    Write-Log "=== Generating Summary Report ==="

    try {
        $summaryPath = New-SummaryReport -ServerResults $serverResults -OutputPath $reportDir `
            -TotalScanned $totalScanned -SQLHostsFound $sqlHosts.Count -FailedServers $failedServers
    }
    catch {
        Write-Log "Failed to generate summary report: $_" -Level Error
    }

    # ---- Phase 5: Summary ----
    $elapsed = (Get-Date) - $script:StartTime
    Write-Log ""
    Write-Log "============================================"
    Write-Log "  DBExplorer Complete"
    Write-Log "============================================"
    Write-Log "  Computers scanned:     $totalScanned"
    Write-Log "  SQL hosts found:       $($sqlHosts.Count)"
    Write-Log "  Successfully inventoried: $($serverResults.Count)"
    Write-Log "  Failed/skipped:        $($failedServers.Count)"
    Write-Log "  Total elapsed time:    $($elapsed.ToString('hh\:mm\:ss'))"
    Write-Log "  Reports saved to:      $reportDir"
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
