# SQLExplorer

**Active Directory MSSQL Discovery, Inventory & Security Assessment Tool**

A single-file PowerShell script that discovers SQL Server instances across your Active Directory domain, inventories their configuration via WinRM, performs a security vulnerability assessment, and generates self-contained HTML reports.

---

## What It Does

SQLExplorer automates the entire SQL Server discovery and auditing workflow:

1. **Discovers computers** from Active Directory (or accepts a manual server list)
2. **Parallel port scans** for common MSSQL service ports (1433, 1434, 2383, 4022)
3. **Connects via WinRM** and detects all SQL Server instances (default + named)
4. **Inventories** server configuration, databases, backups, security model, and agent jobs
5. **Runs a security vulnerability assessment** checking for common misconfigurations
6. **Generates per-server HTML reports** with an interactive summary index

All from a single `.ps1` file. No modules to install. No agents to deploy.

---

## Features

### Discovery & Scanning
- Active Directory computer enumeration with optional OU scoping
- Multi-threaded TCP port scanning using runspace pools
- Automatic SQL Server instance detection via registry and service enumeration
- WinRM connectivity testing with credential fallback

### SQL Server Inventory
- **Server Configuration** - Version, edition, collation, memory, max workers, service accounts, uptime
- **Databases** - Name, status, size, recovery model, compatibility level, owner
- **Backup Status** - Last full, differential, and log backup per database
- **Server Security** - All logins with server role mappings
- **Database Security** - Per-database users with role memberships
- **SQL Agent Jobs** - Job names, status, last run outcome, schedule

### Security Vulnerability Assessment
Checks for 15+ common SQL Server security issues across 10 categories:

| Check | Severity | What It Looks For |
|-------|----------|-------------------|
| xp_cmdshell | Critical | Command shell enabled on the server |
| CLR Integration | Warning | CLR execution enabled |
| OLE Automation | Warning | OLE Automation procedures enabled |
| Ad Hoc Distributed Queries | Warning | Linked server ad hoc queries enabled |
| Cross-Database Ownership Chaining | Warning | Cross-database chaining enabled |
| Remote Access / DAC / Startup Procs | Info | Other dangerous configuration flags |
| Mixed Authentication Mode | Warning | SQL + Windows auth (weaker than Windows-only) |
| SA Account | Critical | SA account enabled, missing password policy/expiration |
| Excessive Sysadmins | Warning | More than 3 sysadmin role members |
| TRUSTWORTHY Databases | Critical | User databases with TRUSTWORTHY flag enabled |
| Guest Access | Warning | Guest account has CONNECT permission in user databases |
| BUILTIN\Administrators | Critical | Legacy admin group with SQL login |
| Public Role Permissions | Warning | Extra server-level permissions granted to public |
| Orphaned Users | Warning | Database users with no matching server login |
| Password Policy Gaps | Warning | SQL logins without password policy enforcement |

### HTML Reports
- **Per-server reports** with collapsible sections, color-coded status indicators, and security severity badges
- **Summary report** with dashboard metrics, server overview table, and security status column
- Self-contained HTML (embedded CSS/JS) - no external dependencies
- XSS-safe: all dynamic content is HTML-encoded
- Print-friendly styling

---

## Requirements

- **Windows** domain-joined PC (the machine running the script)
- **PowerShell 5.1** or later
- **WinRM** enabled on target SQL Servers (standard in domain environments)
- **Active Directory module** (optional - only needed for AD discovery; use `-ComputerName` to bypass)
- Appropriate **Windows permissions** to query target servers via WinRM

> **Note:** No SQL client tools or PowerShell SQL modules are required on the scanning machine. The script executes SQL queries remotely via WinRM and falls back to .NET `SqlClient` if `Invoke-Sqlcmd` is unavailable on the target.

---

## Quick Start

### Scan your entire AD domain
```powershell
.\DBExplorer.ps1
```

### Scan specific servers
```powershell
.\DBExplorer.ps1 -ComputerName "SQL01,SQL02,SQL03"
```

### Scan a specific OU with system databases included
```powershell
.\DBExplorer.ps1 -SearchBase "OU=Servers,DC=corp,DC=local" -IncludeSystemDatabases
```

### Custom output directory and scan settings
```powershell
.\DBExplorer.ps1 -ComputerName "SQL01" -OutputPath "C:\Reports" -MaxThreads 50 -PortTimeout 2000
```

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-SearchBase` | String | *(entire domain)* | AD OU distinguished name to scope the computer search |
| `-ComputerName` | String | - | Comma-separated server list (bypasses AD discovery) |
| `-Ports` | Int[] | `1433,1434,2383,4022` | TCP ports to scan for MSSQL services |
| `-PortTimeout` | Int | `1000` | Port scan timeout in milliseconds |
| `-MaxThreads` | Int | `20` | Maximum parallel threads for port scanning |
| `-OutputPath` | String | `.\DBExplorer_Reports` | Directory for HTML reports and logs |
| `-IncludeSystemDatabases` | Switch | `$false` | Include master, model, msdb, tempdb in inventory |

---

## Output Structure

```
DBExplorer_Reports/
  SQL01_20240115_143022.html      # Per-server report
  SQL02_20240115_143045.html      # Per-server report
  SQL03_20240115_143108.html      # Per-server report
  Summary_20240115_143110.html    # Summary index (opens automatically)
  Logs/
    DBExplorer_20240115_143022.log  # Detailed execution log
```

---

## How It Works

### Architecture

```
                    +------------------+
                    |   AD Discovery   |  Get-ADComputer or manual list
                    +--------+---------+
                             |
                    +--------v---------+
                    | Parallel Port    |  Runspace pool + async TcpClient
                    | Scanner          |  Ports: 1433, 1434, 2383, 4022
                    +--------+---------+
                             |
                    +--------v---------+
                    | WinRM Test +     |  Test-WinRMAccess
                    | Credential       |  Get-CredentialFallback
                    | Fallback         |  (Windows auth only)
                    +--------+---------+
                             |
                    +--------v---------+
                    | Instance         |  Registry enumeration
                    | Detection        |  Service enumeration
                    +--------+---------+
                             |
              +--------------+---------------+
              |              |               |
     +--------v---+  +------v-----+  +------v------+
     | SQL Config |  | Security   |  | Security    |
     | Databases  |  | Model      |  | Vuln        |
     | Backups    |  | (Logins,   |  | Assessment  |
     | Agent Jobs |  |  Users)    |  | (10 checks) |
     +--------+---+  +------+-----+  +------+------+
              |              |               |
              +--------------+---------------+
                             |
                    +--------v---------+
                    | HTML Report      |  Per-server + Summary
                    | Generation       |  Self-contained HTML
                    +------------------+
```

### Authentication Flow

1. Attempts connection with **current user credentials** (Kerberos)
2. If access is denied, prompts for **alternative Windows credentials**
3. Credentials are cached in session memory for reuse across instances on the same server
4. All SQL queries use **Integrated Security (SSPI)** - no SQL authentication

### SQL Query Execution Chain

1. Try `Invoke-Sqlcmd` via **SqlServer** module (if available on target)
2. Fall back to `Invoke-Sqlcmd` via **SQLPS** module (if available on target)
3. Fall back to **.NET System.Data.SqlClient** (always available)

### SQL Version Compatibility

- **SQL Server 2017+**: Uses `STRING_AGG()` for role aggregation
- **SQL Server 2016 and earlier**: Automatically falls back to `STUFF(... FOR XML PATH('')))`

---

## Safety

SQLExplorer is a **read-only reconnaissance tool**. It has been audited across 16 safety categories:

- **Zero** data modification statements (no INSERT/UPDATE/DELETE/DROP/ALTER)
- **Zero** remote write operations (no files created, no configs changed on targets)
- **Zero** destructive commands (no Remove-Item, no service stops, no reboots)
- **Zero** dangerous execution patterns (no Invoke-Expression, no cmd.exe, no encoded commands)
- **Zero** external network calls (no HTTP requests, no data exfiltration, no email)
- **Zero** privilege escalation attempts (no RunAs, no permission changes)

The only files created are **local HTML reports and logs** on the machine running the script.

> **Important:** The generated reports contain sensitive information (login names, service accounts, security vulnerabilities, infrastructure topology). Treat them as confidential and restrict access accordingly.

See `DBExplorer_SafetyAssessment.html` for the full safety audit report.

---

## Report Sections

### Per-Server Report
Each server report includes these collapsible sections:

1. **Security Vulnerability Assessment** - Color-coded findings with severity, detail, and remediation guidance (auto-expands if critical issues found)
2. **Server Configuration** - SQL version, edition, memory, collation, service accounts
3. **Databases** - All databases with size, status, recovery model
4. **Backup Status** - Last backup timestamps per database
5. **Server Security** - All logins and their server role memberships
6. **Database Security** - Per-database user/role details
7. **SQL Agent Jobs** - Job status, last run outcome, schedules

### Summary Report
- Dashboard metric cards (servers scanned, instances found, databases, critical findings)
- Server overview table with quick-glance security status
- Failed servers section (WinRM failures, access denied, etc.)

---

## Included Files

| File | Description |
|------|-------------|
| `DBExplorer.ps1` | The complete tool (single file, ~2,200 lines) |
| `DBExplorer_Documentation.html` | Technical documentation with architecture details, function reference, and SQL query catalog |
| `DBExplorer_SafetyAssessment.html` | Full safety audit report covering 16 risk categories |

---

## FAQ

**Q: Do I need SQL Server tools installed on my machine?**
A: No. The script runs SQL queries remotely via WinRM. If the target server has the SqlServer or SQLPS module, it uses those; otherwise it falls back to .NET SqlClient which is always available.

**Q: Does this modify anything on the target servers?**
A: No. Every SQL query is a SELECT statement. No configurations are changed, no files are created, and no data is modified on remote systems.

**Q: What permissions do I need?**
A: You need WinRM access to the target servers and sufficient SQL Server permissions to query system catalog views (typically `sysadmin` or `VIEW SERVER STATE` + `VIEW ANY DEFINITION`).

**Q: Does it work with SQL Server Express?**
A: Yes. It works with all SQL Server editions including Express, Standard, Enterprise, and Developer.

**Q: Does it support named instances?**
A: Yes. It detects both default (MSSQLSERVER) and named instances via registry and service enumeration.

**Q: What if WinRM isn't enabled on a target?**
A: The server will be logged as a WinRM failure and skipped. Other servers will continue to be scanned.

---

## License

See [LICENSE](LICENSE) for details.
