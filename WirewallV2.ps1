<#
    default deny out
    run as admin
    ezpz
#>

$RuleOptions = @(
    # --- Active Directory Core ---
    @{ Name="CCDC-KRB-88-TCP";        Protocol="TCP"; LocalPort=88;              Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-KRB-88-UDP";        Protocol="UDP"; LocalPort=88;              Direction="Inbound"; Profile="Domain,Public,Private" },

    @{ Name="CCDC-LDAP-389-TCP";      Protocol="TCP"; LocalPort=389;             Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-LDAP-389-UDP";      Protocol="UDP"; LocalPort=389;             Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-LDAPS-636-TCP";     Protocol="TCP"; LocalPort=636;             Direction="Inbound"; Profile="Domain,Public,Private" },
    
    @{ Name="CCDC-SMB-445-TCP";       Protocol="TCP"; LocalPort=445;             Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-DNS-53-UDP";        Protocol="UDP"; LocalPort=53;              Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-SSH-22-TCP";        Protocol="TCP"; LocalPort=22;              Direction="Inbound"; Profile="Domain,Public,Private" },


    @{ Name="CCDC-ICMPv4";            Protocol="ICMPv4"; LocalPort="Any";        Direction="Inbound"; Profile="Domain,Public,Private" },
    # --- Database Services ---
    @{ Name="CCDC-MSSQL-1433-TCP";    Protocol="TCP"; LocalPort=1433;            Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-SQLBR-1434-UDP";    Protocol="UDP"; LocalPort=1434;            Direction="Inbound"; Profile="Domain,Public,Private" },

    # --- Web Services ---
    @{ Name="CCDC-HTTP-80-TCP";       Protocol="TCP"; LocalPort=80;              Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-HTTPS-443-TCP";     Protocol="TCP"; LocalPort=443;             Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-WEB-8080-TCP";      Protocol="TCP"; LocalPort=8080;            Direction="Inbound"; Profile="Domain,Public,Private" },

    # --- Remote Management ---
    @{ Name="CCDC-RDP-3389-TCP";      Protocol="TCP"; LocalPort=3389;            Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-RPC-135-TCP";       Protocol="TCP"; LocalPort=135;             Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-WinRM-5985-TCP";    Protocol="TCP"; LocalPort=5985;            Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-WinRMs-5986-TCP";   Protocol="TCP"; LocalPort=5986;            Direction="Inbound"; Profile="Domain,Public,Private" },
    # --- DHCP ---
    @{ Name="CCDC-DHCP-67-UDP";       Protocol="UDP"; LocalPort=67;              Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-DHCP-68-UDP";       Protocol="UDP"; LocalPort=68;              Direction="Inbound"; Profile="Domain,Public,Private" },

    # --- FTP ---
    @{ Name="CCDC-FTP-21-TCP";        Protocol="TCP"; LocalPort=21;              Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-FTPD-20-TCP";       Protocol="TCP"; LocalPort=20;              Direction="Inbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-FTP-21-TCP";        Protocol="TCP"; LocalPort=21;              Direction="Outbound"; Profile="Domain,Public,Private" },
    @{ Name="CCDC-FTPD-20-TCP";       Protocol="TCP"; LocalPort=20;              Direction="Outbound"; Profile="Domain,Public,Private" }


   
)

$LogPathRoot = "$env:ProgramData\FirewallDefender"


if (-not (Test-Path $LogPathRoot)) { 

New-Item -Path $LogPathRoot -ItemType Directory -Force | Out-Null 

}


$Timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$LogFile = Join-Path $LogPathRoot "FirewallDefender_$Timestamp.log"

# Ports and presets. Edit if your environment needs different ranges.
$Presets = @{
    "DomainController" = @{
        Description = "AD DS typical ports"
        Rules = @(
            @{ Name="CCDC - Allow-Kerberos-In";        Protocol="TCP"; LocalPort=88;  Direction="Inbound";  Profile="Domain,Public,Private" },
            @{ Name="CCDC - Allow-Kerberos-In-UDP";    Protocol="UDP"; LocalPort=88;  Direction="Inbound";  Profile="Domain,Public,Private" },
            @{ Name="CCDC - Allow-LDAP-In";            Protocol="TCP"; LocalPort=389; Direction="Inbound";  Profile="Domain,Public,Private" },
            @{ Name="CCDC - Allow-LDAP-In-UDP";        Protocol="UDP"; LocalPort=389; Direction="Inbound";  Profile="Domain,Public,Private" },
            @{ Name="CCDC - Allow-LDAPS-In";           Protocol="TCP"; LocalPort=636; Direction="Inbound";  Profile="Domain,Public,Private" },
            @{ Name="CCDC - Allow-RPC-EndpointMapper"; Protocol="TCP"; LocalPort=135; Direction="Inbound";  Profile="Domain,Public,Private" },
            @{ Name="CCDC - Allow-NTLM-Netlogon";      Protocol="TCP"; LocalPort=445; Direction="Inbound";  Profile="Domain,Public,Private" },
            @{ Name="CCDC - Allow-DNS-In";             Protocol="UDP"; LocalPort=53;  Direction="Inbound";  Profile="Domain,Public,Private" }
            # Add more if we fillin it chat
        )
    }
    "DNS" = @{
        Description = "DNS server (UDP 53 + TCP 53 for zone transfers)"
        Rules = @(
            @{ Name="CCDC - Allow-DNS-UDP"; Protocol="UDP"; LocalPort=53; Direction="Inbound"; Profile="Any" },
            @{ Name="CCDC - Allow-DNS-TCP"; Protocol="TCP"; LocalPort=53; Direction="Inbound"; Profile="Any" }
        )
    }
    "WebServer" = @{
        Description = "HTTP/HTTPS inbound"
        Rules = @(
            @{ Name="CCDC - Allow-HTTP-In";  Protocol="TCP"; LocalPort=80;  Direction="Inbound"; Profile="Any" },
            @{ Name="CCDC - Allow-HTTPS-In"; Protocol="TCP"; LocalPort=443; Direction="Inbound"; Profile="Any" }
        )
    }
    "FTP" = @{
        Description = "FTP Active (20) / Control (21) and suggested passive range"
        Rules = @(
            @{ Name="CCDC - Allow-FTP-21";  Protocol="TCP"; LocalPort=21; Direction="Inbound"; Profile="Any" },
            @{ Name="CCDC - Allow-FTP-20";  Protocol="TCP"; LocalPort=20; Direction="Inbound"; Profile="Any" }
            #idk if we need bigger range 50000 - 50100 for passive ¯\_(ツ)_/¯
        )
    }
    "ClientWorkstation" = @{
        Description = "Typical client: allow DNS outbound, Windows Update outbound, NTP, DNS resolver"
        Rules = @(
            @{ Name="CCDC - Allow-DNS-Out"; Protocol="UDP"; RemotePort=$Profilep; Direction="Outbound"; Profile="Any" },
            @{ Name="CCDC - Allow-DNS-TCP-Out"; Protocol="TCP"; RemotePort=53; Direction="Outbound"; Profile="Any" },
            @{ Name="CCDC - Allow-NTP-Out"; Protocol="UDP"; RemotePort=123; Direction="Outbound"; Profile="Any" }
            
        )
    }
}



#other fun helper stuff

#extra credit if we want to log the rules we make
Function Write-Log {
    param([string]$Message)
    $t = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$t] $Message"
    $line | Tee-Object -FilePath $LogFile -Append
}


#run as admin for obvious reasons
Function Require-Admin {
    if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) {
        Write-Error "This script must be run as Administrator. Exiting."
        exit 1
    }
}


#optional if its maybe needed for old rules so we dont feel bad about deleteing the whole thing
Function Backup-Firewall {
    Param()

    #actual rules export
    $backupDir = Join-Path $LogPathRoot "backup_$Timestamp"
    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    $rulesFile = Join-Path $backupDir "FirewallRules.wfw"
    try {
        netsh advfirewall export $rulesFile 2>&1 | Out-Null
        Write-Log "Exported firewall policy to $rulesFile"
    } catch {
        Write-Log "Failed to export firewall via netsh: $_"
    }
    #def prof export
    $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    $profiles | Out-File (Join-Path $backupDir "profiles.txt")
    Write-Log "Saved firewall profiles to $backupDir"
    return $backupDir
}

#
Function Restore-Firewall {
    param([string]$BackupDir)
    if (-not (Test-Path $BackupDir)) { Write-Error "Backup directory not found: $BackupDir"; return }
    $rulesFile = Join-Path $BackupDir "FirewallRules.wfw"
    if (Test-Path $rulesFile) {
        Write-Log "Restoring firewall from $rulesFile"
        netsh advfirewall import $rulesFile
        Write-Log "Import completed (check netsh output)."
    } else {
        Write-Log "No rules file found to restore."
    }
    # restore profiles if available
    $profilesFile = Join-Path $BackupDir "profiles.txt"
    if (Test-Path $profilesFile) {
        Write-Log "User can review $profilesFile to manually restore profile settings if needed."
    }
}

Function Set-DefaultPolicies {
    param(
        [ValidateSet("Block","Allow")] [string]$DefaultOutbound = "Block",
        [ValidateSet("Block","Allow")] [string]$DefaultInbound = "Block"
    )
    Write-Log "Setting default outbound = $DefaultOutbound, inbound = $DefaultInbound for Domain/Private/Public profiles."
    foreach ($p in Get-NetFirewallProfile) {
        try {
            Set-NetFirewallProfile -Name $p.Name -DefaultOutboundAction $DefaultOutbound -DefaultInboundAction $DefaultInbound -Verbose:$false
            Write-Log "Profile $($p.Name): DefaultOutbound=$DefaultOutbound DefaultInbound=$DefaultInbound"
        } catch {
            Write-Log "Failed to set profile $($p.Name): $_"
        }
    }
}

Function Create-AllowRule {
    param(
        [string]$Name,
        [string]$Direction = "Inbound",
        [string]$Protocol = "TCP",
        [string]$LocalPort = $null,
        [string]$RemotePort = $null,
        [string]$Profilep = "Any",
        [string]$RemoteAddress = "Any",
        [string]$LocalAddress = "Any",
        [string]$Program = $null,
        [string]$Description = $null
    )
    Write-Log "Creating rule: $Name ($Direction $Protocol LocalPort=$LocalPort RemotePort=$RemotePort Profile=$Profilep)"
    $params = @{
        DisplayName = $Name
        Direction   = $Direction
        Action      = "Allow"
        Profile     = $Profilep
        Enabled     = "True"
        Protocol    = $Protocol
    }
    if ($LocalPort)  { $params['LocalPort']  = $LocalPort }
    if ($RemotePort) { $params['RemotePort'] = $RemotePort }
    if ($RemoteAddress) { $params['RemoteAddress'] = $RemoteAddress }
    if ($LocalAddress)  { $params['LocalAddress']  = $LocalAddress }
    if ($Program) { $params['Program'] = $Program }
    if ($Description) { $params['Description'] = $Description }
    try {
        New-NetFirewallRule @params -ErrorAction Stop | Out-Null
        Write-Log "Rule $Name created."
    } catch {
        Write-Log "Failed to create rule $Name"
    }
}

Function Create-BlockRule {
    param(
        [string]$Name,
        [string]$Direction = "Outbound",
        [string]$Protocol = "TCP",
        [string]$LocalPort = $null,
        [string]$RemotePort = $null,
        [string]$Profilep = "Any"
    )
    Write-Log "Creating block rule: $Name"
    New-NetFirewallRule -DisplayName $Name -Direction $Direction -Action Block -Protocol $Protocol -LocalPort $LocalPort -RemotePort $RemotePort -Profile $Profilep -Enabled True -ErrorAction SilentlyContinue
}

# takes the values from the hashtable "presets" and applys them
Function Apply-Preset {
    param([string]$PresetName)
    if (-not $Presets.ContainsKey($PresetName)) { Write-Log "Preset $PresetName not found."; return }
    $preset = $Presets[$PresetName]
    Write-Log "Applying preset $PresetName : $($preset.Description)"
    foreach ($r in $preset.Rules) {
        Create-AllowRule -Name $r.Name -Direction $r.Direction -Protocol $r.Protocol -LocalPort $r.LocalPort -Profile $r.Profile
    }
    Write-Log "Preset $PresetName applied."
}

# less fast superspeed add rule (But more complex)
Function Quick-Add-Wizard {
    Write-Host "Create new profile wizard"
    $RuleOptions = @(
            @{ Name="CCDC - Allow-Kerberos-In";        Protocol="TCP"; LocalPort=88;  Direction="Inbound";  Profile="Domain" },
            @{ Name="CCDC - Allow-Kerberos-In-UDP";    Protocol="UDP"; LocalPort=88;  Direction="Inbound";  Profile="Domain" },
            @{ Name="CCDC - Allow-LDAP-In";            Protocol="TCP"; LocalPort=389; Direction="Inbound";  Profile="Domain" },
            @{ Name="CCDC - Allow-LDAP-In-UDP";        Protocol="UDP"; LocalPort=389; Direction="Inbound";  Profile="Domain" },
            @{ Name="CCDC - Allow-LDAPS-In";           Protocol="TCP"; LocalPort=636; Direction="Inbound";  Profile="Domain" },
            @{ Name="CCDC - Allow-RPC-EndpointMapper"; Protocol="TCP"; LocalPort=135; Direction="Inbound";  Profile="Domain" },
            @{ Name="CCDC - Allow-NTLM-Netlogon";      Protocol="TCP"; LocalPort=445; Direction="Inbound";  Profile="Domain" },
            @{ Name="CCDC - Allow-DNS-In";             Protocol="UDP"; LocalPort=53;  Direction="Inbound";  Profile="Domain" }
            # Add more if we fillin it chat
        )
    Write-Host $RuleOptions
    
    
}

# superspeed add rule if we need it on the fly
Function Quick-Add {
    param(
        [string]$Name,
        [string]$Protocol = "TCP",
        [string]$Direction = "Inbound",
        [string]$LocalPort = $null,
        [string]$Profilep = "Any",
        [string]$Description = $null
    )
    Create-AllowRule -Name $Name -Protocol $Protocol -Direction $Direction -LocalPort $LocalPort -Profile $Profilep -Description $Description
}

# zerologon honeypot (plz john dont kill me)
Function Start-ZerologonHoneypot {
    <#
    what it do:
        This essentially makes a TCP firewall rule that sets up a honeypot on port 445 (Chatgpt says i can make it whatever I want but idk chat).
        Then we set up a listener (rip wireshark) that grabs all the inbound connection metadata (Free IR)
        Im gunna look into having a different port option and then mirroring the traffic but truth is idk much about zerologon
    #>
    param(
        [int]$HoneyPort = 445,
        [string]$LogFilePath = (Join-Path $LogPathRoot "ZerologonHoneypot_$Timestamp.log")
    )
    Write-Log "Starting Zerologon honeypot on port $HoneyPort (log: $LogFilePath)."
    
    $ruleName = "CCDC-0log-HP-Port-$HoneyPort-AKA-Supersillyportdontworryaboutthisredteam:)"
    Create-AllowRule -Name $ruleName -Direction "Inbound" -Protocol "TCP" -LocalPort $HoneyPort -Profile "Any" -Description "Honeypot listener for Zerologon/Netlogon attempt capture."

    # Start listener in background job
    try {
        $scriptBlock = {
            param($Port,$LogFile)
            Add-Type -AssemblyName System.Net.Sockets
            $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
            try {
                $listener.Start()
            } catch {
                "[$(Get-Date -Format o)] ERROR starting listener on port $Port : $_" | Out-File -FilePath $LogFile -Append
                return
            }
            "[$(Get-Date -Format o)] Honeypot listening on port $Port" | Out-File -FilePath $LogFile -Append
            while ($true) {
                try {
                    $client = $listener.AcceptTcpClient()
                    $remote = $client.Client.RemoteEndPoint.ToString()
                    $timestamp = (Get-Date).ToString('o')
                    "[$timestamp] Connection from $remote" | Out-File -FilePath $LogFile -Append
                    $ns = $client.GetStream()
                    $buffer = New-Object byte[] 4096
                    $read = $ns.Read($buffer,0,$buffer.Length)
                    if ($read -gt 0) {
                        $sample = [System.BitConverter]::ToString($buffer,0,[Math]::Min($read,64))
                        "[$timestamp] Read $read bytes (hex sample): $sample" | Out-File -FilePath $LogFile -Append
                    }
                    $ns.Close()
                    $client.Close()
                } catch {
                    "[$(Get-Date -Format o)] Listener exception: $_" | Out-File -FilePath $LogFile -Append
                }
            }
        }
        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $HoneyPort,$LogFilePath
        Write-Log "Honeypot job started (JobId: $($job.Id)). Logs -> $LogFilePath"
        Write-Host "Honeypot running in background job id $($job.Id). Use 'Get-Job' and 'Receive-Job' to retrieve output. Log file stored at $LogFilePath"
    } catch {
        Write-Log "Failed to start honeypot job: $_"
    }
    Write-Log "Honeypot setup complete"
}

# sweet sweet backups
Function Show-Backups {
    $dirs = Get-ChildItem -Path $LogPathRoot -Directory | Where-Object { $_.Name -like "backup_*" } | Sort-Object Name -Descending
    return $dirs
}

Function Nuke-Firewall{
    Write-Host "This option will completely erase all current rules."
    $Answer = Read-Host "Are you sure you would like to continue? [Y/N]: "

    if ($Answer -match '^[Yy]') {
        write-host "Removing all FW rules..."
        Get-NetFirewallRule | Remove-NetFirewallRule
        Write-Log "[$Timestamp] User nuked all FW rules"
    }else{
        write-host "Aborted..."
    }

}


function New-FWProfile {
    param(
        [Parameter(Mandatory)]
        [string]$UserInput
    )

    $newname = Read-Host "Enter name for new config: "
    $profileFile = Join-Path $LogPathRoot ($newname + ".ps1")

    
    $indices = $UserInput -split '[ ,]+' |
        Where-Object { $_ -match '^\d+$' } |
        ForEach-Object { [int]$_ }

    if (-not $indices) {
        Write-Host "No valid rule numbers entered. Aborting."
        return
    }

    
    $indices = $indices | ForEach-Object { $_ - 1 }

    $lines = @()

    foreach ($idx in $indices) {
        
        if ($idx -lt 0 -or $idx -ge $RuleOptions.Name.Count) {
            Write-Host "Skipping invalid index $($idx + 1) (out of range)."
            continue
        }

        $line = "Create-AllowRule -Name `"$($RuleOptions.Name[$idx])`" -Direction $($RuleOptions.Direction[$idx]) -Protocol $($RuleOptions.Protocol[$idx]) -LocalPort $($RuleOptions.LocalPort[$idx]) -Profile $($RuleOptions.Profile[$idx])"
        Write-Host $line
        $lines += $line
    }

    if ($lines.Count -eq 0) {
        Write-Host "No valid rules selected. Profile not created."
        return
    }

    
    $lines | Set-Content -Path $profileFile -Encoding UTF8

    Write-Host "New profile created at $profileFile"
    Write-Output $profileFile
}




# Menu options (note: subject to change)
Function  Show-Menu   {
    Clear-Host
    Write-Host "=== Firewall Defender Menu ==="
    Write-Host "1) Backup current firewall"
    Write-Host "2) Set default policy: Block Outbound, Block Inbound (recommended)"
    Write-Host "3) Box preset Config (DomainController / DNS / WebServer / FTP / ClientWorkstation)"
    Write-Host "4) Quick add rule"
    Write-Host "5) WIP"
    Write-Host "6) (Technically WIP) Start Zerologon Honeypot (logs connections)"
    Write-Host "7) List backups / Restore from backup"
    Write-Host "8) WIP"
    Write-Host "9) Nuke Firewall"
    Write-Host "10) Exit Wirewall"
    Write-Host "11) Create/Apply firewall Profile"  
      
    $choice = Read-Host "Choose an option [1-9]"
    switch ($choice) {
        "1" {
            $b = Backup-Firewall
            Write-Host "Backup saved to $b"
            Pause
            Show-Menu
        }
        "2" {
            $confirm = Read-Host "This will set default outbound to Block and default inbound to Block for all profiles. Proceed? (Y/N)"
            if ($confirm -match '^[Yy]') {
                Backup-Firewall | Out-Null
                Set-DefaultPolicies -DefaultOutbound Block -DefaultInbound Block
                Write-Log "Default policies enforced."
                Write-Host "Defaults set."
            } else { Write-Host "Aborted." }
            Pause
            Show-Menu
        }
        "3" {
            Write-Host "Available presets: $($Presets.Keys -join ', ')"
            $p = Read-Host "Which preset to apply?"
            if ($p -and $Presets.ContainsKey($p)) {
                Backup-Firewall | Out-Null
                Apply-Preset -PresetName $p
                Write-Host "Preset $p applied."
            } else {
                Write-Host "Invalid preset."
            }
            Pause
            Show-Menu
        }
        "4" {
            
            Show-Menu
        }
        "5" {
            Write-Host "Example: Quick-Add -Name 'Allow-MyApp-443' -Protocol TCP -Direction Inbound -LocalPort 443 -Profile Any"
            $run = Read-Host "Run example to allow inbound 8443? (Y/N)"
            if ($run -match '^[Yy]') {
                Backup-Firewall | Out-Null
                Quick-Add -Name "Allow-Example-8443" -Protocol "TCP" -Direction "Inbound" -LocalPort 8443 -Profile "Any" -Description "Test example rule"
                Write-Host "Example rule created."
            } else { Write-Host "Skipped." }
            Pause
            Show-Menu
        }
        "6" {
            $hp = Read-Host "Honeypot port to bind [445]" ; if (-not $hp) { $hp=445 }
            Backup-Firewall | Out-Null
            Start-ZerologonHoneypot -HoneypotPort [int]$hp
            Pause
            Show-Menu
        }
        "7" {
            $bs = Show-Backups
            if ($bs.Count -eq 0) { Write-Host "No backups found." } else {
                Write-Host "Backups:"
                $i=0
                foreach ($d in $bs) { $i++; Write-Host "$i) $($d.FullName)" }
                $sel = Read-Host "Select number to restore, or press Enter to cancel"
                if ($sel -and ($sel -as [int] -le $bs.Count) -and ($sel -as [int] -gt 0)) {
                    $dir = $bs[([int]$sel-1)].FullName
                    Restore-Firewall -BackupDir $dir
                } else { Write-Host "Cancelled." }
            }
            Pause
            Show-Menu
        }
        "8" {
            
            Show-Menu
        }
        "10" { 
            Write-Host "Goodbye."; return 
        }
        "9"{
            Nuke-Firewall
            Show-Menu
        }"11" {

    for(($i = 0); $i -lt $RuleOptions.Count; $i++){
        if ($i -eq 0) {
            Write-Host "Domain Controller Core"
        }if ($i -eq 10) {
            Write-Host "`nDatabase Services"
        }if ($i -eq 12) {    
            Write-Host "`nWeb Services"
        }if ($i -eq 15) {
            Write-Host "`nRemote Management"
        }if ($i -eq 16) {
            Write-Host "`nDHCP"
        }if ($i -eq 18) {
            Write-Host "`nFTP"
        }
        Write-Host ($i+1) ")" ($RuleOptions.Name[$i]) - ($RuleOptions.Protocol[$i]) - ($RuleOptions.LocalPort[$i]) - ($RuleOptions.Direction[$i]) - ($RuleOptions.Profile[$i])

    }

    $tempProfile = Read-Host "Type the numbers of the rules you want to add to new profile (e.g. 1 3 5) plz add spaces my monke brain: "

    
    $profileFile = New-FWProfile -UserInput $tempProfile

    
    if (-not $profileFile) {
        Write-Host "No profile created. Returning to menu..."
        Show-Menu
        break
    }

    $UserInput = Read-Host "Would you like to apply this new profile now? (y/n)"
    if ($UserInput -match '^[Yy]') {
        
        & $profileFile
        Write-Host "Profile applied from $profileFile"
    } else {
        Write-Host "Exiting..."
    }

    Show-Menu
}
        default {
            Write-Host "Invalid choice."
            Show-Menu
        }



    }
}


Require-Admin
Write-Log "Script started by $env:USERNAME on $env:COMPUTERNAME"
Show-Menu
#ろくなな