#Import Modules
Import-Module $PSScriptRoot\Get-Entropy.psm1


#get-winevent -LogName "Microsoft-Windows-Sysmon/Operational" | format-list | Select -first 10
### Introduce Script
### Print Script Options
### Take Input


Write-Host "This script is intended to provide basic forensic analysis from Sysmon Logs, Windows Event Logs, and System Configurations
The Options for this script are the following:
1. Show Sysmon Event Codes for a time range
2. Identify anomolous network connections by executables
3. Identify potential process injection
4. Identify DNS requests to suspicious URLs
5. Find potential credential dumping through LSASS
"

$input = Read-Host "Please enter your desired option as a number"


### Option 1: Show specific event code for a day
##### Need to change this to select event codes inbetween certain days

function get-logs
    {
    $csv = Read-Host "Would you like this output saved to a csv? (Yes or No)" 
    $event_code = Read-Host "Please enter your desired sysmon event code"
    $start = Read-Host "Please enter your desired date/time in format 3/15/2013 00:00:00"
    $end = Read-Host "Please enter your desired date/time in format 3/15/2013 00:00:00"
    $logs = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$start; EndTime=$end; Id=$event_code }
    $logs | select -first 10 | fl
    if (($csv -eq "Yes") -or ($csv -eq "yes")) {
    $path = Read-Host "What is the full path (including file name) you would like to save these logs to?"
    $logs | Export-Csv -Path $path
    write-host "Your logs have been saved to $path"
    }
    }



### Option 2: Network Connections by Exe
##### Read about XML filtering
function find-C2
    {
    write-host "This script identifies network connections initated by executables to suspicious ports"
    $csv = Read-Host "Would you like this output saved to a csv? (Yes or No)"
    $logs = get-winevent -LogName "Microsoft-Windows-Sysmon/Operational" |
    where-object {$_.Id -eq 3 -and $_.Message -like "*.exe*" -and $_.Message -notlike "*DestinationPort: 443*" -and $_.Message -notlike "*DestinationPort: 53*" -and $_.Message -like "*Protocol: tcp*"} |
    select -first 10 | fl
    $logs
    if (($csv -eq "Yes") -or ($csv -eq "yes")) {
    $path = Read-Host "What is the full path (including file name) you would like to save these logs to?"
    $logs | Export-Csv -Path $path
    write-host "Your logs have been saved to $path"
    }
    }

### Option 3: Identify potential Process Injection
function find-injection
    {
    write-host "This script identifies process injection through enumerating Sysmon event code 8 into suspicious processes"
    $csv = Read-Host "Would you like this output saved to a csv? (Yes or No)"
    $logs = get-winevent -LogName "Microsoft-Windows-Sysmon/Operational" |
    where-object {$_.Id -eq 8 -and ($_.Message -like "*rundll*")} |
    select -first 5 | fl
    $logs
    if (($csv -eq "Yes") -or ($csv -eq "yes")) {
    $path = Read-Host "What is the full path (including file name) you would like to save these logs to?"
    $logs | Export-Csv -Path $path
    write-host "Your logs have been saved to $path"
    }
    }

### Option 4: Find Exfiltration through DNS
function find-exfil
    {
    write-host "This script identifies exfiltration through encoded DNS sub domains"
    get-winevent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 22 -and $_.Message -match "QueryName:\s+([^\r\n]+)" } |
    ForEach-Object {
        $queryName = $matches[1]
        $entropy = Get-Entropy $queryName
        if ([double]$entropy -gt 4.5)
        {
        $queryName
        }

        }}

function find-creddumping
    { 
    write-host "This script identifies access to LSASS potentially indicating credential dumping"
    $csv = Read-Host "Would you like this output saved to a csv? (Yes or No)"
    $logs = get-winevent -LogName "Microsoft-Windows-Sysmon/Operational" |
    where-object {$_.Id -eq 8 -and $_.Message -like "*lsass.exe*"} |
    select -first 5 | fl
    $logs
    if (($csv -eq "Yes") -or ($csv -eq "yes")) {
    $path = Read-Host "What is the full path (including file name) you would like to save these logs to?"
    $logs | Export-Csv -Path $path
    write-host "Your logs have been saved to $path"
    } 
    }

if ($input -eq "1")
    {
    get-logs
    }

if ($input -eq "2")
    {
    find-C2
    }

if ($input -eq "3")
    {
    find-injection
    }

if ($input -eq "4")
    {
    find-exfil
    }

if ($input -eq "5")
    {
    find-creddumping
    }