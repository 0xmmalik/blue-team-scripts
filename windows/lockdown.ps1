[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $OutputFileName = ""
)

function get-strongpwd {
    $basepwd = "GoodTigersMM"
    $date = get-date -format yyyy-MM-dd
    $objRand = new-object random
    $num = $objRand.next(10000, 99999)
    $finalPWD = $basepwd + "!" + $date + "!" + $num
    $finalPWD
}

function get-lusers {
    "USERS:" | Out-File -FilePath sysdata.txt
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $adsi.Children | Where-Object { $_.SchemaClassName -eq "user" } | Foreach-Object {
        $groups = $_.Groups() | Foreach-Object { $_.GetType().InvokeMember("Name", "GetProperty", $null, $_, $null) }
        $namey = $_.name
        if ($null = $groups) {
            $groups = "N/A"
        }
        $namey
    }
}

function add-backupadmin {
    
    $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
    $passwd = get-strongpwd
    $LocalAdmin = $Computer.Create("User", "good-tiger")
    $LocalAdmin.SetPassword($passwd)
    $LocalAdmin.SetInfo()
    $LocalAdmin.FullName = "Good Tigers Secured Account"
    $LocalAdmin.SetInfo()
    # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
    $LocalAdmin.UserFlags = 64 + 65536
    $LocalAdmin.SetInfo()
}

Write-Output "adding backup admin account..."
add-backupadmin

Write-Output "generating list of local users..."
$users = get-lusers
$users >> sysdata.txt

Write-Output "changing user passwords..."
$fdate = get-date -format o | ForEach-Object { $_ -replace ":", "." }
foreach ($user in $users) {
    try {
        $plainTextPWD = get-strongpwd
        Write-Output "Setting $user to $plainTextPWD"
        $securePWD = ConvertTo-SecureString -String $plainTextPWD -AsPlainText -Force
        set-localuser -name $user -Password $securePWD
        Write-Output "$user,$plainTextPWD" >> $env:COMPUTERNAME-$fdate-localusers.txt
        "$user,$plainTextPWD" >> sysdata.txt
    }
    catch {
        Write-Output "PASSWORD CHANGE FAILURE: $user"
        "PASSWORD CHANGE FAILURE: $user" >> sysdata.txt
    }
}

Write-Output "configuring windows firewall..."
Netsh.exe advfirewall firewall add rule name="block notepad.exe network connections" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="block regsvr32.exe network connections" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="block calc.exe network connections" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="block mshta.exe network connections" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="block wscript.exe network connections" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="block cscript.exe network connections" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="block runscripthelper.exe network connections" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall set allprofiles state on

# prevent lolbins
$Params = @{ "DisplayName" = "block network connections notepad.exe"
    "Direction"            = "Outbound"
    "Action"               = "Block"
    "Program"              = "%systemroot%\system32\notepad.exe" 
}
New-NetFirewallRule @params
$Params = @{ "DisplayName" = "block network connections regsvr32.exe"
    "Direction"            = "Outbound"
    "Action"               = "Block"
    "Program"              = "%systemroot%\system32\regsvr32.exe" 
}
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = "block network connections calc.exe" 
    "Direction"            = "Outbound"
    "Action"               = "Block"
    "Program"              = "%systemroot%\system32\calc.exe" 
}
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = "block network connections mshta.exe"
    "Direction"            = "Outbound"
    "Action"               = "Block"
    "Program"              = "%systemroot%\system32\mshta.exe" 
}
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = "block network connections wscript.exe"
    "Direction"            = "Outbound"
    "Action"               = "Block"
    "Program"              = "%systemroot%\system32\wscript.exe" 
}
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = "block network connections cscript.exe" 
    "Direction"            = "Outbound"
    "Action"               = "Block"
    "Program"              = "%systemroot%\system32\cscript.exe" 
}
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = "block network connections runscripthelper.exe"
    "Direction"            = "Outbound"
    "Action"               = "Block"
    "Program"              = "%systemroot%\system32\runscripthelper.exe" 
}
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = "block network connections regsvr32.exe"
    "Direction"            = "Outbound"
    "Action"               = "Block"
    "Program"              = "%systemroot%\system32\regsvr32.exe" 
}
New-NetFirewallRule @Params

$Params = @{ #"Name" = "Domain, Public, Private"
    "Enabled"              = "true"
    "defaultInboundAction" = "Block"
    "LogAllowed"           = "True"
    "LogBlocked"           = "True"
    "LogIgnored"           = "True"
    "LogFileName"          = "%windir%\system32\logfiles\firewall\pfirewall.log"
    "LogMaxSizeKilobytes"  = "32767"
    "NotifyOnListen"       = "True"
}
Set-NetFirewallProfile @Params -all

# basic hardening?
Write-Output "attempting some basic hardening..."
$ErrorActionPreference = "Stop"
try {
	Write-Output "attempting to disable smb..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -name "SMB1" -Type DWORD -Value 0 -Force
}
catch {
	Write-Output "failed..."
}

try {
	Write-Output "attempting to disable smb..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -name "SMB2" -Type DWORD -Value 0 -Force
}
catch {
	Write-Output "failed..."
}

try {
	Write-Output "attempting to enable smb encryption..."
	Set-SmbServerConfiguration –EncryptData $true -Confirm:$false
}
catch {
	Write-Output "failed..."
}

try {
	Write-Output "attempting to disable smb null sessions"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -name "SMB1" -Type DWORD -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -name "RestrictAnonymous" -Type DWORD -Value 1 -Force
# $registryPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
# $Params = @{ "Path" = "HKLM:\System\CurrentControlSet\Control\Lsa"
#              "Name" = "RestrictAnonymous"
#              "Value" = "1"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -name "RestrictAnonymousSAM" -Type DWORD -Value 1 -Force
# $Params = @{ "Path" = "HKLM:\System\CurrentControlSet\Control\Lsa"
#              "Name" = "RestrictAnonymousSAM"
#              "Value" = "1"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -name "EveryoneIncludesAnonymous" -Type DWORD -Value 0 -Force
# $Params = @{ "Path" = "HKLM:\System\CurrentControlSet\Control\Lsa"
#              "Name" = "EveryoneIncludesAnonymous"
#              "Value" = "0"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
}
catch {
	Write-Output "failed..."
}

try {
Write-Output "attemping to disable llmnr..."
#REG ADD  "HKLM\Software\policies\Microsoft\Windows NT\DNSClient"
#REG ADD  "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f
New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT" -Name "DNSClient"
Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -name "EnableMulticast" -Type DWORD -Value 0 -Force
# $registryPath = "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient"
# $Params = @{ "Path" = "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient"
#              "Name" = "EnableMulticast"
#              "Value" = "0"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
}
catch {
	Write-Output "failed..."
}

#reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
try {
Write-Output "attemping to enable protections for lsa..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -name "AuditLevel" -Type DWORD -Value 8 -Force
# $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
# $Params = @{ "Path" = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
#              "Name" = "AuditLevel"
#              "Value" = "8"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
Write-Output "Enabling PPL for LSA"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name "RunAsPPL" -Type DWORD -Value 1 -Force
# $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
# $Params = @{ "Path" = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
#              "Name" = "RunAsPPL"
#              "Value" = "1"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders" -Name "WDigest"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -name "UseLogonCredential" -Type DWORD -Value 0 -Force
# $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
# $Params = @{ "Path" = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
#              "Name" = "UseLogonCredential"
#              "Value" = "0"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "CredentialsDelegation"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -name "AllowProtectedCreds" -Type DWORD -Value 1 -Force
# $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
# $Params = @{ "Path" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
#              "Name" = "AllowProtectedCreds"
#              "Value" = "1"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
#disable netbios over tcp/ip and lmhosts lookups
$nics = Get-WmiObject win32_NetworkAdapterConfiguration
foreach ($nic in $nics) {
    $nic.settcpipnetbios(2) # 2 = disable netbios on interface
    # $nic.enablewins($false,$false) #disable wins
}
}
catch {
	Write-Output "failed..."
}

try {
Write-Output "attempting to enable powershell logging..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
# New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\" -Name "ModuleLogging"
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -name "EnableModuleLogging" -Type DWORD -Value 1 -Force
# $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
# $Params = @{ "Path" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
#              "Name" = "EnableModuleLogging"
#              "Value" = "1"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
# New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\" -Name "ScriptBlockLogging"
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -name "EnableScriptBlockLogging" -Type DWORD -Value 1 -Force

# $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
# $Params = @{ "Path" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
#              "Name" = "EnableScriptBlockLogging"
#              "Value" = "1"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
# New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "Audit"
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -name "ProcessCreationIncludeCmdLine_Enabled" -Type DWORD -Value 1 -Force
# $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
# $Params = @{ "Path" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
#              "Name" = "ProcessCreationIncludeCmdLine_Enabled"
#              "Value" = "1"
#              "PropertyType" = "DWORD"
# }
# if(!(Test-Path $registryPath))  {
#     New-Item -Path $registryPath -Force | Out-Null
#     New-ItemProperty $params -Force | Out-Null
# }
# else {
#     New-ItemProperty $params -Force | Out-Null
# }
}
catch {
	Write-Output "failed..."
}

try {
Write-Output "attempting to disable smb compression"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\" -Name "Parameters"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -name "DisableCompression" -Type DWORD -Value 1 -Force
}
catch {
	Write-Output "failed..."
}
