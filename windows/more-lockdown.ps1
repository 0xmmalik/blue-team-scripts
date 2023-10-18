# disable auto login by removing the registry entries for AutoAdminLogon and DefaultPassword
$RegKey = “HKLM:\SO FTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon”
ForEach ($subkey in “AutoAdminLogon”, “DefaultPassword”) {
  if (Get-ItemProperty -Name $subkey -path $RegKey -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $RegKey -Name $subkey
  }
}

# notify if DNS zone transfer occurs
$Event = Get-WinEvent -FilterHashtable @{LogName='DNS Server';ID='6001'} -MaxEvents 1
If ($Event -like $Null) { # might need to use -eq instead of -like
  exit
}
Else {
  $msg = $Event.Message + "n" + $Event.TimeGenerated | Out-String # havent checked formatting, shouldnt matter too much tho
  [reflection.assembly]::loadwithpartialname('System.Windows.Forms')
  [reflection.assembly]::loadwithpartialname('System.Drawing')
  $notify = new-object system.windows.forms.notifyicon
  $notify.icon = [System.Drawing.SystemIcons]::Information
  $notify.visible = $true
  $notify.showballoontip(10,'DNS ZONE TRANSFER OCCURRED', $msg ,[system.windows.forms.tooltipicon]::None)
}
