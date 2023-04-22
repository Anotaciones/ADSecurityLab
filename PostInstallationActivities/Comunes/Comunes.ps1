
$null = Get-NetAdapterBinding -ComponentID ms_tcpip6 | ForEach-Object {Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6}
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f  2>&1 | Out-Null

winrm quickconfig -transport:http -quiet -force 2>&1 | Out-Null
winrm set winrm/config/service '@{AllowUnencrypted="true"}' 2>&1 | Out-Null
winrm set winrm/config/service/auth '@{Basic="true"}' 2>&1 | Out-Null
winrm set winrm/config/service/auth '@{CredSSP="true"}' 2>&1 | Out-Null

$null = New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Force
$null = New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1

secedit /export /cfg C:\secpol.cfg  2>&1 | Out-Null
(gc C:\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File C:\secpol.cfg 
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY  2>&1 | Out-Null
rm -force C:\secpol.cfg -confirm:$false  2>&1 | Out-Null

Set-MpPreference -DisableRealtimeMonitoring $true

New-ItemProperty -Path $Regkey -Name AutoAdminLogon -Value 0 -Force
New-ItemProperty -Path $Regkey -Name DefaultUserName -Value '' -Force
New-ItemProperty -Path $Regkey -Name DefaultPassword -Value '' -Force

