# SQL Server
& 'C:\Windows\Temp\SQLEXPR_x64_ENU\SETUP.EXE' /ConfigurationFile=C:\Windows\Temp\SQLEXPR_x64_ENU\sql.ini

$env:PSModulePath = "$([Environment]::GetEnvironmentVariable('PSModulePath', 'User'));$([Environment]::GetEnvironmentVariable('PSModulePath', 'Machine'))"

Push-Location
Import-Module Sqlps -DisableNameChecking
Pop-Location

$wmi = New-Object 'Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer'
$tcp = $wmi.GetSmoObject("ManagedComputer[@Name='$env:COMPUTERNAME']/ServerInstance[@Name='SQLEXPRESS']/ServerProtocol[@Name='Tcp']")
$tcp.IsEnabled = $true
$tcp.IPAddresses | Where-Object { $_.Name -eq 'IPAll' } | ForEach-Object {
    foreach ($property in $_.IPAddressProperties) {
        switch ($property.Name) {
            'Enabled' { $property.Value = $true }
            'TcpPort' { $property.Value = '1433' }
            'TcpDynamicPorts' { $property.Value = '0' }
        }
    }
}
$tcp.Alter()
Restart-Service 'MSSQL$SQLEXPRESS' -Force

& 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE' -U "sa" -P "HeyH0Password" -S SRV2 -i C:\Windows\Temp\SQLEXPR_x64_ENU\datos1.sql -o C:\Windows\Temp\SQLEXPR_x64_ENU\exit.txt
& 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE' -U "sa" -P "HeyH0Password" -S SRV2 -Q "CREATE DATABASE sampledb;"
& 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE' -U "sa" -P "HeyH0Password" -S SRV2 -i C:\Windows\Temp\SQLEXPR_x64_ENU\datos2.sql -o C:\Windows\Temp\SQLEXPR_x64_ENU\exit.txt
& 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE' -U "sa" -P "HeyH0Password" -S SRV2 -Q "RESTORE DATABASE [AdventureWorks2017] FROM DISK = 'C:\Users\Public\AdventureWorks2019.bak' WITH MOVE 'AdventureWorks2017' TO 'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\AdventureWorks2017.mdf', MOVE 'AdventureWorks2017_Log' TO 'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\AdventureWorks2017_log.ldf';"
& 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE' -U "sa" -P "HeyH0Password" -S SRV2 -Q "USE AdventureWorks2017; EXEC sp_changedbowner 'SQL01';"

Restart-Service 'MSSQL$SQLEXPRESS' -Force

New-NetFirewallRule `
    -Name 'SQL-SERVER-In-TCP' `
    -DisplayName 'SQL Server (TCP-In)' `
    -Direction Inbound `
    -Enabled True `
    -Protocol TCP `
    -LocalPort 1433 `
    | Out-Null

# Elevacion por permisos
New-Item -ItemType Directory -Force -Path "C:\Program Files\DACL Service\"
Copy-Item -Path "C:\Windows\Temp\daclservice.exe" -Destination "C:\Program Files\DACL Service\daclservice.exe"
c:\\Windows\\Temp\\auto.bat

Install-WindowsFeature -Name Web-Server,Web-ASP -IncludeManagementTools

#
Set-Location "C:\Windows\Temp"
Remove-Item * -recurse -force

Set-Location "C:\Windows\Prefetch"
Remove-Item * -recurse -force

Set-Location "C:\Documents and Settings"
Remove-Item ".\*\Local Settings\temp\*" -recurse -force

Set-Location "C:\Users"
Remove-Item ".\*\Appdata\Local\Temp\*" -recurse -force