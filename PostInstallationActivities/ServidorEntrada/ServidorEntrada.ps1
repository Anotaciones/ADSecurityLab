Start-Sleep -Seconds 10
# Acceso por RDP
1..10 | %{
    $numero = ([string]$_).PadLeft(2,'0') 
    net localgroup "Remote Desktop Users" "user.$numero" /ADD
    Start-Sleep -Seconds 1
}

#
Set-Location "C:\Windows\Temp"
Remove-Item * -recurse -force

Set-Location "C:\Windows\Prefetch"
Remove-Item * -recurse -force

Set-Location "C:\Documents and Settings"
Remove-Item ".\*\Local Settings\temp\*" -recurse -force

Set-Location "C:\Users"
Remove-Item ".\*\Appdata\Local\Temp\*" -recurse -force