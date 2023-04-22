$labName = 'ADSecurityLab'
$domain = "contoso.com"
$labSources = "C:\LabSources"

New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV
Add-LabVirtualNetworkDefinition -Name $labName -AddressSpace 172.16.10.0/24

$secPwd = [System.Web.Security.Membership]::GeneratePassword(32, 5)
$secPwd = "Somepass1"
Add-LabDomainDefinition -Name $domain -AdminUser services -AdminPassword $secPwd
Set-LabInstallationCredential -Username services -Password $secPwd
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:IsDomainJoined'= $true
    'Add-LabMachineDefinition:DomainName'= $domain
    'Add-LabMachineDefinition:Processors'= 2
}

$Comunes = Get-LabPostInstallationActivity -ScriptFileName Comunes.ps1 -DependencyFolder $labSources\PostInstalacionActivities\Comunes
$DatosDeDominio = Get-LabPostInstallationActivity -ScriptFileName DatosDeDominio.ps1 -DependencyFolder $labSources\PostInstalacionActivities\DatosDeDominio
$SQLExpress2019 = Get-LabPostInstallationActivity -ScriptFileName SQLServerExpress2019.ps1 -DependencyFolder $labSources\PostInstalacionActivities\SQLServerExpress2019
$ServidorEntrada = Get-LabPostInstallationActivity -ScriptFileName ServidorEntrada.ps1 -DependencyFolder $labSources\PostInstalacionActivities\ServidorEntrada

Add-LabMachineDefinition -Name SRV1 -Memory 1GB -IpAddress 172.16.10.11 -UserLocale es-ES -OperatingSystem "Windows Server 2019 Standard Evaluation" -Roles RootDC -PostInstallationActivity @($Comunes, $DatosDeDominio)
Add-LabMachineDefinition -Name SRV2 -Memory 1GB -IpAddress 172.16.10.12 -UserLocale es-ES -OperatingSystem "Windows Server 2019 Standard Evaluation" -Roles WebServer -PostInstallationActivity @($Comunes, $SQLExpress2019)
Add-LabMachineDefinition -name CLI1 -Memory 2GB -IpAddress 172.16.10.18 -UserLocale es-ES -OperatingSystem "Windows 10 Pro" -PostInstallationActivity @($Comunes, $ServidorEntrada)

Install-Lab -NetworkSwitches -BaseImages -VMs -Domains -StartRemainingMachines -DelayBetweenComputers 25

Copy-LabFileItem -Path $labSources\Resources\CLI1\Vulns\* -ComputerName CLI1 -DestinationFolderPath C:\Windows\Temp\ -Recurse
Copy-LabFileItem -Path $labSources\Resources\CLI1\Tools\ -ComputerName CLI1 -DestinationFolderPath C:\AD\ -Recurse
Copy-LabFileItem -Path $labSources\Resources\CLI1\Tools\Powerview\Powerview.ps1 -ComputerName SRV1 -DestinationFolderPath C:\Windows\Temp\
Copy-LabFileItem -Path $labSources\Resources\SRV2\SQLEXPR_x64_ENU.zip -ComputerName SRV2 -DestinationFolderPath C:\Windows\Temp\
Copy-LabFileItem -Path $labSources\Resources\SRV2\AdventureWorks2019.bak -ComputerName SRV2 -DestinationFolderPath C:\Users\Public\
Copy-LabFileItem -Path $labSources\Resources\SRV2\Vulns\* -ComputerName SRV2 -DestinationFolderPath C:\Windows\Temp\ -Recurse
$instCred = [pscredential]::new('services' , ("Somepass1" | ConvertTo-SecureString -AsPlain -Force))
Invoke-LabCommand -ScriptBlock {Expand-Archive -LiteralPath C:\Windows\Temp\SQLEXPR_x64_ENU.zip -DestinationPath C:\Windows\Temp\} -ComputerName SRV2 -Credential $instCred -ActivityName "Recursos SQL"

Install-Lab -PostInstallations -Verbose

Copy-LabFileItem -Path $labSources\Resources\SRV2\employee.asp -ComputerName SRV2 -DestinationFolderPath C:\inetpub\wwwroot\
Copy-LabFileItem -Path $labSources\Resources\SRV2\Default.asp -ComputerName SRV2 -DestinationFolderPath C:\inetpub\wwwroot\

Show-LabDeploymentSummary -Detailed

Start-Sleep -Seconds 10
Stop-LabVm -All