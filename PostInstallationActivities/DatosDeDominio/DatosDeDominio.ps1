# Para proteger la lectura de SPNs
Function Set-SpnPermission {
    param(
        [adsi]$TargetObject,
        [Security.Principal.IdentityReference]$Identity
    )
    $spnSecGuid = new-object GUID "f3a64788-5306-11d1-a9c5-0000f80367c1"
    $adRight=[DirectoryServices.ActiveDirectoryRights]"ReadProperty"
    $accessRuleArgs = $identity,$adRight,"Deny",$spnSecGuid,"None"
    $spnAce = new-object DirectoryServices.ActiveDirectoryAccessRule $accessRuleArgs
    $TargetObject.psbase.ObjectSecurity.AddAccessRule($spnAce)
    $TargetObject.psbase.CommitChanges()    
    return $spnAce
}
Function Create-Users {
    param(
        [string]$Prefix,
        [string]$Group,
        [string]$Password,
        [int[]]$Range
)
    $Range | %{
        $number = ([string]$_).PadLeft(2,'0') 
        New-ADUser -Name "$Prefix.$number" -Description "$Prefix member N: $number" -SamAccountName "$Prefix.$number" -UserPrincipalName "$Prefix.$number@contoso.com" -Path "OU=$Group,DC=contoso,DC=com" -AccountPassword (Convertto-SecureString -AsPlainText $Password -Force) -Enabled $true
        Add-ADGroupMember -Identity $Group -Members "$Prefix.$number"
    }
}


Function Block-SPNs {
    param(
        [string]$Prefix,
        [int[]]$Range
)
    $Range | %{
        $number = ([string]$_).PadLeft(2,'0') 
        $name = "$Prefix.$number"
        $blockuser = [security.principal.ntaccount]"contoso\$name"
        $spnuser1 = "LDAP://CN=victim.03,DC=contoso,DC=com"
        Set-SpnPermission -TargetObject $spnuser1 -Identity $blockuser
    }
}

########################################################
Import-Module ActiveDirectory
Import-Module C:\Windows\Temp\Powerview.ps1

########################################################
# Unidades Organizativas
New-ADOrganizationalUnit -Name "Casualomputers" -Path "DC=contoso,DC=com"
New-ADOrganizationalUnit -Name "CasualUsers" -Path "DC=contoso,DC=com"
New-ADOrganizationalUnit -Name "Alumni" -Path "DC=contoso,DC=com"

# Unidades Organizativas / Grupos
New-ADGroup –name "CasualUsers" –groupscope Global –path "OU=CasualUsers,DC=contoso,DC=com"
New-ADGroup –name "Alumni" –groupscope Global –path "OU=Alumni,DC=contoso,DC=com"

# Standard users
Create-Users -Prefix "user" -Group "Alumni" -Password "Password123!" -Range @(1,2,3,4,5,6,7,8,9,10)

# victim users
Create-Users -Prefix "victim" -Group "CasualUsers" -Password "Str0ngPaSS67" -Range @(1,5,6,7,8,9,10)
Create-Users -Prefix "victim" -Group "CasualUsers" -Password "SuperStr0ngPassword" -Range @(2,3,4)

# Additional user
New-ADUser -Name "admin.aux" -Description "DA Aux Admin" -SamAccountName "admin.aux" -UserPrincipalName "admin.aux@contoso.com" -Path "OU=CasualUsers,DC=contoso,DC=com" -AccountPassword (Convertto-SecureString -AsPlainText "gMP}pp8!](5kHcs)wG8<sUS" -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "admin.aux"
Add-ADGroupMember -Identity "CasualUsers" -Members "admin.aux"

########################################################
# Misconfigurations
# 1.- Groups.xml
$Groups_xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="victim.01" image="2" changed="2019-08-27 21:07:40" uid="{0BF14BE4-4AAD-44DD-933C-6DA54774FA2E}"><Properties action="U" newName="" fullName="victim.01" description="victim.01 Backup Account For Temp Use" cpassword="JCzwVAEdHyQeEAHXGNhtuSu9nOdiLr9x3kzmXGWd9xo" changeLogon="0" noChange="0" neverExpires="0" acctDisabled="0" userName="victim.01"/></User>
</Groups>
"@
$groupspath = "C:\Windows\SYSVOL\sysvol\contoso.com\Policies\"
$filepath = Get-ChildItem "C:\Windows\SYSVOL\sysvol\contoso.com\Policies\"
$sysvolpath = $filepath.BaseName[1]
$filepath = "$groupspath$sysvolpath\"
mkdir "$filepath\MACHINE\Preferences\Groups\"
Write-Output "$Groups_xml"  > "$filepath\MACHINE\Preferences\Groups\Groups.xml"

# 2.- LLLMNR Poisoning
$jobname = "Recurring PowerShell Task"
$script=@'
$instCred = [pscredential]::new('victim.02' , ("Fuck1ngStr0ng" | ConvertTo-SecureString -AsPlain -Force))
Invoke-WebRequest -Credential $instCred -Uri http://CHALLENGE/UPS
'@
$repeat = (New-TimeSpan -Minutes 1)
$scriptblock = [scriptblock]::Create($script)
$trigger = New-JobTrigger -Once -At (Get-Date).Date -RepeatIndefinitely -RepetitionInterval $repeat
$instCred = [pscredential]::new('services' , ("Somepass1" | ConvertTo-SecureString -AsPlain -Force))
$options = New-ScheduledJobOption -RunElevated -ContinueIfGoingOnBattery -StartIfOnBattery
Register-ScheduledJob -Name $jobname -ScriptBlock $scriptblock -Trigger $trigger -ScheduledJobOption $options -Credential $instCred

# 3.- Kerberoasting
setspn -s http/contoso.com:80 victim.03

# 4.- Permisos en ACLs / ACEs: Usuario
Add-DomainObjectAcl -TargetIdentity "CN=victim.04,OU=CasualUsers,DC=contoso,DC=com" -PrincipalIdentity victim.03 -Rights All

# 5.-  Permisos en ACLs / ACEs: Grupo
Add-DomainObjectAcl -TargetIdentity "CN=Domain Admins,CN=Users,DC=contoso,DC=com" -PrincipalIdentity victim.04 -Rights All

########################################################
# Solo victim.0002 puede leer victim.0003 SPN properties
Block-SPNs -Range @(1,2,3,4,5,6,7,8,9,10) -Prefix "user"
Block-SPNs -Range @(1,4,5,6,7,8,9,10) -Prefix "victim"

# Permitir acceso por RDP al grupo Alumni
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Alumni"


# 
Set-Location "C:\Windows\Temp"
Remove-Item * -recurse -force

Set-Location "C:\Windows\Prefetch"
Remove-Item * -recurse -force

Set-Location "C:\Documents and Settings"
Remove-Item ".\*\Local Settings\temp\*" -recurse -force

Set-Location "C:\Users"
Remove-Item ".\*\Appdata\Local\Temp\*" -recurse -force