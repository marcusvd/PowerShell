function addDomain{Param([Parameter(Mandatory=$false, ValueFromPipeLine)]
$DomainP,
$UserNameP,
$PasswordP

)
CLS
if($DomainP)
{
$Pwd = $PasswordP | ConvertTo-SecureString -asPlainText -Force
$Dom = $DomainP.Split('.')

$DomainUserNAme = $Dom[0] +"\"+ $UserNameP
$credential = New-Object System.Management.Automation.PSCredential($DomainUserNAme, $Pwd)
Add-Computer -DomainName $DomainP -Credential $credential #-ErrorAction SilentlyContinue
}
else
{
$domain = Read-Host("Please, insert domain.")
$username = Read-Host("Please, insert your username")
$password = Read-Host("Please, insert password") | ConvertTo-SecureString -asPlainText -Force

$Dom = $DomainP.Split('.')

$DomainUserNAme = $Dom[0] +"\"+ $UserNameP

$credential = New-Object System.Management.Automation.PSCredential($DomainUserNAme, $password)
Add-Computer -DomainName $domain -Credential $credential #-ErrorAction SilentlyContinue
}
}
addDomain -DomainP "locpipa.intra" -UserNameP "nostop" -PasswordP "sMtp2020$&"
Function AutoLogon{Param([parameter(Mandatory=$true)]
$Domain,
$UserName,
$Password,
$Enabled
)
cls
$caminhoReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$VolRegCaminho = Get-ItemProperty -Path $caminhoReg -Name "AutoAdminLogon"

if($Enabled)
{
#HABILITANDO LOGON AUTOMATICO
Set-ItemProperty -Path $caminhoReg -Name "AutoAdminLogon" -Value "1"
Set-ItemProperty -Path $caminhoReg -Name "DefaultUserName" -Value $UserName
New-ItemProperty -Path $caminhoReg -Name "DefaultPassword" -Value $Password -ErrorAction SilentlyContinue
Set-ItemProperty -Path $caminhoReg -Name "DefaultDomainName" -Value $Domain
}
else
{
Set-ItemProperty -Path $caminhoReg -Name "AutoAdminLogon" -Value "0"
}



}
AutoLogon -Domain "locpipa" -UserName "locpipa\nostop" -Password "sMtp2020$&" -Enabled $true
Function CallSomeFileInInitialization{Param([Parameter(Mandatory=$true)]
$NameItem,
$PathFileOrCmdOrBoth,
[bool]$Once
)

if($Once)
{
#Started with administrative privileges
$GetValueName = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -Name $NameItem -ErrorAction SilentlyContinue
if($GetValueName)
{
set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -Name $NameItem -Value $PathFileOrCmdOrBoth
}
else
{
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -Name $NameItem -Value $PathFileOrCmdOrBoth
}
}
else
{

#Started with administrative privileges
$GetValueName = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name $NameItem -ErrorAction SilentlyContinue
if($GetValueName)
{
set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name $NameItem -Value $PathFileOrCmdOrBoth
}
else
{
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name $NameItem -Value $PathFileOrCmdOrBoth
}



}




}
CallSomeFileInInitialization -NameItem BackupCode -PathFileOrCmdOrBoth "powershell -File c:\util\vms.ps1" -Once $false