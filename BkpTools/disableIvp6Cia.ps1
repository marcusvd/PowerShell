function ProtocolEnableDisableAllAdapters{Param([Parameter(Mandatory=$True)]
$Protocol,
$Enable
)
$Adapters = Get-NetAdapter -Name "*"
ForEach($adapter in $Adapters)
{

if($Enable)
{
Enable-NetAdapterBinding -Name $Adapters.Name  -ComponentID $Protocol #-ErrorAction SilentlyContinue
Write-Output $adapter
}

if($Enable -eq $false)
{
Disable-NetAdapterBinding -Name $Adapters.Name -ComponentID $Protocol #-ErrorAction SilentlyContinue
}
}
    #IPV6 = ms_tcpip6 
    #RDTC = ms_rspndr
    #D E/S = ms_lltdio
    #LLDP = ms_lldp
}
ProtocolEnableDisableAllAdapters -Protocol ms_tcpip6 -Enable $false
ProtocolEnableDisableAllAdapters -Protocol ms_rspndr -Enable $false
ProtocolEnableDisableAllAdapters -Protocol ms_lltdio -Enable $false
ProtocolEnableDisableAllAdapters -Protocol ms_lldp -Enable $false

function EnableDisableFirewall{param([Parameter(ValueFromPipeLine)]
[Bool]$Domain,
[Bool]$Public,
[Bool]$Private,
[Bool]$All,
[String]$Enabled
)

if($Domain -eq $True){
Set-NetFirewallProfile -Profile Domain -Enabled $Enabled
}

if($Public -eq $True){
Set-NetFirewallProfile -Profile Public -Enabled $Enabled
}

if($Private -eq $True){
Set-NetFirewallProfile -Profile Private -Enabled $Enabled
}

if($all)
{

Set-NetFirewallProfile -Profile Domain,Public ,Private -Enabled $Enabled

}


}
EnableDisableFirewall -All $true -Enabled false

Function IpSet{Param([Parameter(Mandatory=$true)]
$AdapterName,
$IpAddress,
$SubNetMask,
$GateWay,
$Dns1,
$Dns2
)
#4 - Dns address set
$Dnss += $Dns1, $Dns2
write-host($Dnss)
Netsh interface ipv4 set address $AdapterName static $IpAddress $SubNetMask $GateWay
#4 - Dns address set
Set-DnsClientServerAddress -InterfaceAlias $AdapterName -ServerAddresses $Dnss
}
IpSet -AdapterName Ethernet -IpAddress 192.168.200.99 -SubNetMask 255.255.255.0 -GateWay 192.168.200.1 -Dns1 192.168.200.199 -Dns2 8.8.8.8

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
CallSomeFileInInitialization -NameItem BackupCode -PathFileOrCmdOrBoth "c:\util\vms.ps1" -Once $false


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
addDomain -DomainP "nostopti.intra" -UserNameP "adm01" -PasswordP "sMtp2007$&"
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
AutoLogon -Domain "nostopti" -UserName "nostop" -Password "sMtp2020$&" -Enabled $true