#cd\
[string]$folders = "Util", "Backup"
#New-Item -Name $folders[0]  -Path "c:" -ItemType directory
#cd "c:\util"
#New-Item -Name $folders[1]  -Path "c:" -ItemType directory
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
IpSet -AdapterName Ethernet -IpAddress 192.168.252.252 -SubNetMask 255.255.255.0 -GateWay 192.168.252.1 -Dns1 192.168.252.3 -Dns2 1.1.1.1
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
CallSomeFileInInitialization -NameItem BackupCode -PathFileOrCmdOrBoth "powershell -File c:\util\scripts\srvbkpfull2.ps1" -Once $true
Function RenameMachine{Param([Parameter(Mandatory=$true)]
$NewName
)

Rename-Computer $NewName

}
RenameMachine -NewName "SRVBKP01"
