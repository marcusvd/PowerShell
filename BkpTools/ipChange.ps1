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
IpSet -AdapterName Ethernet -IpAddress 192.168.252.99 -SubNetMask 255.255.255.0 -GateWay 192.168.252.1 -Dns1 192.168.252.3 -Dns2 8.8.8.8

