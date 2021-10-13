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