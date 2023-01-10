#Create a new switch 
Function switchAdapter($SwitchName, $AdpName, $AllowMangementOs, $Note)
{
$VmSwitch = Get-VMSwitch | Select-Object -Property Name

ForEach($Vs in $VmSwitch)
{
if ($Vs.Name -eq $SwitchName)
{
Write-host("Switch name already exist. Change the switch name and try again!")
}
else
{
New-VMSwitch -Name $SwitchName -NetAdapterName $AdpName -AllowManagementOS $AllowMangementOs -Notes $Note
}
}


}
#switchAdapter -SwitchName "CONEXÃO" -AdpName "Ethernet" -AllowMangementOs $true -Note 'Parent OS, VMs, LAN'

Function CreateNewVM($VMachineName, $VMemory, $VDiskFile, $SwitchName)
{
$VmSwitch = Get-VM | Select-Object -Property Name

ForEach($Vs in $VMachineName)
{
if ($Vs.Name -eq $VMachineName)
{
Write-host("Switch name already exist. Change the switch name and try again!")
}
else
{
$Mem = $VMemory
New-VM $VMachineName  $Mem -VHDPath $VDiskFile -SwitchName $SwitchName}
}
}
#CreateNewVM -VMachineName "SRVAD01" -VMemory 1024MB -VDiskFile "F:\VMS\SERVIDORES\TESTES\ad.vhdx" -SwitchName "CONEXÃO_VMS"

Function CreateVhdxDisk($NewVhdx, $Size)
{
if(Test-Path($NewVhdx))
{
Write-Host("The vhdx already exist, change the name and try again!")
}
else
{
New-VHD -Path $NewVhdx -SizeBytes $Size -Dynamic
}

}
#CreateVhdxDisk -NewVhdx 'f:\DADOS34.vhdx' -Size 150gb

Function AttachVhdx($VMName, $vhdx, $CtrlType, $CtrlNumber, $CtrlLocation)
{
Add-VMHardDiskDrive -VMName $VMName -Path $vhdx -ControllerType $ControllerType -ControllerNumber $ControllerNumber -ControllerLocation $ControllerLocation
}
AttachVhdx -VMName "SRVAD01" -vhdx F:\DADOS34.vhdx"" -CtrlType "IDE" -CtrlNumber "0" -CtrlLocation "1"
