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
AutoLogon -Domain "locpipa" -UserName "nostop" -Password "sMtp2020$&" -Enabled $true