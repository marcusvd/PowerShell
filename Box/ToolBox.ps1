#region DEFAULT OPERATIONS
#region FILES AND FOLDERS OPERATIONS
Function DirNew 
{Param([Parameter(ValueFromPipeline)]
  $Path,
 $NewDirNAme
)
if(Test-Path("$Path\$NewDirNAme"))
{
write-Host("Já Existe!")
}
Else
{
New-Item -Path $Path -Name $NewDirNAme -ItemType Directory
}

}
#DirNew -Path "c:\users\marcus\desktop" -NewDirNAme  "Manuteção NoStop-TI"

Function DirNewMultiples
{Param([Parameter(ValueFromPipeline)]
 [string[]]$Paths
)
ForEach($Test in $Paths)
{
if(Test-Path($Test))
{
write-Host("Já Existe!")
}
Else
{
ForEach($Path in $Paths)
{
New-Item -Path $Path -Name $NewDirNAme -ItemType Directory
}
}
}
}
$Paths = "c:\users\marcus\desktop\PASTAS", "c:\users\marcus\desktop\PASTAS\ADMINISTRATIVO","c:\users\marcus\desktop\PASTAS\VENDAS","c:\users\marcus\desktop\PASTAS\PUBLICA"
#DirNewMultiples -Path $Paths

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function DeleteFolderFile{Param([Parameter(ValueFromPipeline)]
  $Path,
  $Recurse
)

if($Recurse -eq $true){

if(Test-Path("$Path"))

{
Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
}
Else
{
write-Host("Pasta ou arquivo, não encontrada.")
}

}
else{

if(Test-Path("$Path"))

{
Remove-Item -Path $Path -ErrorAction SilentlyContinue -Force
}
Else
{
write-Host("Pasta ou arquivo, não encontrada.")
}
}




}
#DeleteFolderFile -Path "c:\users\marcus\desktop\SCRIPTS" -Recurse $true

Function DelByExtension($path)
{
remove-item $path -Recurse -force -ErrorAction SilentlyContinue
}
#DelByExtension -path "$env:PUBLIC\desktop\*.lnk"
#DelByExtension -path "$env:PUBLIC\desktop\*.lnk"



#<><><><><><><><><><><><><><><><><><><><>><><>#
Function RenameFolderFile
{Param([Parameter(ValueFromPipeline)]
  $Path,
  $NewName
)

if($Recurse -eq $true){

if(Test-Path("$Path"))

{
Rename-Item -Path $Path -NewName $NewName -ErrorAction SilentlyContinue
}
Else
{
write-Host("Pasta não encontrada.")
}

}
else{

if(Test-Path("$Path"))

{
Rename-Item -Path $Path -NewName $NewName -ErrorAction SilentlyContinue
}
Else
{
write-Host("Pasta não encontrada.")
}
}
}
#DirRename -Path "C:\Users\marcus\Desktop\nostop ti ó" -NewName "perfeito"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function CopyFolderFile
{Param([Parameter(ValueFromPipeline)]
  $Source,
  $Target
  )


if(Test-Path($Target))
{
write-Host("Pasta já existe no destino!")
}
Else
{
Copy-Item -Path $Source -Destination $Target -Recurse -Force -ErrorAction Continue
}
}
#CopyFolderFile -Source "\\192.168.0.197\pastas$\TECNICA\PROGRAMAS\VIRTUALIZADORES" -Target "c:\users\marcus\desktop\Virtualizadores"

Function CreateShortCut( [string]$SourceExe, [string]$DestinationPath, $Icon)
{
#Icon parameter not is needed.

$WshShell = New-Object -ComObject WScript.Shell
$ShortCut = $WshShell.CreateShortCut($DestinationPath)
$ShortCut.TargetPath = $SourceExe
if($Icon -ne $null)
{
$ShortCut.IconLocation = ("$env:SystemDrive\manut\Auto\CONFIGS\areaDeTrabalho\tvIcone.ico")
}
$ShortCut.Save()
}
#CreateShortCut -SourceExe "$env:SystemDrive\\Program Files (x86)\\TeamViewer\\TeamViewer.exe" -DestinationPath "$env:USERPROFILE\desktop\NO STOP TI.lnk" -Icon "$env:SystemDrive\manut\Auto\CONFIGS\areaDeTrabalho\tvIcone.ico"

Function CreateShortCutArgs ($LnkDestination, $Target, [string]$Ar, $WorkDir){
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($LnkDestination)
$Shortcut.TargetPath = $Target
$Shortcut.Arguments = $Ar
$Shortcut.WorkingDirectory = $WorkDir
$Shortcut.Save()
}
#CreateShortCutArgs -LnkDestination "$env:USERPROFILE\desktop\ToolBox.lnk" -Target "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" -Ar "\\srvfl10\pastas$\TECNICA\FERRAMENTAS\INSTALACOES\POWERSHELL\SCRIPTS\MODULES\ToolBox.psm1" -WorkDir "C:\Windows\System32"

Function InternetShortCut($_Url, $_TargetCreate, $_NameToSaveShortCut)
{
$wshShell = New-Object -ComObject "WScript.Shell"
$urlShortcut = $wshShell.CreateShortcut(
  (Join-Path $wshShell.SpecialFolders.Item($_TargetCreate) $_NameToSaveShortCut)
)
$urlShortcut.TargetPath = $_Url
$urlShortcut.Save()
}
#InternetShortCut -_Url "http://www.google.com.br" -_TargetCreate "AllUsersDesktop" -_NameToSaveShortCut "Googleeeeeeee.url"



Function CopyData($Source, $Target){
Copy-Item -Path $Source -Destination $Target -Recurse -force

}
#CopyData -Source "\\srvfl10\pastas$\TECNICA\PROGRAMAS\DESENVOLVIMENTO\MICROSOFT\COMPILADORES\VS2019" -Target "$env:SystemDrive\manut\VS2019"


#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SetAttributes 
{Param([Parameter(ValueFromPipeline)]
  $Path,
  $Attibute
)

if(Test-Path($Path))
{
if($Attibute -eq "Normal")
{
 (Get-Item $Path -Force).Attributes = 'Normal'
}
if($Attibute -eq "Hidden")
{
 (Get-Item $Path -Force).Attributes = 'Normal'
 (Get-Item $Path -Force).Attributes = 'Hidden'
}
if($Attibute -eq "ReadOnly")
{
 (Get-Item $Path -Force).Attributes = 'Normal'
 (Get-Item $Path -Force).Attributes = 'ReadOnly'
}







}





}
#SetAttributesClean -Path $Data -Attibute "Normal"

#<><><><><><><><><><><><><><><><><><><><>><><>#
function InheritanceOffAclsClean
{Param([Parameter(ValueFromPipeline)]
  $Path

  )

#Disable Inheritance and remove all 
$Acl = Get-Acl -Path $Path
$Acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path $Path $Acl

#Clean allacls
$acl = Get-Acl $Path
$access = $acl.Access
ForEach ($a in $access)
{
$ids = $a.IdentityReference.Value
ForEach($id in $ids)
{
$f = Convert-Path $acl.PSPath
$acl.RemoveAccessRule($a)
Set-Acl -path $f -aclObject $acl | Out-Null
}
}
}
#InheritanceOffAclsClean -Path $Data

function InheritanceOnOFF{
Param([Parameter(ValueFromPipeline)]
$path,
[Bool]$On
)
if($On){
$Acl = Get-Acl -Path $Path
$Acl.SetAccessRuleProtection($false, $false)
Set-Acl -Path $Path $Acl
}
else{
$Acl = Get-Acl -Path $Path
$Acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path $Path $Acl
}
}
#InheritanceOnOFF -path $Data -On $true

#<><><><><><><><><><><><><><><><><><><><>><><>#
function AddAcl 
{Param([Parameter(ValueFromPipeLine)]
$Data,
$Account

)

$acl = Get-Acl $Data

$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account,"FullControl","Allow")

$acl.SetAccessRule($AccessRule)

$acl | Set-Acl $Data

}
#AddAcl  -Data $Data -Account $account

function SetOwner{Param([Parameter(ValueFromPipeLine)]
$Path,
$UserAccount
)

$ACL = Get-ACL $Path
$Group = New-Object System.Security.Principal.NTAccount($UserAccount)
$ACL.SetOwner($Group)
Set-Acl -Path $Path -AclObject $ACL
}
#SetOwner -Path $Data -UserAccount "MAQNS010\adm02"

#endregion

#region REGISTRY OPERATIONS
Function KeyNew 
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
 $NewDirNAme
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path\$NewDirNAme"))
{
write-Host("Já Existe!")

}
Else
{
New-Item -Path "HKLM:\$Path" -Name $NewDirNAme -ItemType Directory
}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path\$NewDirNAme"))
{
write-Host("Já Existe!")
}
Else
{
New-Item -Path "HKCU:\$Path" -Name $NewDirNAme -ItemType Directory
}
}
}

Function CheckSetOrCreateRegKeyNamesValues ($KeyPath, $VolumeName, $VolumeData, $Type)
{
if(Test-Path($KeyPath))
{
$Get = Get-Item -Path $KeyPath
[string[]]$VNames = $null

foreach($VolNames in $Get.GetValueNames())
{
$VNames += $VolNames
}
if($VNames.Count -eq 0)
{
try
{
Set-ItemProperty -Path $KeyPath -Name $VolumeName -Value $VolumeData  -ErrorAction SilentlyContinue
Write-Host($Type + " Created!")
}
catch{Write-Host("(1) - Error, volume Name created.")}
}


elseif($VNames.Contains($VolumeName))
{
Set-ItemProperty -Path $KeyPath -Name $VolumeName -Value $VolumeData  -ErrorAction SilentlyContinue
}
else
{

try
{
Set-ItemProperty -Path $KeyPath -Name $VolumeName -Value $VolumeData  -ErrorAction SilentlyContinue
Write-Host($Type + " Created!")
}
catch{Write-Host("(2) - Error, volume Name created.")}

}
}
else
{
try
{
New-item -Path $KeyPath -ItemType Directory -ErrorAction SilentlyContinue
Write-host("Key directory created!")
}
Catch{Write-host("Creating Key directory error.")}
try
{
Set-ItemProperty -Path $KeyPath -Name $VolumeName -Value $VolumeData  -ErrorAction SilentlyContinue
}
catch{Write-Host("(3) - Error, volume Name created.")}

}
}
#CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -VolumeName "DisableNotificationCenter" -VolumeData 1 -Type DWORD
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function KeyDel 
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path"))
{
Remove-Item -Path "HKLM:\$Path" -Force

}
Else
{
write-host ("Key não encontrada: $Path")

}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path\$NewDirNAme"))
{
Remove-Item -Path "HKCU:\$Path" -Force

}
Else
{
write-host ("Key não encontrada: $Path")
}
}
}
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function KeyRename 
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
 $NewNameDir
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path\$NewNameDir"))
{
write-Host("Já Existe!")

}
Else
{
Rename-Item -Path "HKLM:\$Path" -NewName $NewNameDir
}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path\$NewNameDir"))
{
write-Host("Já Existe!")
}
Else
{
Rename-Item -Path "HKCU:\$Path" -NewName $NewNameDir
}
}
}
function KeyExport{Param([Parameter(Mandatory=$True)]
$KeyExportingPath,
$BackupPath,
$NameFileExporting
)

Invoke-Command{ REG EXPORT $KeyExportingPath "$BackupPath\$NameFileExporting"}
}
#KeyExport -KeyExportingPath "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -BackupPath "c:\users\marcus\desktop" -NameFileExporting "kuhvhvvuijijvjuvjuhujh.reg"
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function ImportReg ($FileRegToImport){
regedit /s $FileRegToImport -ErrorAction SilentlyContinue
}
#ImportReg("$env:SystemDrive\manut\registry.reg")
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function NewValueName
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
  $NewValueName,
  $Value,
  $Kind
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path\$NewValueName"))
{
write-Host("Já Existe!")
}
Else
{
New-ItemProperty -Path "HKLM:\$Path" -Name $NewValueName -Value $Value -PropertyType $Kind
}
}
#---------------------------------------------------------------------------#
If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path\$NewValueName"))
{
write-Host("Já Existe!")
}
Else
{
New-ItemProperty -Path "HKCU:\$Path" -Name $NewValueName -Value $Value -PropertyType $Kind
}
}
} 
#NewValueName -Root "LocalMachine" -Path "SOFTWARE\ODBC\ODBCINST.INI\ODBC Core" -NewValueName "TESTE" -Value "2" -Kind "DWord"
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function GetValue
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
  $ValueName
)

If($Root -eq "LocalMachine")
{

if("$Root\$Path\$ValueName" -eq "$Root\$Path\$ValueName")
{
 
$Value = Get-ItemProperty -Path "HKLM:\$Path" -Name $ValueName
return $Value.$ValueName
}
Else
{
write-Host("Nome do volume não encontrado.")
}
}
#---------------------------------------------------------------------------#
If($Root -eq "CurrentUser")
{
if("$Root\$Path\$ValueName" -eq "$Root\$Path\$ValueName")
{
$Value = Get-ItemProperty -Path "HKCU:\$Path" -Name $ValueName
return $Value.$ValueName
}
Else
{
write-Host("Nome do volume não encontrado.")
}
}
}
#GetValue -Root "CurrentUser" -Path "Software\Icaros" -ValueName "Offset"
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SetValueName
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
  $ValueName,
  $NewValueName
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path\$NewValueName"))
{
write-Host("Já Existe!")

}
Else
{

Rename-ItemProperty -Path "HKLM:\$Path" -Name $ValueName -NewName $NewValueName

}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path\$NewValueName"))
{
write-Host("Já Existe!")
}
Else
{
Rename-ItemProperty -Path "HKCU:\$Path" -Name $ValueName -NewName $NewValueName
}
}
}
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SetValue
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
  $ValueName,
  $NewValue
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path\$NewValue"))
{
write-Host("Já Existe!")

}
Else
{

Set-ItemProperty -Path "HKLM:\$Path" -Name $ValueName -Value $NewValue
}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path\$NewValue"))
{
write-Host("Já Existe!")
}
Else
{
Set-ItemProperty -Path "HKLM:\$Path" -Name $ValueName -Value $NewValue
}
}
}
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function DelValueName
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
  $ValueName
  
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path\ValueName"))
{
write-Host("Já Existe!")

}
Else
{

Remove-ItemProperty -Path "HKLM:\$Path" -Name $ValueName

}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path\ValueName"))
{
write-Host("Já Existe!")
}
Else
{
Remove-ItemProperty -Path "HKCU:\$Path" -Name $ValueName
}
}
}
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function ShowKeyRecursively
{Param([Parameter(ValueFromPipeLine)] $Root, $Path, [bool]$Recursively)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path"))
{

if($Recursively -eq $true)
{
Get-ChildItem -Path  "HKLM:\$Path" -Recurse| Select Name
}
else
{
Get-ChildItem -Path  "HKLM:\$Path" | Select Name
}
}
}

#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path\$NewDirNAme"))
{
if(Test-Path("HKCU:\$Path"))
{

if($Recursively -eq $true)
{
Get-ChildItem -Path  "HKCU:\$Path" -Recurse| Select Name


}
else
{
Get-ChildItem -Path  "HKCU:\$Path" | Select Name
}
}
}
}
}
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function ShowValueNames
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path"))
{
Get-ItemProperty -Path "HKLM:\$Path"

}
Else
{
write-host ("Key não encontrada: $Path")

}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path"))
{
Get-ItemProperty -Path "HKCU:\$Path"

}
Else
{
write-host ("Key não encontrada: $Path")
}
}
}
#<><><><><>><><># INHERINTENCE #<><><><><>><><>#
Function InheritanceOnOFF
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
  [Bool]$On
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path"))
{
 if($On){
$Acl = Get-Acl -Path HKLM:\$Path
$Acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path HKLM:\$Path $Acl
Write-Host("------------------------------------------------------------")
}

 else{
$Acl = Get-Acl -Path HKLM:\$Path
$Acl.SetAccessRuleProtection($False, $False)
Set-Acl -Path HKLM:\$Path $Acl
}

}
Else
{
write-Host("Key não encontrado.")
}
}
#---------------------------------------------------------------------------#
If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path"))
{
if($On){
$Acl = Get-Acl -Path HKCU:\$Path
$Acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path HKCU:\$Path $Acl
}
else
{
$Acl = Get-Acl -Path HKCU:\$Path
$Acl.SetAccessRuleProtection($False, $False)
Set-Acl -Path HKCU:\$Path $Acl
}
}
Else
{
write-Host("Key não encontrado.")
}
}
}
#InheritanceOnOFF -Root "CurrentUser" -Path "SOFTWARE\Icaros" -On $true

#<><><><><>><><># INHERINTENCE #<><><><><>><><>#
function InheritanceOffAclsClean
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path
  )

  If($Root -eq "CurrentUser")
{
$Root = "HKCU:\"
Set-Location -Path $Root

if(Test-Path("$Root\$Path"))
{
#Disable Inheritance and remove all 
$Acl = Get-Acl  -ErrorAction SilentlyContinue
$Acl.SetAccessRuleProtection($true, $true)
Set-Acl $Path $Acl


$access = $acl.Access
ForEach ($a in $access)
{
$ids = $a.IdentityReference.Value
ForEach($id in $ids)
{
$f = Convert-Path $acl.PSPath -ErrorAction SilentlyContinue
$acl.RemoveAccessRuleAll($a) 
Set-Acl $f -aclObject $acl | Out-Null
cls
}
}
}
}

  If($Root -eq "LocalMachine")
{
$Root = "HKLM:\"
Set-Location -Path $Root

if(Test-Path("$Root\$Path"))
{
#Disable Inheritance and remove all 
$Acl = Get-Acl  -ErrorAction SilentlyContinue
$Acl.SetAccessRuleProtection($true, $true)
Set-Acl $Path $Acl


$access = $acl.Access
ForEach ($a in $access)
{
$ids = $a.IdentityReference.Value
ForEach($id in $ids)
{
$f = Convert-Path $acl.PSPath -ErrorAction SilentlyContinue
$acl.RemoveAccessRuleAll($a) 
Set-Acl $f -aclObject $acl | Out-Null
cls
}
}
}
}

}
#InheritanceOffAclsClean -Root "LocalMachine" -Path "Software\Icaros"

Function AddAcl
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
  $Account,
  $Access,
  $AllowDenied

)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path"))
{

$Root = "HKLM:\"
Set-Location -Path $Root

$acl = Get-Acl $Path

$AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule($Account, $Access, $AllowDenied)

$acl.SetAccessRule($AccessRule)

$acl | Set-Acl $Path

}
Else
{
write-host ("Key não encontrada: $Path")

}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path"))
{

$Root = "HKCU:\"
Set-Location -Path $Root

$acl = Get-Acl $Path

$AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule($Account, "FullControl", $AllowDenied)

$acl.SetAccessRule($AccessRule)

$acl | Set-Acl $Path

}
Else
{
write-host ("Key não encontrada: $Path")
}
}
}
#AddAcl   -Root "LocalMachine" -Path "SOFTWARE\Icaros" -Account "MAQNS10\TESTE" -Access "FullControl" -AllowDenied "Allow"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SetOwner
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
  $Useraccount

  
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path"))
{
$ACL = Get-ACL HKLM:\$Path
$Group = New-Object System.Security.Principal.NTAccount($UserAccount)
$ACL.SetOwner($Group)
Set-Acl -Path HKLM:\$Path -AclObject $ACL
}
Else
{

Write-Host("Key não encontrada!")

}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path"))
{
$ACL = Get-ACL HKLM:\$Path
$Group = New-Object System.Security.Principal.NTAccount($UserAccount)
$ACL.SetOwner($Group)
Set-Acl -Path HKCU:\$Path -AclObject $ACL
}
Else
{
Write-Host("Key não encontrada!")
}
}
}
#SetOwner -Root "LocalMachine" -Path "SOFTWARE\Icaros" -Useraccount "maqns010\adm02"
#Não aceitou usuarios locais só do dominio.
#endregion

#region SERVICES OPERATIONS
Function GetStatusServ
{Param([Parameter(ValueFromPipeline)]
  $ServiceName
  
)

$ServiceName = Get-Service -Name $ServiceName

return $ServiceName.Status

}
#GetStatusServ -ServiceName "wuauserv"

#<><><><><><><><><><><><><><><><><><><><>><><>#
function GetStartUpType{
Param([parameter(Mandatory=$True)][String]$ServiceName)

(Get-Service -Name $ServiceName).StartType


}
#GetStartUpType -ServiceName "wuauserv"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function StartStopServ 
{Param([Parameter(ValueFromPipeline)]
  $ServiceName,
  $Status
)

if($Status -eq "Stopped"){

Stop-Service -Name $ServiceName -Force

}


$Services = Set-Service -Name $ServiceName -Status $Status
$Services


}
#StartStopServ -ServiceName "wuauserv" -Status "Running"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SetStartUpType
{Param([Parameter(ValueFromPipeline)]
  $ServiceName,
  $Stype
)

$Service = Set-Service -Name $ServiceName -StartupType $Stype
$Service
}
#SetStartUpType -ServiceName "wuauserv" -Stype "Automatic"
#endregion

#region ACCOUNT OPERATIONS
Function GetAllLocalAccounts{
$Accounts = Get-LocalUser
$Accounts.Name
}
#GetAllLocalAccounts

Function NewUserAccount{param([parameter(Mandatory=$true)]
$NewUsr,
$Pass
)

$Encry = convertto-securestring $Pass -asplaintext -force

New-LocalUser -Name $NewUsr -Password $Encry


}
#NewUserAccount -NewUsr "98231fa615669@#$%" -Pass "123"

Function DelUserAccount{param([parameter(Mandatory=$true)]
$AccountToDel
)

Remove-LocalUser -Name $AccountToDel

}
#DelUserAccount -AccountToDel "USUARIO"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function AccountIsEnable{Param
([Parameter(Mandatory=$True)]
[String]$Account
)
$Accounts = Get-LocalUser -Name $Account
[Bool]$Result = $Accounts.Enabled
Write-Output $Result
}
#AccountIsEnable -Account "Adm02"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SetPasswordUserAccount{Param
([Parameter(Mandatory=$True)]
[String]$AccountName,
[String]$Password
)
$Encry = convertto-securestring $Password -asplaintext -force
$GetUserAccount = Get-LocalUser -Name $AccountName
$GetUserAccount | Set-LocalUser -Password $Encry
}
#SetPasswordUserAccount -AccountName "Adm02" -Password "123"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SetNameUserAccount{Param
([Parameter(Mandatory=$True)]
[String]$OldNameAccount,
[String]$NewNameAccount
)
$AccountNameToChg = Get-LocalUser -Name $OldNameAccount
Set-LocalUser -Name $AccountNameToChg -FullName $NewNameAccount
Rename-LocalUser -Name $AccountNameToChg -NewName $NewNameAccount
}
#SetNameUserAccount -OldNameAccount "adm02" -NewNameAccount "TESTE"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function AccountExist{
Param
([Parameter(Mandatory=$True)]
[String]$AccountName

)

$GetAllAccounts = Get-LocalUser | Where-Object {$_.Name}

if ($GetAllAccounts.Name -eq $AccountName){
return $True
}
else{
return $False
}

}
#AccountExist -AccountName "adminigstrador"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function EnableDisableUserAccount{Param
([Parameter(Mandatory=$True)]
[String]$AccountName,
[String]$EnableDisable
)
if($EnableDisable -eq ("ENABLE")){

Enable-LocalUser -Name $AccountName

}
if($EnableDisable -eq ("DISABLE")){

Disable-LocalUser -Name $AccountName 

}

}
#EnableDisableUserAccount -AccountName "ADM02" -EnableDisable "ENABLE"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function PasswordNeverExpires{Param
([Parameter(Mandatory=$True)]
[String]$AccountName,
[Int]$NeverExpire
)
if($EnableDisable -eq (1)){

Set-LocalUser -Name $AccountName -PasswordNeverExpires $NeverExpire

}
if($EnableDisable -eq (0)){

Disable-LocalUser -Name $AccountName 
}

Set-LocalUser -Name $AccountName -PasswordNeverExpires $NeverExpire

}
#PasswordNeverExpires -AccountName "USUARIO" -NeverExpire "0"

#endregion

#region GROUP OPERATIONS
Function GetAllLocalGroups{
$Groups = Get-LocalGroup
$Groups.Name
}
#GetAllLocalGroups

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function GroupExist{Param
([Parameter(Mandatory=$True)]
[String]$Group
)
$GetAll = Get-LocalGroup
ForEach($Groups in $GetAll.Name ){
if($Groups -eq $Group){
return $True
}
else{
Return $False
}
}
}
GroupExist -Group "Administradores1458"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function AddRemoveMemberGroup{Param
([Parameter(Mandatory=$True)]
[String]$Member,
[String]$Group,
[String]$AddRemove

)

if($AddRemove -eq "Add"){

Add-LocalGroupMember -Group $Group -Member $Member

}
if($AddRemove -eq "Remove"){

Remove-LocalGroupMember -Group $Group -Member $Member

}
}
#AddRemoveMemberGroup -Member "Convidado" -Group "Administradores" -AddRemove "Remove"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function CreateGroup{Param
([Parameter(Mandatory=$True)]
[String]$Group,
[String]$Desc
)

New-LocalGroup -Name $Group -Description $Desc

}
#CreateGroup -Group "Admins" -Desc "ddddd"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function DelGroup{Param
([Parameter(Mandatory=$True)]
[String]$Group
)

Remove-LocalGroup -Name $Group

}
#DelGroup -Group "Admins"


Function AddUserToLocalAdmGroup ($DomainUser){

net localgroup administradores /add $DomainUser


}
#AddUserToLocalAdmGroup("nostopti\ns002")


#endregion

#region PROCESS START


#Simple Start-process Function
Function StartProcess($Run){
Start-Process -FilePath $Run
} 
#StartProcess -Run "c:\windows\system32\calc.exe"


#WorkDirectory Start-process Function
Function StartProcess($Run, $WorkDir){
Start-Process -FilePath $Run -WorkingDirectory $WorkDir
} 
#StartProcess -Run "calc.exe"  -WorkDir "c:\windows\system32"

#Register Input, Output and OutPut Erros
Function StartProcess($Run, $ArgsToRun, $CmdInput, $ExecutableReturned, $Error){
#Fields
$DateTime = get-date
$NameFileToRename = $DateTime.ToFileTime()

if(Test-Path($CmdInput))
{

Rename-Item $CmdInput -NewName $CmdInput$NameFileToRename
new-item $CmdInput -Force

}
else{new-item $CmdInput -Force}

if(Test-Path($ExecutableReturned))
{
Rename-Item $ExecutableReturned -NewName $ExecutableReturned$NameFileToRename
new-item $ExecutableReturned -Force
}
else
{new-item $ExecutableReturned -Force}

if(Test-Path($Error))
{
Rename-Item $Error -NewName $Error$NameFileToRename
new-item $Error -Force
}
else{new-item $Error -Force}

Start-Process -FilePath $Run -ArgumentList $ArgsToRun -RedirectStandardInput $CmdInput -RedirectStandardOutput $ExecutableReturned -RedirectStandardError $Error -Wait

}
#StartProcess -Run "cmd" -ArgsToRun "/c start c:\windows\system32\calc.exe" -CmdInput "C:\manut\returns\starprocess\input.txt" -ExecutableReturned "C:\manut\returns\starprocess\ExecutableReturned.txt" -Error "C:\manut\returns\starprocess\ErroExecution.txt"

#Wait finish and window style
Function StartProcess($Run, $Style){

Start-Process -FilePath $Run -Wait -WindowStyle $Style

}
StartProcess -Executable "C:\Program Files (x86)\TeamViewer\TeamViewer.exe" -Style Maximized

#endregion


#endregion

#region O.S SETTINGS

#region NetWork
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


function ProtocolEnableDisableSpecificAdapter{Param([Parameter(Mandatory=$True)]
$Protocol,
$adapterName,
$Enable
)

if($Enable)
{
Enable-NetAdapterBinding -Name $adapterName  -ComponentID $Protocol #-ErrorAction SilentlyContinue
}

if($Enable -eq $false)
{
Disable-NetAdapterBinding -Name $adapterName -ComponentID $Protocol #-ErrorAction SilentlyContinue
}
    #IPV6 = ms_tcpip6 
    #RDTC = ms_rspndr
    #D E/S = ms_lltdio
    #LLDP = ms_lldp
}
#ProtocolEnableDisableSpecificAdapter -Protocol "ms_tcpip6" -adapterName "wi-fi" -Enable $true
#ProtocolEnableDisableSpecificAdapter -Protocol "ms_rspndr" -adapterName "wi-fi" -Enable $true
#ProtocolEnableDisableSpecificAdapter -Protocol "ms_lltdio" -adapterName "wi-fi" -Enable $true
#ProtocolEnableDisableSpecificAdapter -Protocol "ms_lldp" -adapterName "wi-fi" -Enable $true


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
#EnableDisableFirewall -Domain $true -Enabled false
#EnableDisableFirewall -Public $true -Enabled false
#EnableDisableFirewall -Private $true -Enabled false


function EnableDisableSpecficRuleFirewall{Param([Parameter(Mandatory=$true)]
$Rule,
$Open
)
netsh advfirewall firewall set rule group=`"$Rule`" new enable=$Open
}
#EnableDisableSpecficRuleFirewall -Rule "Área de trabalho Remota" -Open "Yes"
#EnableDisableSpecficRuleFirewall -Rule  "Gerenciamento Remoto do Windows" -Open "Yes"

#<><><><><><><><><><><><><><><><><><><><>><><>#
function RdpEnable{Param([Parameter(Mandatory=$true)]
[Bool]$Enable,
[Bool]$Level
)

if($Enable)
{
#AcessEnable
$val = Get-itemProperty -path "HKLM:\SYSTEM\ControlSet001\Control\Terminal Server" -name fDenyTSConnections
    if ($val."fDenyTSConnections" -ne 0)
    {
    Set-ItemProperty -path "HKLM:\SYSTEM\ControlSet001\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    }

    #Crypt level
    if($level)
    {
        Set-ItemProperty -path "HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
    }

    if($level -eq $false)
    {
        Set-ItemProperty -path "HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0
    }
}

if($Enable -eq $false)
{
#AcessDisable
$val = Get-itemProperty -path "HKLM:\SYSTEM\ControlSet001\Control\Terminal Server" -name fDenyTSConnections
    if ($val."fDenyTSConnections" -ne 1)
    {
    Set-ItemProperty -path "HKLM:\SYSTEM\ControlSet001\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    }

   #Crypt level
    if($level)
    {
        Set-ItemProperty -path "HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
    }

    if($level -eq $false)
    {
        Set-ItemProperty -path "HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0
    }
}
}
#RdpEnable -Enable $False -Level $True

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SendMail{Param([Parameter(Mandatory=$false)]
$SMTPServer,
$SMTPPort,
$Username,
$Password,
$to,
$cc,
$subject,
$body,   
$attachment
)
$Email = New-Object System.Net.Mail.MailMessage
$Email.subject = $subject
$Email.body = $body
$Email.to.add("marcusmvd@yahoo.com.br")
#$Email.cc.add($cc)
$Email.from = $username
#$Email.attachments.add($attachment)
$Smtp = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort);
$Smtp.EnableSsl =$true
$Smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password);
$Smtp.Send($Email)




}
SendMail -SMTPServer "smtp.gmail.com" -SMTPPort "587" -Username "contato@nostopti.com" -Password "http2018$%" -to "marcusmvd@yahoo.com.br" -subject "13:52 04/12/2019" -body "corpo da msg"
#<><><><><><><><><><><><><><><><><><><><>><><>#

#endregion

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function ActiveSetPassDefaulAdm{Param
([Parameter(ValueFromPipeLine)]
[String]$AccountName1 = "Administrador",
[String]$AccountName2 = "Administrador",
[String]$Password,
[Bool]$Br = $true,
[Bool]$Us = $True
)
$GetAllAccounts = Get-LocalUser | Where-Object {$_.Name -eq $AccountName1}

if ($GetAllAccounts.Name -eq "Administrador"){

Enable-LocalUser -Name $AccountName1

$Encry = convertto-securestring $Password -asplaintext -force

$GetAllAccounts.Name | Set-LocalUser -Password $Encry

}
else{
$Br = $False
}

$GetAllAccounts = Get-LocalUser | Where-Object {$_.Name -eq $AccountName2}

if($GetAllAccounts.Name -eq "administrator"){

Enable-LocalUser -Name $AccountName2

$Encry = convertto-securestring $Password -asplaintext -force

$GetAllAccounts.Name | Set-LocalUser -Password $Encry

}
else{
$Us = $False
}

if($Us, $Br -eq $False){

Write-Host("Default account, administrator, may have been removed or renamed.")

}
}
#ActiveSetPassDefaulAdm -Password "http2018$"
#<><><><><><><><><><><><><><><><><><><><>><><>#

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function PowerPlan{Param([Parameter(Mandatory=$False)]
[Bool]$Balanced = $false,
[Bool]$High = $false,
[Bool]$PowerSaver = $false
)
if($Balanced)
{
Powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e
Write-Host("The power plan selected is the (Balanced)")

}

if($High)
{
Powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
Write-Host("The power plan selected is the (High)")
}

if($PowerSaver)
{
Powercfg -setactive a1841308-3541-4fab-bc81-f71556f20b4a
Write-Host("The power plan selected is the (PowerSaver)")

}

}
#PowerPlan -High $True

#<><><><><><><><><><><><><><><><><><><><>><><>#
function DefenderException{Param([Parameter(Mandatory=$false)]
[string[]]$Paths
)
foreach($files in $Paths)
{
  Add-MpPreference -ExclusionPath $files -ErrorAction SilentlyContinue
}
}
#DefenderException -Paths "c:\windows\KMS-QADhook.dll", "c:\windows\KMS-R@1nhook.exe", "c:\manut","C:\manut\Auto\Ativador\W10\AW10.exe", "c:\windows\KMS-R@1n.exe"
#<><><><><><><><><><><><><><><><><><><><>><><>#
#------------Windows10
Function InstallOptionalFeature{Param([Parameter(Mandatory=$true)]
$FeatureName

)

$adFeature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName
if($adFeature.State -eq "Disabled")
{
Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName
}
If($adFeature.State -eq "Enabled")
{
write-host("It is already installed.")
}

}
#InstallOptionalFeature -FeatureName  "WAS-WindowsActivationService"

Function InstallWindowsFeature{Param([Parameter(Mandatory=$true)]
$FeatureName

)

$adFeature = Get-WindowsFeature -Name $FeatureName
if($adFeature.Installed -eq $false)
{
Install-WindowsFeature -Name $FeatureName
}
If($adFeature.Installed -eq $true)
{
write-host("It is already installed.")
}

}
InstallWindowsFeature -FeatureName "Wds"
InstallWindowsFeature -FeatureName "WDS-Deployment"
InstallWindowsFeature -FeatureName "WDS-Transport"
InstallWindowsFeature -FeatureName "WDS-AdminPack"

#2012
Function InstallWindowsFeature{Param([Parameter(Mandatory=$true)]
$FeatureName

)

$adFeature = Get-WindowsFeature -Name $FeatureName

if($adFeature.Installed -eq $false)
{
Install-WindowsFeature -Name $FeatureName -IncludeAllSubFeature -IncludeManagementTools
}
else
{
write-host("It is already installed.")
}

}
InstallWindowsFeature -FeatureName  "AD-Domain-Services"
InstallWindowsFeature -FeatureName  "DHCP"
InstallWindowsFeature -FeatureName  "DNS"

Function RemoveWindowsFeature{Param([Parameter(Mandatory=$true)]
$FeatureName

)

$adFeature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName
if($adFeature.State -eq "Enabled")
{
Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName
}
If($adFeature.State -eq "Disabled")
{
write-host("Not installed.")
}

}
#RemoveWindowsFeature -FeatureName  "WAS-WindowsActivationService"
#<><><><><><><><><><><><><><><><><><><><>><><>#

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
#AutoLogon -Domain "NOSTOPTI" -UserName "Marcus" -Password "123" -Enabled $true

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
#CallSomeFileInInitialization -NameItem "ValueName" -PathFileOrCmdOrBoth "Huhuhuhuhuhuhuuh" -Once $False

Function RenameMachine{Param([Parameter(Mandatory=$true)]
$NewName
)

Rename-Computer $NewName

}
#RenameMachine -NewName "MAQNS10"

Function RenameMachineRandom{
$chars = [char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
[string]$NewName = [string](($chars[0..25]|Get-Random)+(($chars|Get-Random -Count 14) -join ""))

Rename-Computer $NewName

}
#RenameMachineRandom

Function DisabledActionCenter
{

Function TestReg($Path, $Nome, $Vol)
{

if(Test-Path($Path))
{

}


}



New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows" -Name "Explorer"
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion" -Name "PushNotifications"
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0
Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0
Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0
Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 0
Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay" -Name "Enabled" -Value 0

}
DisabledActionCenter



#endregion

#region TROUBLESHOOTING OS
Function Wuapp($Restart){
Function StartStopServ{Param([Parameter(ValueFromPipeline)]
  $ServiceName,
  $Status
)

if($Status -eq "Stopped"){

Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue

}


$Services = Set-Service -Name $ServiceName -Status $Status -ErrorAction SilentlyContinue
$Services


}
Function DeleteFolderFile{Param([Parameter(ValueFromPipeline)]
  $Path,
  $Recurse
)

if($Recurse -eq $true){

if(Test-Path("$Path"))

{
Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
}
Else
{
write-Host("Pasta ou arquivo, não encontrada.")
}

}
else{

if(Test-Path("$Path"))

{
Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
}
Else
{
write-Host("Pasta ou arquivo, não encontrada.")
}
}


}
Function Download($Url, $DownTarget){
#Down for work the invoke-request
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $DownTarget
}
function CompressDecompress{Param([Parameter(Mandatory=$True)]
$Source,
$Target,
[bool]$Compress
#[bool]$Decompress
)
#Down for work the invoke-request
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#LIBRARY DOWN
#DOWNLOAD
$url = "http://www.nostopti.com/tvirtual/toolbox/libraries/system.io.compression.filesystem.dll"
$output = "$env:SystemDrive\manut\Auto\OFFLINE\CompressDecompress.dll"
#INSTALAR
Download -Url $url -DownTarget $output

Add-Type -Path $env:SystemDrive\manut\Auto\OFFLINE\CompressDecompress.dll

if($Compress)
{

if(Test-Path($Target))
{
DeleteFolderFile -Path $Target -Recurse $true
}
[System.IO.Compression.ZipFile]::CreateFromDirectory($Source, $Target)

#DECOMPRESS
}
else
{
if(Test-Path($Target))
{
DeleteFolderFile -Path "$Target\PSWindowsUpdate" -Recurse $true
}
[System.IO.Compression.ZipFIle]::ExtractToDirectory($Source, $Target)
}

}
Function CopyFolderFile{Param([Parameter(ValueFromPipeline)]
  $Source,
  $Target
  )


if(Test-Path($Target))
{
DeleteFolderFile -Path "$Target\PSWindowsUpdate" -Recurse $true
Copy-Item -Path $Source -Destination $Target -Recurse -Force -ErrorAction Continue
}
Else
{
Copy-Item -Path $Source -Destination $Target -Recurse -Force -ErrorAction Continue
}
}
Function CallUpdate{Param([Parameter(Mandatory=$true)]
[Bool]$Restart
)
if($Restart)
{
cls
write-host @"
**************************************************
***   UPDATE DO WINDOWS POR FAVOR AGUARDE....  ***
**************************************************
"@

$UpdateNow = Get-WUInstall -confirm:$false -AutoReboot Driver -ErrorAction SilentlyContinue

if($UpdateNow -eq $null){

write-host("Received Null")
}
else
{
write-host ("Updates Founds")
Get-WUInstall -confirm:$false -AutoReboot Driver
}



write-host @"
**********************
***  FINALIZANDO   ***
**********************
"@
#Invoke-Command{shutdown -r -f -t 00}
}

#Update system without restart
else{

cls
write-host @"
**************************************************
***   UPDATE DO WINDOWS POR FAVOR AGUARDE....  ***
**************************************************
"@

Get-WUInstall -confirm:$false

write-host @"
**********************
***  FINALIZANDO   ***
**********************
"@

}
}
if(Test-Path("c:\manut"))
{
write-host("A pasta já existe")
}
else
{
new-item -Path "c:\manut\auto" -Name "OFFLINE" -ItemType directory
}

#Stop services
StartStopServ -ServiceName "wuauserv" -Status "Stopped"
StartStopServ -ServiceName "bits" -Status "Stopped"
#Clean cache wuapp
DeleteFolderFile -Path "$env:SystemRoot\softwareDistribution" -Recurse $true
#Start sevices
StartStopServ -ServiceName "wuauserv" -Status "Running"
StartStopServ -ServiceName "bits" -Status "Running"
#Download Module
Download -Url "https://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc/file/41459/47/PSWindowsUpdate.zip" -DownTarget "$env:SystemDrive\manut\Auto\OFFLINE\MdlWuapp.zip"
#Decompress Module
CompressDecompress -Source "$env:SystemDrive\manut\Auto\OFFLINE\MdlWuapp.zip" -Target "$env:SystemDrive\manut\Auto\OFFLINE" -Compress $false
#Install Module
CopyFolderFile -Source "$env:SystemDrive\manut\Auto\OFFLINE\PSWindowsUpdate" -Target "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules"
import-module pswindowsupdate
#Call Update
CallUpdate -Restart $Restart}
Wuapp -Restart $true

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function delExtensionRecurse{Param([Parameter(Mandatory=$true)]
[string[]]$Extension
)

Foreach($ext in $Extension){
$DelEx = Get-ChildItem "$env:SystemDrive\*.$ext" -Recurse -ErrorAction SilentlyContinue
Foreach($deleting in $DelEx){
write-host ("DELETANDO.: "+$deleting)
Remove-Item -Path $deleting -Recurse -Force -ErrorAction SilentlyContinue
}

}

}
#delExtensionRecurse -Extension "tmp"

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function delTmpPathsRecurse{
Write-host("DELETANDO...")
Remove-Item -Path "$env:SystemRoot\temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:USERPROFILE\appdata\local\temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Write-host("DELETADO.")
}
#delTmpPathsRecurse

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function DefenderUpdateScan{

Get-MpComputerStatus | select *updated, *version
Update-MpSignature
Get-MpComputerStatus | select *updated, *version

write-host("ATUALIZADO!")
Start-Sleep -Seconds 3
cls
Start-MpScan -ScanType FullScan
}
#DefenderUpdateScan

#<><><><><><><><><><><><><><><><><><><><>><><>#
function FixPrinter {

$path = "$env:SystemRoot\System32\spool\PRINTERS"

#troca proprietario
$ACL = Get-ACL $Path
$Group = New-Object System.Security.Principal.NTAccount("Todos")
$ACL.SetOwner($Group)
Set-Acl -Path $path -AclObject $ACL
#Clean allacls
$Acl = Get-Acl -Path $Path
$Acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path $Path $Acl

$acl = Get-Acl $Path
$access = $acl.Access
ForEach ($a in $access)
{
$ids = $a.IdentityReference.Value
ForEach($id in $ids)
{
$f = Convert-Path $acl.PSPath
$acl.RemoveAccessRule($a)
Set-Acl -path $f -aclObject $acl | Out-Null
}
}
#add acl
$acl = Get-Acl $path
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Todos","FullControl","Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl $path

if(Test-Path($path))
{
Remove-Item -Path $path\* -Recurse -Force -ErrorAction SilentlyContinue
Get-Printer | Get-PrintJob | Remove-PrintJob
}




}
#FixPrinter
#endregion

#region GENERAL TOOLS
#<><><><><><><><><><><><><><><><><><><><>><><>#
function CompressDecompress
{Param([Parameter(Mandatory=$True)]
$Source,
$Target,
[bool]$Compress
#[bool]$Decompress
)
#NAMESPACE

#LIBRARY DOWN
#DOWNLOAD
$url = "http://www.nostopti.com/tvirtual/ToolBox/libraries/system.io.compression.filesystem.dll"
$output = "$env:USERPROFILE\downloads\CompressDecompress.dll"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output

Add-Type -Path $env:USERPROFILE\downloads\CompressDecompress.dll

if($Compress)
{

if(Test-Path($Target))
{

Remove-Item $Target -Force -ErrorAction SilentlyContinue

}
[System.IO.Compression.ZipFile]::CreateFromDirectory($Source, $Target)

#DECOMPRESS
}
else
{
[System.IO.Compression.ZipFIle]::ExtractToDirectory($Source, $Target)
}

}
CompressDecompress -Source "C:\Users\marcus\Desktop\WORKING" -Target "C:\Users\marcus\Desktop\working.zip" -Compress $false
#<><><><><><><><><><><><><><><><><><><><>><><>#
Function EsdToWim{Param([Parameter(Mandatory=$true)]
[string]$EsdSource,
[string]$WimTarget
)
dism /get-WimInfo /wimFile:$EsdSource
write-host("")
write-host("")
$Index = Read-Host("Insert index number, here.")
DISM /Export-Image /SourceImageFile:$EsdSource /SourceIndex:$Index /DestinationImageFile:$WimTarget /Compress:Max /CheckIntegrity
}
#EsdToWim -EsdSource "C:\users\marcus\desktop\install.esd" -WimTarget C:\users\marcus\desktop\install.wim

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SpecialReboot{Param([parameter(Mandatory=$true)]
$RebootMode
)

if($RebootMode -eq 0)
{
bcdedit /deletevalue '{current}' safeboot
Restart-Computer -Force
}

if($RebootMode -eq 1)
{
Invoke-Command{bcdedit /set '{current}' safeboot minimal}
Restart-Computer -Force
}

if($RebootMode -eq 2)
{
bcdedit /set {current} safeboot network
Restart-Computer -Force
}

if($RebootMode -eq 3)
{
Invoke-Command{bcdedit /set loadoptions DDISABLE_INTEGRITY_CHECKS
Restart-Computer -Force
}
}
}
SpecialReboot -RebootMode 3
#Normal                     = 0
#SafeMode                   = 1
#SafeMode with network      = 2
#Disable Integrity Drivers  = 3


Function TurnOffOneMultiples{Param([Parameter(Mandatory=$False)]
[string[]]$Machines,
[string]$Pwd,
[string]$Domain,
[string]$UserName
)
cls
[String]$Pass = $Pwd | ConvertTo-SecureString -AsPlainText -Force
write-host($Domain+"\"+$UserName)
$Credetial = New-Object System.Management.Automation.PSCredential($Domain+"\"+$UserName, $Pass)
ForEach($M in $Machines)
{
$user = $Domain+"\"+$UserName

net use \\$m /user:$user $Pwd
Start-Sleep -Seconds 10
shutdown -s -f -t 00 -m $m
}
}
[string[]]$Machines = "srvhv01" , "SRVAD01"
TurnOffOneMultiples -Machines $Machines -UserName "adm01" -Domain "locpipa" -Pwd "sMtp2007`$&"

#<><><><><><><><><><><><><><><><><><><><>><><>#


Function SilentInstall{Param([Parameter(Mandatory=$false)]
$Url,
$Output,
[string]$ExecutableOffline,#Executable offline
$WaitFinish,
$Args#arguments of setup executable
)
try
{
#region Check internet available.
$ping = New-Object System.Net.NetworkInformation.Ping
$result = $ping.Send("www.google.com.br",1,1)
$HttpCheck = invoke-webrequest $Url -DisableKeepAlive -UseBasicParsing -Method head
#endregion
#region internet available true
if($HttpCheck.BaseResponse.ContentLength -ne -1)
{

Invoke-WebRequest -Uri $Url -OutFile $Output
[string[]]$splitVer = $Output.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]
if($Ex -eq "exe")
{
try
{
if($WaitFinish -eq $true)
{

Write-Host("Installing "+$code+"...")
Start-Process -FilePath $Output -ArgumentList $Args -Wait
Write-Host("$code, Installed.")

}
else
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $Output -ArgumentList $Args
Write-Host("$code, Installed.")

}

}
catch
{
Write-Host("Error.")
}
}
if($Ex -eq "msi")
{
try
{
if($WaitFinish -eq $true)
{
Write-Host("Installing "+$code+"...")
start-process -wait -filepath msiexec " /I $Output /qn"
Write-Host("$code, Installed.")
}
else
{
Write-Host("Installing "+$code+"...")
start-process -filepath msiexec " /I $Output /qn"
Write-Host("$code, Installed.")
}
}
catch
{
Write-Host("Error.")
}
}
}
}
#endregion


catch
{

if(Test-Path($ExecutableOffline))
{
[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($Ex -eq "exe")
{

[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]

[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($WaitFinish -eq $true)
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $ExecutableOffline -ArgumentList $Args -Wait
Write-Host("$code, Installed.")
}
else
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $ExecutableOffline -ArgumentList $Args
Write-Host("$code, Installed.")

}
}

if($Ex -eq "msi")
{

[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($WaitFinish -eq $true)
{
Write-Host("Installing "+$Ex+"...")
start-process -wait -filepath msiexec " /I $ExecutableOffline /qn"
Write-Host("$code, Installed.")
}
else
{
Write-Host("Installing "+$Ex+"...")
start-process -filepath msiexec " /I $ExecutableOffline /qn"
Write-Host("$code, Installed.")

}
}

}
else
{
Write-host("all installation methods have failed." )
}

}
}
SilentInstall -Url "https://dl2.cdn.filezilla-project.org/server/FileZilla_Server-0_9_60_2.exe?h=V_XtM0wupyWI8_7RYHaXNQ&x=1587122265" -ExecutableOffline "$env:USERPROFILE\downloads\FileZilla.exe" -Args "/S"
SilentInstall -Url $xml._WorkStation._Softwares._Compress7Z._Url -OutPut $xml._WorkStation._Softwares._Compress7Z._OutPut -ExecutableOffline $xml._WorkStation._Softwares._Compress7Z._ExecutableOffline -Args $xml._WorkStation._Softwares._Compress7Z._Args -WaitFinish $true



Function SilentUninstall{Param([Parameter(Mandatory=$false)]
$Name,
$Args
)
cls
$ObjectUninstall = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match $Name } |
            Select-Object -Property DisplayName, UninstallString
           
ForEach ($ver in $ObjectUninstall) 
{
if($ver.UninstallString)
{
$Msi = $ver | Where-Object {$_.UninstallString -match "{"}
If($Msi)
{
ForEach ($ver in $ObjectUninstall) 
{
if($ver.UninstallString){
$splitVer = $ver.UninstallString -split("/x")
$code = $splitVer[1]
}
Write-Host("Desistalando "+$Name+"...")
Start-Process -FilePath MsiExec.exe  "/X $code  /qn /norestart" -Wait
}
}
$Exe = $ver | Where-Object {$_.UninstallString -match "\\"}
If($Exe)
{
Write-Host("Desistalando "+$Name+"...")
Start-Process -FilePath $ver.UninstallString $Args -Wait
}
}
}
}
#MsiPack don't need Args.
#SilentUninstall -Name "TeamViewer" -Args 

Function MultiRDPConnections([string[]]$Accounts)
{
foreach($account in $UserAccounts)
{
$ip = "srvrdp01"

$UserName = $account
cmdkey /generic:TERMSRV/"srvrdp01" /user:"pdk\$account" /pass:"http2007$"
for($n =0; $n -le 39; $n++)
{
mstsc /v:"srvrdp01"
}
}
}
#$UserAccounts = "PROTS01,PROTS02,PROTS03,PROTS04,PROTS05,PROTS06,PROTS07,PROTS08,PROTS09,PROTS10,PROTS11,PROTS12,PROTS13,PROTS14,PROTS15,PROTS16,PROTS17,PROTS18,PROTS19,PROTS20,PROTS21,PROTS22,PROTS23,PROTS24,PROTS25,PROTS26,PROTS27,PROTS28,PROTS29,PROTS30,PROTS31,PROTS32,PROTS33,PROTS34,PROTS35,PROTS36,PROTS37,PROTS38,PROTS39,"
#MultiRDPConnections $UserAccounts


Function SendMail{Param([Parameter(Mandatory=$false)]
$SMTPServer,
$SMTPPort,
$Username,
$Password,
$to,
$cc,
$subject,
$body,   
$attachment
)
$Email = New-Object System.Net.Mail.MailMessage
$Email.subject = $subject
$Email.body = $body
$Email.to.add("marcusmvd@yahoo.com.br")
#$Email.cc.add($cc)
$Email.from = $username
#$Email.attachments.add($attachment)
$Smtp = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort);
$Smtp.EnableSsl =$true
$Smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password);
$Smtp.Send($Email)




}
SendMail -SMTPServer "smtp.gmail.com" -SMTPPort "587" -Username "contato@nostopti.com" -Password "http2018$%" -to "marcusmvd@yahoo.com.br" -subject "13:52 04/12/2019" -body "corpo da msg"
#<><><><><><><><><><><><><><><><><><><><>><><>#


#region SEND PRINT SCREEN
#
#Before create "C:\manut\returns\print"
#


#region Functions
Function GetMemory{
#Get total memory installed.
$InstalledRAM = Get-WmiObject -Class Win32_ComputerSystem
#Divide  Mbytes by gb
$Total = [Math]::Round(($InstalledRAM.TotalPhysicalMemory/ 1GB))
$MemoryPysical = Get-WmiObject -Class Win32_PhysicalMemory
$Speed = $MemoryPysical | Select-Object -ExpandProperty Speed
[string[]]$MemoryTotalBank = $MemoryPysical
$TotalReturn = $Total


$TotalReturn
$MemoryTotalBank.Count
$Speed
}
Function GetMachineName{
$MachineName = $env:COMPUTERNAME
$MachineName
}
Function GetProcessor{

$Processor = Get-WmiObject Win32_Processor

$Processor.Name

$Processor.Description

}
Function GetOs {

$OSInfo = Get-WmiObject Win32_OperatingSystem

$OSInfo.Caption

$OSInfo.Version

}
Function GetDisk{

$Disk = Get-PhysicalDisk
[string[]]$TotalDisks = $Disk
$DisksType = $Disk | Select-Object -ExpandProperty MediaType 
#Free Space
$DriverLetter = $env:SystemDrive
$FreeSpace = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$DriverLetter'"  | % {[Math]::Round(($_.FreeSpace / 1GB),2)}
$TotalSystemDisk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$DriverLetter'"  | % {[Math]::Round(($_.Size / 1GB),2)}

$TotalDisks.Count
$TotalSystemDisk
$FreeSpace
$DisksType
#$FormattedDisk
}
Function MBoard{

$MatherBoard = Get-WmiObject win32_baseboard 
$Product = $MatherBoard | Select-Object -ExpandProperty Product

$Manufacturer = $MatherBoard | Select-Object -ExpandProperty Manufacturer

$Product
$Manufacturer


}
Function Download($Url, $DownTarget){
#Down for work the invoke-request
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $DownTarget
}
function CompressDecompress{Param([Parameter(Mandatory=$True)]
$Source,
$Target,
[bool]$Compress
#[bool]$Decompress
)
#NAMESPACE

#LIBRARY DOWN
#DOWNLOAD
$url = "http://www.nostopti.com/tvirtual/toolbox/libraries/system.io.compression.filesystem.dll"
$output = "$env:SystemDrive\manut\Auto\OFFLINE\CompressDecompress.dll"
#INSTALAR
Download -Url $url -DownTarget $output

Add-Type -Path $env:SystemDrive\manut\Auto\OFFLINE\CompressDecompress.dll

if($Compress)
{

if(Test-Path($Target))
{

Remove-Item $Target -Force -ErrorAction SilentlyContinue
}
[System.IO.Compression.ZipFile]::CreateFromDirectory($Source, $Target)

#DECOMPRESS
}
else
{
[System.IO.Compression.ZipFIle]::ExtractToDirectory($Source, $Target)
}

}
Function SendMail{Param([Parameter(Mandatory=$false)]
$SMTPServer,
$SMTPPort,
$Username,
$Password,
$to,
$cc,
$subject,
$body,   
$attachment
)
$Email = New-Object System.Net.Mail.MailMessage
$Email.subject = $subject
$Email.body = $body
$Email.to.add("contato@nostopti.com")
#$Email.cc.add($cc)
$Email.from = $username
$Email.attachments.add($attachment)
$Smtp = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort);
$Smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password);
$Smtp.EnableSsl =$true
Clear
Write-host("Sending mail...")
$Smtp.Send($Email)
Write-host("Email has been sent.")
}
Function IDsPrintSend([string]$Run, $Style){
Function Wait([int]$Second, $Milliseconds){
if($Second)
{
Start-Sleep -Seconds $Second
}

if($Milliseconds)
{
Start-Sleep -Milliseconds $Milliseconds
}


}
Function PrintScreen ($SaveTo){
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
#Screen Resolution Information
$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
$Width = $Screen.Width
$Height = $Screen.Height
$Left = $Screen.Left
$Top = $Screen.Top
#Create Bitmap using the  top-left and bottom-right bounds
$bitmap = New-Object System.Drawing.Bitmap $Width, $Height
$Graphic = [System.Drawing.Graphics]::FromImage($bitmap)
#capture screen
$Graphic.CopyFromScreen($Left, $top, 0, 0, $bitmap.Size)
#Save File
$bitmap.Save($SaveTo)
Write-Output("Screenshot saved to: $SaveTo")
}



$RunSpl = $Run.Split('\')

[int]$LastElement = $RunSpl.Count

$LastElement--

$NameToSplit = $RunSpl[$LastElement]

$FinalName = $NameToSplit.Split('.')
[string]$Fname = $FinalName[0]
$FinishName = "$Fname.bmp"
Start-Process -FilePath $Run -WindowStyle $Style
Wait -Second 15


$GetProcess = Get-Process -Name $FinalName[0] | Stop-Process -Force
Start-Process -FilePath $Run -WindowStyle $Style
Wait -Second 15

#Never will be change
$save = "$env:SystemDrive\manut\returns\print\$FinishName"
PrintScreen -SaveTo $Save
Wait -Second 3
}

#endregion
#region HARDWARESCREEN
$infoObject = New-Object PSObject
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Machine Name" -value ($_MachineName)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Processor Name" -value ($_ProcName)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Processor Description" -value ($_ProcDesc)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "O.S Name" -value ($_OsName)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "O.S Version" -value ($_OsVersion)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Total Memory GB" -value ($_TotalPhysicalMemory)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Total Banks" -value ($_MemoryTotalBank)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Speed Memory" -value ($_Speed[0])
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Total Physical Disks" -value ($_TotalDisks)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "System Disk Letter" -value ($env:SystemDrive)
Add-Member -InputObject $infoObject -MemberType NoteProperty -Name "Max size System driver" -Value ($_TotalSystemDisk)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Free Space System Disk" -value ($_FreeSpace)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Type of disks" -value ($_DisksType)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "M.B Model" -value ($_Product)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "M.B Manufacturer" -value ($_Manufacturer)
#





#endregion
#region CALL FUNCTIONS
$_MachineName = GetMachineName
$_TotalPhysicalMemory,$_MemoryTotalBank, $_Speed = GetMemory
$_ProcName,$_ProcDesc = GetProcessor
$_OsName, $_OsVersion = GetOs
$_TotalDisks, $_TotalSystemDisk, $_FreeSpace, $_DisksType = GetDisk
$_Product, $_Manufacturer = MBoard
IDsPrintSend -Run "C:\Program Files (x86)\TeamViewer\TeamViewer.exe" -Style Maximized
IDsPrintSend -Run "C:\Program Files (x86)\AnyDeskMSI\AnyDeskMSI.exe" -Style Maximized
CompressDecompress -Source "C:\manut\returns\print"  -Target "c:\manut\returns\screen.zip" -Compress $true
SendMail -SMTPServer "smtp.gmail.com" -SMTPPort "587" -Username "contato@nostopti.com" -Password "http2018$%" -to "contato@nostopti.com" -subject "FORMATACAO \ NO STOP TI" -body $infoObject -attachment "c:\manut\returns\print\screen.bmp"
#endregion



#endregion






#region Overwritten
Function SilentInstall{Param([Parameter(Mandatory=$false)]
$Url,#Link to down
$Output,#Downloaded File
[string]$ExecutableOffline,#Executable offline
$Args#arguments of setup executable
)
try
{
#region Check internet available.
$ping = New-Object System.Net.NetworkInformation.Ping
$result = $ping.Send("www.google.com.br",1,1)
$HttpCheck = invoke-webrequest $Url -DisableKeepAlive -UseBasicParsing -Method head
#endregion
#region internet available true
if($HttpCheck.BaseResponse.ContentLength -ne -1)
{
Invoke-WebRequest -Uri $Url -OutFile $Output
[string[]]$splitVer = $Output.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]
if($Ex -eq "exe")
{
try
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $Output -ArgumentList $Args
Write-Host("$code, Installed.")

}
catch
{
Write-Host("Error.")
}
}
if($Ex -eq "msi")
{
try
{
Write-Host("Installing "+$code+"...")
start-process -wait -filepath msiexec " /I $Output /qn"
Write-Host("$code, Installed.")

}
catch
{
Write-Host("Error.")
}
}
}
}
#endregion


catch
{

if(Test-Path($ExecutableOffline))
{
[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($Ex -eq "exe")
{

[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]

[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $ExecutableOffline -ArgumentList $Args -Wait
Write-Host("$code, Installed.")

}

if($Ex -eq "msi")
{

[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
<#[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]#>
Write-Host("Installing "+$Ex+"...")
start-process -wait -filepath msiexec " /I $ExecutableOffline /qn"
Write-Host("$code, Installed.")

}

}
else
{
Write-host("all installation methods have failed." )
}

}
}
#SilentInstall -Url "https://download.teamviewer.com/download/TeamViewer_Setup.exe" -Output "$env:USERPROFILE\downloads\TEAMVIEWER.exe" -ExecutableOffline "$env:SystemDrive\manut\Auto\OFFLINE\TEAMVIEWER.exe" -Args "/S"
#endregion
#endregion

#region SUPPORT

Function Finish{Param([Parameter(Mandatory=$true)]
$CurrentUser,
$NewUserName,
$NewComputerName,
$NewPassword,
$AutoUpdate
)

Rename-Computer $NewComputerName

$Encry = convertto-securestring $NewPassword -asplaintext -force
$GetUserAccount = Get-LocalUser -Name $CurrentUser
$GetUserAccount | Set-LocalUser -Password $Encry

$AccountNameToChg = Get-LocalUser -Name $CurrentUser
Set-LocalUser -Name $AccountNameToChg -FullName $NewUserName
Rename-LocalUser -Name $AccountNameToChg -NewName $NewUserName
#AutoLogon Disable
$caminhoReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $caminhoReg -Name "AutoAdminLogon" -Value "0"
if($AutoUpdate -eq "false")
{
Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
}
else
{
Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
}

}
Finish -CurrentUser "Adm02" -NewUserName "Fatima" -NewComputerName "MAQCS01" -NewPassword "123" -AutoUpdate "false"

function ActivatorW10{Param([Parameter(Mandatory=$false)]
[string[]]$Paths,
[string]$CrackZipFIle,
[string]$UncompressFolder,
[string]$ExeUncompressed,
[string]$Silencedparameters
)
cls
#NAMESPACE

#LIBRARY DOWN
#DOWNLOAD
$url = "http://www.nostopti.com/tvirtual/toolbox/libraries/system.io.compression.filesystem.dll"

$output = "$env:USERPROFILE\downloads\CompressDecompress.dll"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output

Add-Type -Path $env:USERPROFILE\downloads\CompressDecompress.dll

#Add Exception
foreach($files in $Paths)
{
 Add-MpPreference -ExclusionPath $files -ErrorAction SilentlyContinue
}

if(Test-Path($UncompressFolder))
{

Remove-Item $UncompressFolder -Recurse -Force
[System.IO.Compression.ZipFIle]::ExtractToDirectory($CrackZipFIle, $UncompressFolder)
}
else
{
#NAMESPACE
[System.IO.Compression.ZipFIle]::ExtractToDirectory($CrackZipFIle, $UncompressFolder)

}


start-process $ExeUncompressed $Silencedparameters
}
ActivatorW10 -Paths "c:\windows\KMS-QADhook.dll", "c:\windows\KMS-R@1nhook.exe", "c:\manut","C:\manut\Auto\Ativador\W10\AW10.exe", "c:\windows\KMS-R@1n.exe" -CrackZipFIle "c:\manut\Auto\Ativador\W10.zip" -UncompressFolder "C:\manut\Auto\Ativador\W10\" -ExeUncompressed "c:\manut\Auto\Ativador\W10\aw10.exe" -Silencedparameters " /ActWindows /silent /preactivate"

function SerialChange{Param([Parameter(Mandatory=$true)]
$Key
)
SLMGR /ipk $Key | CHANGE cdkey
slmgr /skms kms.xspace.in
}
#SerialChange -Key "VK7JG-NPHTM-C97JM-9MPGT-3V66T"

#region I.E Configurations
#region INTERNET ZONE 3
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2107" -VolumeData 00000004 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1200" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1400" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1001" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1004" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1201" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1206" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1207" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1208" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1209" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "120A" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "120B" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "120C" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1402" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1405" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1406" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1407" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1408" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1409" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "140A" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1601" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1604" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1605" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1606" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1607" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1608" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1609" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "160A" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "160B" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1802" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1803" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1804" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1809" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1812" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1A00" -VolumeData 00020000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1A02" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1A03" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1A04" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1A05" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1A06" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1A10" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1C00" -VolumeData 00010000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2000" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2005" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2007" -VolumeData 00010000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2100" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2101" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2102" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2103" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2104" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2105" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2106" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2200" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2201" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2300" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2301" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2302" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2400" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2401" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2402" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2600" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2700" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2701" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2702" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2703" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2704" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2708" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2709" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "270B" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "270C" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "270D" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "140C" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "1806" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2500" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2707" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2001" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "2004" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "CurrentLevel" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -VolumeName "Flags" -VolumeData 00000001 -Type DWORD
#endregion
#region TRUSTED SITES ZONE 2
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "CurrentLevel" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "Flags" -VolumeData 00000071 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1200" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1400" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1001" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1004" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1201" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1206" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1207" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1208" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1209" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "120A" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "120B" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "120C" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1402" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1405" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1406" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1407" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1408" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1409" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "140A" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "140C" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1601" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1604" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1605" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1606" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1607" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1608" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1609" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "160A" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "160B" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1802" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1803" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1804" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1809" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1812" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1A00" -VolumeData 00020000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1A02" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1A03" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1A04" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1A05" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1A06" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1A10" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1C00" -VolumeData 00010000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2000" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2001" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2004" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2005" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2007" -VolumeData 00010000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2100" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2101" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2102" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2103" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2104" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2105" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2106" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2107" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2108" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2200" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2201" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2300" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2301" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2302" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2400" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2401" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2402" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2600" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2700" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2701" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2702" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2703" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2704" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2708" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2709" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "270B" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "270C" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "270D" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2500" -VolumeData 00000003 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "2707" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -VolumeName "1806" -VolumeData 00000000 -Type DWORD
#endregion
#region I.E ADVANCED TABLE

#REG_SZ
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "Move System Caret" -VolumeData "no"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "Expand Alt Text" -VolumeData "no"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "EnableAlternativeCodec" -VolumeData "yes"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "Enable AutoImageResize" -VolumeData "yes"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "Check_Associations" -VolumeData "yes"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "Friendly http errors" -VolumeData "yes"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "NotifyDownloadComplete" -VolumeData "yes"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "Isolation" -VolumeData "PMIL"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "Error Dlg Displayed On Every Error" -VolumeData "no"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\AutoComplete" -VolumeName "Append Completion" -VolumeData "yes"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Download" -VolumeName "CheckExeSignatures" -VolumeData "no"
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing" -VolumeName "UseMRUSwitching" -VolumeData "no"
#REG_DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "PlaySounds" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "UseSWRender" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "Show image placeholders" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "NscSingleExpand" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "UseThemes" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "GotoIntranetSiteForSingleWordEntry" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "HideOpenWithEdgeInContextMenu" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "HideNewEdgeButton" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "SmoothScroll" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "MixedContentBlockImages" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "DoNotTrack" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "DOMStorage" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main" -VolumeName "Isolation64Bit" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\CaretBrowsing" -VolumeName "EnableOnStartup" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Control Panel" -VolumeName "UTF8URLQuery" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Download" -VolumeName "RunInvalidSignatures" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\FlipAhead" -VolumeName "FPEnabled" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\IEDevTools\Options" -VolumeName "ConsoleBufferAlways" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\PrefetchPrerender" -VolumeName "Enabled" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Recovery" -VolumeName "AutoRecover" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Suggested Sites" -VolumeName "Enabled" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Zoom" -VolumeName "ResetZoomOnStartup2"  -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Zoom" -VolumeName "ResetTextSizeOnStartup" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "EnableHttp1_1" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "ProxyHttp1.1" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "EnableHTTP2" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "UrlEncoding" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "EnablePunycode" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "DisableIDNPrompt" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "ShowPunycode" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "WarnonBadCertRecving" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "WarnOnPostRedirect" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" -VolumeName "iexplore.exe" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" -VolumeName "LOCALMACHINE_CD_UNLOCK" -VolumeData 00000001 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-VolumeName "CertificateRevocation" -VolumeData 00000000 -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"-VolumeName "State" -VolumeData "0x00023E00" -Type DWORD
#endregion 
#region I.E PRIVACY TABLE
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE" -VolumeName "DisableToolbars" -VolumeData "00000000" -Type DWORD
CheckSetOrCreateRegKeyNamesValues -KeyPath "HKCU:\Software\Microsoft\Internet Explorer\New Windows" -VolumeName "PopupMgr" -VolumeData "00000000" -Type DWORD
#endregion
#endregion
#region Backup
function AssistantAuth{Param([Parameter(Mandatory=$True)]
$AddrMachine,
$UserName,
$Pwd
)
Invoke-Command{net use \\$AddrMachine /user:$UserName $pwd}
}
function ConfRegExport{Param([Parameter(Mandatory=$True)]
$KeyExportingPath,
$BackupPath,
$NameSave,
$NameFileExporting
)

#AssistantAuth -AddrMachine 192.168.0.21 -UserName nostopti\marcus -Pwd "123"
if(Test-Path("$BackupPath\$env:COMPUTERNAME")){
New-Item -Path "$BackupPath\$env:COMPUTERNAME" -Name $NameSave -ItemType directory -ErrorAction SilentlyContinue
if(Test-Path("$BackupPath\$env:COMPUTERNAME\$NameSave\$NameFileExporting"))
{
Remove-Item "$BackupPath\$env:COMPUTERNAME\$NameSave\$NameFileExporting" -Force
}
Invoke-Command{ REG EXPORT $KeyExportingPath "$BackupPath\$env:COMPUTERNAME\$NameSave\$NameFileExporting"}
}
else
{
Write-host("$BackupPath\$env:COMPUTERNAME")

New-Item -Path $BackupPath -Name $env:COMPUTERNAME -ItemType Directory
if(Test-Path("$BackupPath\$env:COMPUTERNAME")){
New-Item -Path "$BackupPath\$env:COMPUTERNAME" -Name $NameSave -ItemType directory -ErrorAction SilentlyContinue
Invoke-Command{ REG EXPORT $KeyExportingPath "$BackupPath\$env:COMPUTERNAME\$NameSave\$NameFileExporting"}
}
else
{
 write-host("I'm sorry, I can not solve your problem. Contact your network support.")
}
}
}
ConfRegExport -KeyExportingPath "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -BackupPath "C:\Users\marcus\Desktop\last2" -NameSave "TASKBAR" -NameFileExporting "TASKBAR.reg"
ConfRegExport -KeyExportingPath "HKCU\Software\Microsoft\Office\15.0\Outlook\Profiles" -BackupPath "C:\Users\marcus\Desktop\last2" -NameSave "OUTLOOK" -NameFileExporting "OUTLOOK2013.reg"
ConfRegExport -KeyExportingPath "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains" -BackupPath "\\192.168.0.21\c$\users\marcus\desktop\Exported" -NameSave "SECURITY_SITES" -NameFileExporting "ALLOWED_SITES.reg"
function ConfFilesExport{Param([Parameter(Mandatory=$True)]
$TargetExportingPath,
$BackupPath,
$NameSave,
$NameFileExporting
)

AssistantAuth -AddrMachine 192.168.0.21 -UserName nostopti\marcus -Pwd "123"
if(Test-Path("$BackupPath\$env:COMPUTERNAME")){
New-Item -Path "$BackupPath\$env:COMPUTERNAME" -Name $NameSave -ItemType directory -ErrorAction SilentlyContinue
if(Test-Path($TargetExportingPath))
{
Copy-Item -Path $TargetExportingPath  -Destination "$BackupPath\$env:COMPUTERNAME\$NameSave\$NameFileExporting" -Recurse -Force
}
else
{
Write-host("User file exception not found.")
}
}
else
{
New-Item -Path $BackupPath -Name $env:COMPUTERNAME -ItemType Directory
if(Test-Path("$BackupPath\$env:COMPUTERNAME")){
New-Item -Path "$BackupPath\$env:COMPUTERNAME" -Name $NameSave -ItemType directory -ErrorAction SilentlyContinue
if(Test-Path($TargetExportingPath))
{
Copy-Item -Path $TargetExportingPath  -Destination "$BackupPath\$env:COMPUTERNAME\$NameSave\$NameFileExporting" -Recurse -Force
}
else
{
Write-host("User file exception not found.")
}
}
else
{
 write-host("I'm sorry, I can not solve your problem. Contact your network support.")
}
}
}
ConfFilesExport -TargetExportingPath "$env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites" -BackupPath "\\192.168.0.21\c$\users\marcus\desktop\Exported" -NameSave "JAVA" -NameFileExporting "exceptions.sites"
function ConfFilesExport{Param([Parameter(Mandatory=$True)]
$TargetExportingPath,
$BackupPath,
$NameSave,
$NameFileExporting
)

AssistantAuth -AddrMachine 192.168.0.21 -UserName nostopti\marcus -Pwd "123"
if(Test-Path("$BackupPath\$env:COMPUTERNAME")){
New-Item -Path "$BackupPath\$env:COMPUTERNAME" -Name $NameSave -ItemType directory -ErrorAction SilentlyContinue
if(Test-Path($TargetExportingPath))
{
Copy-Item -Path $TargetExportingPath  -Destination "$BackupPath\$env:COMPUTERNAME\$NameSave\$NameFileExporting" -Recurse -Force
}
else
{
Write-host("User file exception not found.")
}
}
else
{
New-Item -Path $BackupPath -Name $env:COMPUTERNAME -ItemType Directory
if(Test-Path("$BackupPath\$env:COMPUTERNAME")){
New-Item -Path "$BackupPath\$env:COMPUTERNAME" -Name $NameSave -ItemType directory -ErrorAction SilentlyContinue
if(Test-Path($TargetExportingPath))
{
Copy-Item -Path $TargetExportingPath  -Destination "$BackupPath\$env:COMPUTERNAME\$NameSave\$NameFileExporting" -Recurse -Force
}
else
{
Write-host("User file exception not found.")
}
}
else
{
 write-host("I'm sorry, I can not solve your problem. Contact your network support.")
}
}
}
ConfFilesExport -TargetExportingPath "$env:USERPROFILE\appdata\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned" -BackupPath "C:\Users\marcus\Desktop\last2" -NameSave "TASKBAR" -NameFileExporting "FOLDERS"


Function RestoreTaskBar($BkpIconsRestore, $BkpRegRestore){
$TaskbarDefaultPath = $env:APPDATA+"\Microsoft\Internet Explorer\Quick Launch\User Pinned\"
regedit /s $BkpRegRestore -ErrorAction SilentlyContinue
copy-item -Path  $BkpIconsRestore -Destination $TaskbarDefaultPath -Recurse -Force -ErrorAction SilentlyContinue
}
RestoreTaskBar -BkpIconsRestore "$env:SystemDrive\manut\NOSTOPTI\$mac\taskbar" -BkpRegRestore "$env:SystemDrive\manut\NOSTOPTI\$mac\taskbar.reg"





#endregion
#region Troubleshooting Apps
Function FixChromeFav
{
#Pega a data do sistema e da um formato a ela 'permitido por ter o -uformat antes.
$data = Get-Date -uformat "(%d-%m-%Y)"
#PEGA HORA DO BKP
$horario = Get-Date
$horas = $horario.Hour

$Process = Get-Process -Name "chrome" | Stop-Process -Force

$profile = $env:USERPROFILE
$ChromeFolderRaiz = "AppData\Local\Google"
$Fav = "\Chrome\User Data\Default"
$fullPathToFav = "$profile\$ChromeFolderRaiz$Fav"

if(Test-Path("$fullPathToFav")){

$NewName = "Google_"
$NewName += $horario.ToFileTime()

if(Test-Path("$fullPathToFav\Bookmarks")){

copy-item -Path $fullPathToFav\Bookmarks -Destination $profile
$Process = Get-Process -Name "chrome" | Stop-Process
Start-Sleep  -Seconds 5
Rename-Item -Path "$profile\$ChromeFolderRaiz" -NewName $NewName

}
Start-Process -FilePath chrome
Start-Sleep -Seconds 3
$Process = Get-Process -Name "chrome" | Stop-Process -Force
copy-item -Path $profile\Bookmarks -Destination $fullPathToFav
Start-Process -FilePath chrome
}

}

Function AdvFixChrome{
#PEGA ENDEREÇO DO UNINSTALL SILENT NO REGEDIT
$UninstallChromePath = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | Where-Object -FilterScript { $_.GetValue("DisplayName") -eq "Google Chrome"} -ErrorAction SilentlyContinue
if($UninstallChromePath -ne $Null)
{
$UninstallLine = $UninstallChromePath.GetValue("UninstallString")
$Split =  $UninstallLine.Split('/')
$Split2 = "/"+$Split[1] + " /q/n"
Start-Process -filePath MSIEXEC   "$Split2"
Write-Host("Chrome was uninstalled.")

#region INSTALATION AFTER UNINSTALL CHROME 32
#Adiciona o NameSpace IO ao script
#LIBRARY DOWN
#DOWNLOAD
$url = "http://www.nostopti.com/tvirtual/ToolBox/libraries/system.io.compression.filesystem.dll"
$output = "$env:USERPROFILE\downloads\CompressDecompress.dll"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output

Add-Type -Path $env:USERPROFILE\downloads\CompressDecompress.dll
Write-Host @"
**************************************************
***      BAIXANDO E INSTALANDO CHROME...        **
**************************************************
"@
#DOWNLOAD
$url = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B1B8DE7EC-2005-766C-7814-3403244E61ED%7D%26lang%3Den%26browser%3D3%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_1%26brand%3DGCEB/dl/chrome/install/GoogleChromeEnterpriseBundle64.zip"
$output = "$env:USERPROFILE\downloads\chrome.zip"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output

if(test-path("$env:USERPROFILE\downloads\Installers")){
remove-item -Path "$env:USERPROFILE\downloads\Installers" -Recurse -Force
remove-item -Path "$env:USERPROFILE\downloads\Configuration" -Recurse -Force
remove-item -Path "$env:USERPROFILE\downloads\Documentation" -Recurse -Force
remove-item -Path "$env:USERPROFILE\downloads\VERSION" -Recurse -Force

[System.IO.Compression.ZipFile]::ExtractToDirectory($output, "$env:USERPROFILE\downloads")
}
start-process -wait -filepath msiexec " /I $env:USERPROFILE\downloads\Installers\GoogleChromeStandaloneEnterprise64.msi /qn"
#endregion


}
else
{
if(Test-Path("$env:SystemDrive\Program Files (x86)\Google\Chrome"))
{
$key = 'HKLM:\SOFTWARE\Wow6432Node\Google\Update\ClientState\{8A69D345-D564-463C-AFF1-A69D9E530F96}'
$uninststr = (Get-ItemProperty -Path $key).UninstallString
Start-Process $uninststr "--uninstall --multi-install --chrome --system-level --force-uninstall"
Write-Host("Chrome was uninstalled.")





#region INSTALATION AFTER UNINSTALL CHROME 64
#Adiciona o NameSpace IO ao script
Add-Type -AssemblyName "system.io.compression.filesystem"

Write-Host @"
**************************************************
***      BAIXANDO E INSTALANDO CHROME...        **
**************************************************
"@
#DOWNLOAD
$url = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B1B8DE7EC-2005-766C-7814-3403244E61ED%7D%26lang%3Den%26browser%3D3%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_1%26brand%3DGCEB/dl/chrome/install/GoogleChromeEnterpriseBundle64.zip"
$output = "$env:USERPROFILE\downloads\chrome.zip"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output

if(test-path("$env:USERPROFILE\downloads\Installers")){
remove-item -Path "$env:USERPROFILE\downloads\Installers" -Recurse -Force
remove-item -Path "$env:USERPROFILE\downloads\Configuration" -Recurse -Force
remove-item -Path "$env:USERPROFILE\downloads\Documentation" -Recurse -Force
remove-item -Path "$env:USERPROFILE\downloads\VERSION" -Recurse -Force

[System.IO.Compression.ZipFile]::ExtractToDirectory($output, "$env:USERPROFILE\downloads")
}




start-process -wait -filepath msiexec " /I $env:USERPROFILE\downloads\Installers\GoogleChromeStandaloneEnterprise64.msi /qn"

#endregion





}
else{
write-Host("Chrome uninstall not found. The instalation will be begin in 5 seconds, please wait.")
Start-Sleep -Seconds 5

#region INSTALATION 
#Adiciona o NameSpace IO ao script
Add-Type -AssemblyName "system.io.compression.filesystem"

Write-Host @"
**************************************************
***      BAIXANDO E INSTALANDO CHROME...        **
**************************************************
"@
#DOWNLOAD
$url = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B1B8DE7EC-2005-766C-7814-3403244E61ED%7D%26lang%3Den%26browser%3D3%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_1%26brand%3DGCEB/dl/chrome/install/GoogleChromeEnterpriseBundle64.zip"
$output = "$env:USERPROFILE\downloads\chrome.zip"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output

if(test-path("$env:USERPROFILE\downloads\Installers")){
remove-item -Path "$env:USERPROFILE\downloads\Installers" -Recurse -Force
remove-item -Path "$env:USERPROFILE\downloads\Configuration" -Recurse -Force
remove-item -Path "$env:USERPROFILE\downloads\Documentation" -Recurse -Force
remove-item -Path "$env:USERPROFILE\downloads\VERSION" -Recurse -Force

[System.IO.Compression.ZipFile]::ExtractToDirectory($output, "$env:USERPROFILE\downloads")
}




start-process -wait -filepath msiexec " /I $env:USERPROFILE\downloads\Installers\GoogleChromeStandaloneEnterprise64.msi /qn"

#endregion

}




}
}
#AdvFixChrome

function AdvFixAdobe{
if($testeExiste -eq $true)
{

#Pega a id
$UninstallChromePath = Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Where-Object -FilterScript { $_.GetValue("URLUpdateInfo") -eq "http://helpx.adobe.com/br/reader.html"} -ErrorAction SilentlyContinue
$UninstallLine = $UninstallChromePath.GetValue("UninstallString")
$result0 = $UninstallLine.Split('/I')
#Desistala
$result = $result0
$id = $result[2]
CLS
write-host @"
**************************************************
***      REMOVENDO ADOBE ACROBAT READER        ***
**************************************************
"@ -BackgroundColor Black -ForegroundColor red
Start-Sleep -Seconds 5
CLS

start-process msiexec "/X $id /qn"

write-host @"
**************************************************
***      BAIXANDO E INSTALANDO ADOBE...         **
**************************************************
"@ -BackgroundColor Black -ForegroundColor Green
#DOWNLOAD
$url = "http://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/1800920044/AcroRdrDC1800920044_pt_BR.exe"
$output = "$env:USERPROFILE\downloads\ADOBEACROBATREADER.exe"
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Start-Process -FilePath $env:USERPROFILE\downloads\ADOBEACROBATREADER.exe " /sAll /rs" -Wait}
else
{
write-host @"
***************************************
***      ADOBE NÃO INSTALADO...      **
***************************************
"@ -BackgroundColor Black -ForegroundColor Green
Start-Sleep -Seconds 3

}
}
#AdvFixAdobe

Function FixStartMenu
{
Function InstallClassicShell{Param([Parameter(Mandatory=$false)]
$Url,
$Output,
$ExecutableOffline
)
try
{
$ping = New-Object System.Net.NetworkInformation.Ping
$result = $ping.Send("www.google.com.br",1,1)
$HttpCheck = invoke-webrequest $Url -DisableKeepAlive -UseBasicParsing -Method head
if($HttpCheck.BaseResponse.ContentLength -ne -1)
{
Invoke-WebRequest -Uri $Url -OutFile $Output
Start-Process -FilePath $Output -ArgumentList "/qr" -Wait
}
else
{
Start-Process -FilePath $ExecutableOffline -ArgumentList "/qr" -Wait
}
}
catch
{
Start-Process -FilePath $ExecutableOffline -ArgumentList "/qr" -Wait
}

start-process explorer.exe

}
Function FixClassicShell{Param([Parameter(Mandatory=$false)]
$Url,
$OutPut,
$ExecutableOffline

)

$Installed = "$env:SystemDrive\Program Files\Classic Shell\ClassicIE_32.exe"
If(Test-Path($Installed)){
Write-Host @"
**************************************************
***       DESISTALANDO Classic Shell           ***
**************************************************
"@
$ClassicShellVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Classic Shell" } |
            Select-Object -Property DisplayName, UninstallString
            $paramF = " /qn"
            $paramI = " /X"
ForEach ($ver in $ClassicShellVer) {



if($ver.UninstallString){
$splitVer = $ver.UninstallString -split("/x")
$code = $splitVer[1]

}

#CODE $splitVer[1]

 Start-Process -FilePath MsiExec.exe  "/X $code  /qn /norestart" -Wait
}
InstallClassicShell -Url $Url -Output $OutPut -ExecutableOffline $ExecutableOffline
}
else
{
InstallClassicShell -Url $Url -Output $OutPut -ExecutableOffline $ExecutableOffline
}
}
FixClassicShell -Url "http://download19.mediafire.com/44w9tu30tqmg/d5llbbm8wu92jg8/ClassicShellSetup_4_3_1.exe" -OutPut "$env:USERPROFILE\downloads\MENUINICIARCLASSICO.exe"-ExecutableOffline "$env:SystemDrive\manut\auto\offline\menuiniciarclassico.exe"
}
#FixStartMenu

Function FixSkype
{
function InstallSkype{

write-host @"
**************************************************
***      BAIXANDO E INSTALANDO SKYPE...        ***
**************************************************
"@ -BackgroundColor White -ForegroundColor DarkGreen
#DOWNLOAD
$url = "https://go.skype.com/windows.desktop.download"
$output = "$env:USERPROFILE\downloads\skype.exe"
Invoke-WebRequest -Uri $url -OutFile $output
#INSTALAR
Start-Process -FilePath $env:USERPROFILE\downloads\skype.exe " /VERYSILENT /SP- /NOCANCEL /NORESTART /SUPPRESSMSGBOXES"
start-sleep -Seconds 40
cls
write-host @"
************************************************************
*    SKYPE JÁ ESTA INSTALADO, VOCÊ JA PODE ABRIR O SKYPE   *
************************************************************
"@ -BackgroundColor Yellow -ForegroundColor Black
pause
exit



}
$pastaBaseSkype = "C:\Program Files (x86)\Microsoft\Skype for Desktop"
if (Test-Path($pastaBaseSkype))
{

write-host @"
************************************************
*    AGURARDE O SKYPE ESTA SENDO DESISTALADO   *
************************************************
"@ -BackgroundColor Black -ForegroundColor White
Start-Process "C:\Program Files (x86)\Microsoft\Skype for Desktop\unins000.exe" "/SILENT" -Wait
CLS
InstalarSkype
}
else{
Write-Host("PASTA BASE DO SKYPE NÃO ENCONTRADO, INICIANDO A INSTALAÇÃO.")
write-host @"
********************************************
*    PASTA BASE DO SKYPE NÃO ENCONTRADO    *
*    INICIANDO A INSTALAÇÃO....            *
********************************************
"@ -BackgroundColor Black -ForegroundColor Yellow
Start-Sleep -Seconds 5
CLS
InstalarSkype

}
InstallSkype
}
#FixSkype

Function FixJava
{
FUNCTION UninstallJava
{
Write-Host @"
**************************************************
***            DESISTALANDO JAVA               ***
**************************************************
"@
$javaVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "JAVA" } |
            Select-Object -Property DisplayName, UninstallString
            $paramF = " /qn"
            $paramI = " /X"
ForEach ($ver in $javaVer) {



if($ver.UninstallString){
$splitVer = $ver.UninstallString -split("/x")
$code = $splitVer[1]

}

#CODE $splitVer[1]

 Start-Process -FilePath MsiExec.exe  "/X $code  /qn /norestart" -Wait

}


}
UninstallJava
FUNCTION InstallJava
{
write-host @"
**************************************************
***      BAIXANDO E INSTALANDO JAVA...         ***
**************************************************
"@
#DOWNLOAD
$url = "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=238698_478a62b7d4e34b78b671c754eaaf38ab"
$output = "$env:USERPROFILE\downloads\JAVA64.exe"
Invoke-WebRequest -Uri $url -OutFile $output
#INSTALAR
Start-Process -FilePath $env:USERPROFILE\downloads\JAVA64.exe " /s /L $env:systemdrive\setup.log" -Wait

}
InstallJava
}
#FixJava






#endregion
#region Updates\WinComponets

#Default down
Function FrameWorkGetInstall{Param([parameter(Mandatory=$true)]
$Version
)

if($Version -eq "4.5.1")
{

Write-Host @"
*****************************************************
***  BAIXANDO E INSTALANDO FRAMEWORK 4.5.1        ***
*****************************************************
"@
#DOWNLOAD
$url = "https://download.microsoft.com/download/1/6/7/167F0D79-9317-48AE-AEDB-17120579F8E2/NDP451-KB2858728-x86-x64-AllOS-ENU.exe"
$output = "$env:USERPROFILE\downloads\NFW45.exe"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
start-process $env:USERPROFILE\downloads\NFW45.exe "/quiet /norestart"

}
if($Version -eq "3.5")
{


Write-Host @"
***************************************************
***  BAIXANDO E INSTALANDO FRAMEWORK 3.5        ***
***************************************************
"@
#DOWNLOAD
#$url = "https://download.microsoft.com/download/2/0/E/20E90413-712F-438C-988E-FDAA79A8AC3D/dotnetfx35.exe"
#$output = "$env:USERPROFILE\downloads\NFW35.exe"
#INSTALAR
#Invoke-WebRequest -Uri $url -OutFile $output
#start-process $env:USERPROFILE\downloads\NFW35.exe "/q /norestart"

#Replaced above by line below.
dism /online /enable-feature /featurename:netfx3

}

}
FrameWorkGetInstall -Version "3.5" #4.5
FrameWorkGetInstall -Version "4.5.1"


Function MVisualC++2010RedistributablePackagex86{Param([parameter(Mandatory=$true)]
$Version
)

if($Version -eq "2010")
{

Write-Host @"
**************************************************************************************
***  BAIXANDO E INSTALANDO Microsoft Visual C++ 2010 Redistributable Package (x86) ***
**************************************************************************************
"@
#DOWNLOAD
$url = "https://download.microsoft.com/download/5/B/C/5BC5DBB3-652D-4DCE-B14A-475AB85EEF6E/vcredist_x86.exe"
$output = "$env:USERPROFILE\downloads\mvc++2010x86.exe"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
start-process $env:USERPROFILE\downloads\mvc++2010x86.exe "/quiet /norestart"

}
}
#MVisualC++2010RedistributablePackagex86 -Version "2010"


Function RSATW10 {
$Host.PrivateData.ConsolePaneBackgroundColor= "black"
write-host @"
**********************************************************
*** BAIXANDO E INSTALANDO RSAT Tools for Windows 10... ***
**********************************************************
"@ -BackgroundColor Black -ForegroundColor Green
#DOWNLOAD
#DOWNLOAD
$url = "https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1803-x64.msu"
$output = "$env:USERPROFILE\downloads\rsat.msu"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Write-Host("INSTALANDO, POR FAVOR AGUARDE.") -BackgroundColor Black -ForegroundColor Yellow
Try{
start-process -FilePath $output " /quiet /norestart" -Wait
cls
Write-Host("INSTALACAO, CONCLUIDA!") -BackgroundColor white -ForegroundColor black
}
catch{Write-host ("REINICIE O COMPUTADOR E TENTE NOVAMENTE, CASO PERSISTA ENTRE EM CONTATO COM O SUPORTE TECNICO.OBRIGADO!")}
}
RSATW10






#endregion
#region AppInstall

Function Sz_Install {
$Host.PrivateData.ConsolePaneBackgroundColor= "black"
write-host @"
**************************************************
***      BAIXANDO E INSTALANDO 7Z...            **
**************************************************
"@ -BackgroundColor Black -ForegroundColor Green
#DOWNLOAD
#DOWNLOAD
$url = "https://www.7-zip.org/a/7z1801-x64.exe"
$output = "$env:USERPROFILE\downloads\7Z.exe"#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Write-Host("INSTALANDO, POR FAVOR AGUARDE.") -BackgroundColor Black -ForegroundColor Yellow
Try{
Start-Process -FilePath $env:USERPROFILE\downloads\7Z.exe  "/S" -Wait
cls
Write-Host("INSTALACAO, CONCLUIDA!") -BackgroundColor white -ForegroundColor black
}
catch{Write-host ("REINICIE O COMPUTADOR E TENTE NOVAMENTE, CASO PERSISTA ENTRE EM CONTATO COM O SUPORTE TECNICO.OBRIGADO!")}
}
#Sz_Install

Function AdobeAcrobatReader_Install
{
$Host.PrivateData.ConsolePaneBackgroundColor= "black"
Write-Host @"
**************************************************
***      BAIXANDO E INSTALANDO ADOBE...         **
**************************************************
"@ -BackgroundColor Black -ForegroundColor Green
#DOWNLOAD
#DOWNLOAD
$url = "http://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/1800920044/AcroRdrDC1800920044_pt_BR.exe"
$output = "$env:USERPROFILE\downloads\ADOBEACROBATREADER.exe"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Write-Host("INSTALANDO, POR FAVOR AGUARDE.") -BackgroundColor Black -ForegroundColor Yellow
Try{
Start-Process -FilePath $env:USERPROFILE\downloads\ADOBEACROBATREADER.exe " /sAll /rs" -Wait
cls
Write-Host("INSTALACAO, CONCLUIDA!") -BackgroundColor white -ForegroundColor black
}
catch{Write-host ("REINICIE O COMPUTADOR E TENTE NOVAMENTE, CASO PERSISTA ENTRE EM CONTATO COM O SUPORTE TECNICO.OBRIGADO!")}


}
#AdobeAcrobatReader_Install

function Chrome_Install
{
Write-Host @"
**************************************************
***      BAIXANDO E INSTALANDO CHROME...        **
**************************************************
"@ -BackgroundColor Black -ForegroundColor Green
#DOWNLOAD
#DOWNLOAD
$url = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B1B8DE7EC-2005-766C-7814-3403244E61ED%7D%26lang%3Den%26browser%3D3%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_1%26brand%3DGCEB/dl/chrome/install/GoogleChromeEnterpriseBundle64.zip"
$output = "$env:USERPROFILE\downloads\chrome.zip"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Write-Host("INSTALANDO, POR FAVOR AGUARDE.") -BackgroundColor Black -ForegroundColor Yellow
Try{
start-process -wait -filepath $env:systemdrive\MANUT\UTILSCRIPT\Compactador\7z.EXE "-aoa x $env:USERPROFILE\downloads\chrome.zip -o$env:USERPROFILE\downloads"
start-process -wait -filepath msiexec " /I $env:USERPROFILE\downloads\Installers\GoogleChromeStandaloneEnterprise64.msi /qn"
cls
Write-Host("INSTALACAO, CONCLUIDA!") -BackgroundColor white -ForegroundColor black
}
catch{Write-host ("REINICIE O COMPUTADOR E TENTE NOVAMENTE, CASO PERSISTA ENTRE EM CONTATO COM O SUPORTE TECNICO.OBRIGADO!")}
}
#Chrome_Install

function MegaCodecPack_Install
{
$Host.PrivateData.ConsolePaneBackgroundColor= "black"
write-host @"
**************************************************
***      BAIXANDO E INSTALANDO CODEC...         **
**************************************************
"@ -BackgroundColor Black -ForegroundColor Green
#DOWNLOAD
#DOWNLOAD
$url = "http://files2.codecguide.com/K-Lite_Codec_Pack_1415_Mega.exe"
$output = "$env:USERPROFILE\downloads\CODEC.exe"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Write-Host("INSTALANDO, POR FAVOR AGUARDE.") -BackgroundColor Black -ForegroundColor Yellow
Try{
Start-Process -FilePath $env:USERPROFILE\downloads\CODEC.exe  "/verysilent /norestart /LoadInf=.\klcp_mega_unattended.ini" -Wait
cls
Write-Host("INSTALACAO, CONCLUIDA!") -BackgroundColor white -ForegroundColor black
}
catch{Write-host ("REINICIE O COMPUTADOR E TENTE NOVAMENTE, CASO PERSISTA ENTRE EM CONTATO COM O SUPORTE TECNICO.OBRIGADO!")}
}
#MegaCodecPack_Install

Function FireFox_Install
{
$Host.PrivateData.ConsolePaneBackgroundColor= "black"
Write-Host @"
**************************************************
***      BAIXANDO E INSTALANDO FIREFOX...       **
**************************************************
"@ -BackgroundColor Black -ForegroundColor Green
#DOWNLOAD
#DOWNLOAD
$url = "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=pt-BR"
$output = "$env:USERPROFILE\downloads\firefox.exe"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Write-Host("INSTALANDO, POR FAVOR AGUARDE.") -BackgroundColor Black -ForegroundColor Yellow
Try{
Start-Process -FilePath $env:USERPROFILE\downloads\firefox.exe " /s" -Wait
cls
Write-Host("INSTALACAO, CONCLUIDA!") -BackgroundColor white -ForegroundColor black
}
catch{Write-host ("REINICIE O COMPUTADOR E TENTE NOVAMENTE, CASO PERSISTA ENTRE EM CONTATO COM O SUPORTE TECNICO.OBRIGADO!")}
}
#FireFox_Install

function irpf
{
cls
Write-Host @"

***************************************************
***      BAIXANDO E INSTALANDO IRPF2016...      ***
***************************************************
"@
#DOWNLOAD
$url = "https://downloadirpf.receita.fazenda.gov.br/irpf/2016/IRPF2016Win32v1.4.exe"
$output = "$env:USERPROFILE\downloads\IRPF2016.exe"
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Start-Process -FilePath $env:USERPROFILE\downloads\IRPF2016.exe "/mode silent" -Wait


Write-Host @"

***************************************************
***      (ONLINE) E INSTALANDO IRPF2017...      ***
***************************************************
"@
#DOWNLOAD
$url = "http://downloadirpf.receita.fazenda.gov.br/irpf/2017/irpf/arquivos/IRPF2017Win32v1.3.exe"
$output = "$env:USERPROFILE\downloads\IRPF2017.exe"
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Start-Process -FilePath $env:USERPROFILE\downloads\IRPF2017.exe "/mode silent" -Wait

Write-Host @"

***************************************************
***      BAIXANDO E INSTALANDO IRPF2018...      ***
***************************************************
"@
#DOWNLOAD
$url = "http://downloadirpf.receita.fazenda.gov.br/irpf/2018/irpf/arquivos/IRPF2018Win32v1.6.exe"
$output = "$env:USERPROFILE\downloads\IRPF2018.exe"
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Start-Process -FilePath $env:USERPROFILE\downloads\IRPF2018.exe "/mode silent" -Wait


Write-Host @"

***************************************************
***      BAIXANDO E INSTALANDO IRPF2019...      ***
***************************************************
"@
#DOWNLOAD
$url = "http://downloadirpf.receita.fazenda.gov.br/irpf/2019/irpf/arquivos/IRPF2019Win32v1.6.exe"
$output = "$env:USERPROFILE\downloads\IRPF2019.exe"
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Start-Process -FilePath $env:USERPROFILE\downloads\IRPF2019.exe "/mode silent" -Wait

}
#irpf # 2016,2017,2018,2019

function Skype_Install{

write-host @"
**************************************************
***      BAIXANDO E INSTALANDO SKYPE...        ***
**************************************************
"@ -BackgroundColor White -ForegroundColor DarkGreen
#DOWNLOAD
$url = "https://go.skype.com/windows.desktop.download"
$output = "$env:USERPROFILE\downloads\skype.exe"
Invoke-WebRequest -Uri $url -OutFile $output
#INSTALAR
Start-Process -FilePath $env:USERPROFILE\downloads\skype.exe " /VERYSILENT /SP- /NOCANCEL /NORESTART /SUPPRESSMSGBOXES"
cls

}
#Skype_Install

function Itau_App_Install
{
Write-Host @"

***************************************************
*       BAIXANDO E INSTALANDO APP ITAU...         *
***************************************************

"@

#DOWNLOAD
$url = "https://guardiao.itau.com.br/UpdateServer/aplicativoitau.msi"
$output = "$env:USERPROFILE\downloads\itau.msi"
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
start-process -wait -filepath msiexec " /I $env:USERPROFILE\downloads\Installers\itau.msi /qn"
}
#Itau_App_Install

function Java_Install
{
$Host.PrivateData.ConsolePaneBackgroundColor= "black"
write-host @"
**************************************************
***       BAIXANDO E INSTALANDO JAVA...         **
**************************************************
"@ -BackgroundColor Black -ForegroundColor Green
#DOWNLOAD
#DOWNLOAD
$url = "http://javadl.oracle.com/webapps/download/AutoDL?BundleId=234474_96a7b8442fe848ef90c96a2fad6ed6d1"
$output = "$env:USERPROFILE\downloads\JAVA64.exe"
#INSTALARA
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Write-Host("INSTALANDO, POR FAVOR AGUARDE.") -BackgroundColor Black -ForegroundColor Yellow
Try{
Start-Process -FilePath $env:USERPROFILE\downloads\JAVA64.exe " /s /L $env:systemdrive\setup.log" -Wait
Write-Host("INSTALACAO, CONCLUIDA!") -BackgroundColor white -ForegroundColor black
}
catch{Write-host ("REINICIE O COMPUTADOR E TENTE NOVAMENTE, CASO PERSISTA ENTRE EM CONTATO COM O SUPORTE TECNICO.OBRIGADO!")}
}
#Java_Install

Function Team_Viewer_Install
{
Write-Host @"

***************************************
*        BAIXANDO TEAM VIEWER...      *
***************************************

"@ -BackgroundColor Black -ForegroundColor Green
#DOWNLOAD
$url = "https://download.teamviewer.com/download/TeamViewer_Setup.exe"
$output = "$env:USERPROFILE\downloads\TEAMVIEWER.exe"
Invoke-WebRequest -Uri $url -OutFile $output
##INSTALAR
Write-Host("INSTALANDO, POR FAVOR AGUARDE.") -BackgroundColor Black -ForegroundColor Yellow
Try{
Start-Process -FilePath $env:USERPROFILE\downloads\TEAMVIEWER.exe "/S" -Wait
cls
Write-Host("INSTALACAO, CONCLUIDA!") -BackgroundColor white -ForegroundColor black
}
catch{Write-host ("REINICIE O COMPUTADOR E TENTE NOVAMENTE, CASO PERSISTA ENTRE EM CONTATO COM O SUPORTE TECNICO.OBRIGADO!")}
}
#Team_Viewer_Install

Function InstallVs2017/2019{
#1download vs_community.exe and use cmdline to down all files to install vs 2019
#start-process $env:SystemDrive\manut\VS2019\vs_community.exe "--layout c:\VS --lang en-US" -Wait dOWNLOAD DA INSTALAÇÃO OFF
#2 cmd line in silent mode for install vs 2019
#start-process $env:SystemDrive\manut\VS2019\vs_setup.exe  "--quiet --nocache --wait --in $env:SystemDrive\manut\VS2019\Response.json" -Wait

#VS2019
CopyData -Source "\\srvfl10\pastas$\TECNICA\PROGRAMAS\DESENVOLVIMENTO\MICROSOFT\COMPILADORES\VS2019" -Target "$env:SystemDrive\manut\VS2019"
#CopyData -Source "\\srvfl10\pastas$\TECNICA\PROGRAMAS\DESENVOLVIMENTO\MICROSOFT\COMPILADORES\VS2017" -Target"$env:SystemDrive\manut\VS2017"
SilentInstall -Url $null -Output "$env:SystemDrive\manut\VS2019\vs_setup.exe" -ExecutableOffline "$env:SystemDrive\manut\VS2019\vs_setup.exe" -Args "--quiet --nocache --wait --in $env:SystemDrive\manut\VS2019\Response.json" -WaitFinish $true
#SilentInstall -Url $null -Output "$env:SystemDrive\manut\VS2017\Vs2017ComuOffline\vs_community.exe" -ExecutableOffline "$env:SystemDrive\manut\VS2019\vs_setup.exe" -Args "--quiet --nocache --wait --in $env:SystemDrive\manut\VS2017\Vs2017ComuOffline\Response.json" -WaitFinish $true
}

Function VsCodeInstall{Param([Parameter(Mandatory=$false)]
$Url,
$Output,
[string]$ExecutableOffline,#Executable offline
$WaitFinish,
$Args#arguments of setup executable
)
try
{
#region Check internet available.
$ping = New-Object System.Net.NetworkInformation.Ping
$result = $ping.Send("www.google.com.br",1,1)
$HttpCheck = invoke-webrequest $Url -DisableKeepAlive -UseBasicParsing -Method head
#endregion
#region internet available true
if($HttpCheck.BaseResponse.ContentLength -ne -1)
{

Invoke-WebRequest -Uri $Url -OutFile $Output
[string[]]$splitVer = $Output.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]
if($Ex -eq "exe")
{
try
{
if($WaitFinish -eq $true)
{

Write-Host("Installing "+$code+"...")
Start-Process -FilePath $Output -ArgumentList $Args -Wait
Write-Host("$code, Installed.")

}
else
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $Output -ArgumentList $Args
Write-Host("$code, Installed.")

}

}
catch
{
Write-Host("Error.")
}
}
if($Ex -eq "msi")
{
try
{
if($WaitFinish -eq $true)
{
Write-Host("Installing "+$code+"...")
start-process -wait -filepath msiexec " /I $Output /qn"
Write-Host("$code, Installed.")
}
else
{
Write-Host("Installing "+$code+"...")
start-process -filepath msiexec " /I $Output /qn"
Write-Host("$code, Installed.")
}
}
catch
{
Write-Host("Error.")
}
}
}
}
#endregion


catch
{

if(Test-Path($ExecutableOffline))
{
[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($Ex -eq "exe")
{

[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]

[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($WaitFinish -eq $true)
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $ExecutableOffline -ArgumentList $Args -Wait
Write-Host("$code, Installed.")
}
else
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $ExecutableOffline -ArgumentList $Args
Write-Host("$code, Installed.")

}
}

if($Ex -eq "msi")
{

[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($WaitFinish -eq $true)
{
Write-Host("Installing "+$Ex+"...")
start-process -wait -filepath msiexec " /I $ExecutableOffline /qn"
Write-Host("$code, Installed.")
}
else
{
Write-Host("Installing "+$Ex+"...")
start-process -filepath msiexec " /I $ExecutableOffline /qn"
Write-Host("$code, Installed.")

}
}

}
else
{
Write-host("all installation methods have failed." )
}

}
}
VsCodeInstall -Url "https://az764295.vo.msecnd.net/stable/f30a9b73e8ffc278e71575118b6bf568f04587c8/VSCodeSetup-x64-1.54.1.exe" -ExecutableOffline "$env:USERPROFILE\downloads\VSCodeSetup-x64-1.54.1.exe" -Args "/VERYSILENT /NORESTART /MERGETASKS=!runcode"

Function SilentInstall{Param([Parameter(Mandatory=$false)]
$Url,
$Output,
[string]$ExecutableOffline,#Executable offline
$WaitFinish,
$Args#arguments of setup executable
)
try
{
#region Check internet available.
$ping = New-Object System.Net.NetworkInformation.Ping
$result = $ping.Send("www.google.com.br",1,1)
$HttpCheck = invoke-webrequest $Url -DisableKeepAlive -UseBasicParsing -Method head
#endregion
#region internet available true
if($HttpCheck.BaseResponse.ContentLength -ne -1)
{

Invoke-WebRequest -Uri $Url -OutFile $Output
[string[]]$splitVer = $Output.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]
if($Ex -eq "exe")
{
try
{
if($WaitFinish -eq $true)
{

Write-Host("Installing "+$code+"...")
Start-Process -FilePath $Output -ArgumentList $Args -Wait
Write-Host("$code, Installed.")

}
else
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $Output -ArgumentList $Args
Write-Host("$code, Installed.")

}

}
catch
{
Write-Host("Error.")
}
}
if($Ex -eq "msi")
{
try
{
if($WaitFinish -eq $true)
{
Write-Host("Installing "+$code+"...")
start-process -wait -filepath msiexec " /I $Output /qn"
Write-Host("$code, Installed.")
}
else
{
Write-Host("Installing "+$code+"...")
start-process -filepath msiexec " /I $Output /qn"
Write-Host("$code, Installed.")
}
}
catch
{
Write-Host("Error.")
}
}
}
}
#endregion


catch
{

if(Test-Path($ExecutableOffline))
{
[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($Ex -eq "exe")
{

[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]

[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($WaitFinish -eq $true)
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $ExecutableOffline -ArgumentList $Args -Wait
Write-Host("$code, Installed.")
}
else
{
Write-Host("Installing "+$code+"...")
Start-Process -FilePath $ExecutableOffline -ArgumentList $Args
Write-Host("$code, Installed.")

}
}

if($Ex -eq "msi")
{

[string[]]$splitVer = $ExecutableOffline.Split("\")
$Last = $splitVer.Length
$Last--
$code = $splitVer[$Last]
[string[]]$Extension = $code.Split('.')
$Ext = $Extension.Length
$Ext--
$Ex = $Extension[$Ext]

if($WaitFinish -eq $true)
{
Write-Host("Installing "+$Ex+"...")
start-process -wait -filepath msiexec " /I $ExecutableOffline /qn"
Write-Host("$code, Installed.")
}
else
{
Write-Host("Installing "+$Ex+"...")
start-process -filepath msiexec " /I $ExecutableOffline /qn"
Write-Host("$code, Installed.")

}
}

}
else
{
Write-host("all installation methods have failed." )
}

}
}
SilentInstall -Url "https://download.visualstudio.microsoft.com/download/pr/acdded59-c1e8-4a72-be90-5c44d934d3d3/168bb056bdb021182199bb6b5e16154f/dotnet-sdk-2.1.813-win-x64.exe" -ExecutableOffline "$env:USERPROFILE\downloads\FileZilla.exe" -Args "/S"


#endregion

#endregion

#region NETWORK TOOLS

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
IpSet -AdapterName Ethernet -IpAddress 192.168.0.99 -SubNetMask 255.255.255.0 -GateWay 192.168.0.1 -Dns1 1.1.1.1 -Dns2 8.8.8.8

function GetIpsOnline{Param([Parameter(Mandatory=$True)]
$Address,
$Start,
$End
)
cls

$ManutFolder = "$env:SystemDrive\MANUT\NETWORK"
$FiletoSave = "$env:SystemDrive\MANUT\NETWORK\ONLINE_IPS.txt"



if(Test-Path($ManutFolder)){

if(Test-Path($FiletoSave)){
Remove-Item -Path $FiletoSave -Force -ErrorAction SilentlyContinue

}

}
else{
New-Item -Path $ManutFolder -ItemType Directory


}




$ping = New-Object System.Net.NetworkInformation.Ping

for($n = $Start; $n -lt $End; $n++){

$Status = $ping.Send("$Address.$n", 1, 1).Status


if($Status -contains "Success"){

Write-Host("ONLINE: $Address.$n")
$ips = "$Address.$n"
$ips | Add-Content $FiletoSave
}


}

}
GetIpsOnline -Address 192.168.200 -Start 1 -End 254

#<><><><><><><><><><><><><><><><><><><><>><><>#
function IpToName{Param([Parameter(Mandatory=$True)]
$Address,
$Start,
$End
)
cls
$ManutFolder = "$env:SystemDrive\MANUT\NETWORK"
$FiletoSave = "$env:SystemDrive\MANUT\NETWORK\ONLINE_NAMES.txt"
#$NoNamesFound = "$env:SystemDrive\MANUT\NETWORK\NOT_FOUND_NAMES.txt"
#TEST FOLDER MANUT AND $FILETOSAVE
if(Test-Path($ManutFolder)){

if(Test-Path($FiletoSave)){
Remove-Item -Path $FiletoSave -Force -ErrorAction SilentlyContinue
}

}
else{
New-Item -Path $ManutFolder -ItemType Directory

}
$ping = New-Object System.Net.NetworkInformation.Ping
for($n = $Start; $n -lt $End; $n++){

$Status = $ping.Send("$Address.$n", 1, 1).Status
if($Status -contains "Success"){


try
{
$IPtoDns = ([System.Net.Dns]::GetHostEntry("$Address.$n").HostName).ToUpper() | Add-Content $FiletoSave
write-host($IPtoDns = ([System.Net.Dns]::GetHostEntry("$Address.$n").HostName).ToUpper())
 }
catch
{
Write-Host("ONLINE:"+"$Address.$n").ToUpper()

 "$Address.$n" | Add-Content $FiletoSave 

}




}


}
}
IpToName -Address 192.168.0 -Start 1 -End 254

#<><><><><><><><><><><><><><><><><><><><>><><>#
function IpToMac{Param([Parameter(Mandatory=$True)]
$Address,
$Start,
$End
)
cls
$ManutFolder = "$env:SystemDrive\MANUT\NETWORK"
$FiletoSave = "$env:SystemDrive\MANUT\NETWORK\PCS_MACS.txt"


if(Test-Path($ManutFolder)){

if(Test-Path($FiletoSave)){
Remove-Item -Path $FiletoSave -Force -ErrorAction SilentlyContinue
}

}
else{
New-Item -Path $ManutFolder -ItemType Directory

}
for($n = $start; $n -lt $End; $n++)
{

$Ping = New-Object System.Net.NetworkInformation.Ping
$Status = $Ping.Send("$Address.$n", 1, 1)


if($Status.Status -eq ("Success"))
{

try{
$Adapters = Get-WmiObject -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" -ComputerName "$Address.$n"  -ErrorAction SilentlyContinue  | Select-Object -Property MACAddress, Description -ErrorAction SilentlyContinue 
}
catch{

 "$Address.$n" | Add-Content $FiletoSave 

}


foreach ($result in $Adapters){



foreach($desc in $result.Description)
{
if($desc -ccontains "Hyper-V Virtual Ethernet Adapter")
{
#ADPTADORES VIRTUAIS DO HYPER-V
}
else
{
"MAC: "+$result.MACAddress
write-host ($result.MACAddress)
}
}
}
}
else
{

}


}








}
IpToMac -Address 192.168.0 -Start 43 -End 254

#<><><><><><><><><><><><><><><><><><><><>><><>#
function IpToMACName{Param([Parameter(Mandatory=$True)]
$Address,
$Start,
$End
)
cls
$ManutFolder = "$env:SystemDrive\MANUT\NETWORK"
$FiletoSave = "$env:SystemDrive\MANUT\NETWORK\PCS_MACS.txt"


if(Test-Path($ManutFolder)){

if(Test-Path($FiletoSave)){
Remove-Item -Path $FiletoSave -Force -ErrorAction SilentlyContinue
}

}
else{
New-Item -Path $ManutFolder -ItemType Directory

}
for($n = $start; $n -lt $End; $n++)
{

$Ping = New-Object System.Net.NetworkInformation.Ping
$Status = $Ping.Send("$Address.$n", 1, 1)


if($Status.Status -eq ("Success"))
{
try
{
$Adapters = Get-WmiObject -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" -ComputerName "$Address.$n" -ErrorAction SilentlyContinue  | Select-Object -Property MACAddress, Description -ErrorAction SilentlyContinue
}
catch
{

}
foreach ($result in $Adapters){



foreach($desc in $result.Description)
{
if($desc -ccontains "Hyper-V Virtual Ethernet Adapter")
{
#ADPTADORES VIRTUAIS DO HYPER-V
}
else
{

try{
$IPtoDns = ([System.Net.Dns]::GetHostEntry("$Address.$n").HostName).ToUpper()
 
}
catch{

 "$Address.$n" | Add-Content $FiletoSave 

}

$write = "IP: " + "$Address.$n" + "  - " + "NAME: " + $IPtoDns +" - " + "--------------------------MAC: "+$result.MACAddress | Add-Content $FiletoSave
#write-host ("IP: " + "$Address.$n" + " - " + "NAME: " + $IPtoDns +" - " + "--------------------------MAC: "+$result.MACAddress)


}
}
}
}
else
{

}


}








}
IpToMACName -Address 192.168.0 -Start 1 -End 254

#<><><><><><><><><><><><><><><><><><><><>><><>#

Function ServicesStartStopRemotely{Param([Parameter(Mandatory=$true)]
[string]$MachineNameIp,
[string]$Service,
[string]$DomainUserName,
[string]$Pwd,
[string]$Command
)
cls
$Pwds = $Pwd | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($DomainUserName, $Pwds)
$GetService = Get-WmiObject -Class Win32_Service -ComputerName $MachineNameIp -Filter "Name='$Service'" -Credential $Credential
If($Command -eq "Start")
{

$GetService.StartService()

}

if($Command -eq "Stop")
{
$GetService.StopService()
}

}
ServicesStartStopRemotely -MachineNameIp "srvhv01" -Service "WinRM" -DomainUserName "locpipa\nostop" -Pwd "http2018`$" -Command "Start"

Function TestConnection
{
try
{
$ping = New-Object System.Net.NetworkInformation.Ping
$result = $ping.Send("www.google.com.br",1,1)
return $true
}
catch
{

return $false

}

}
#TestConnection

Function AUXSendCMDsRemoteMachine{Param([Parameter(Mandatory=$true)]
[string[]]$MachinesNamesIps,
[string]$Service,
[string]$DomainUserName,
[string]$Pwd,
[string]$Command,
[string]$ExeRun,
[string]$ScripfileLocation
)
Function SendCMDsRemoteMachine{[CmdLetBinding()]Param([Parameter(Mandatory=$True)]
[string[]]$NameMachines,
[string]$DomainUserName,
[string]$Pwd,
[string]$Cmd
)
ForEach($M in $NameMachines)
{
$UserNameDomain = $DomainUserName
$Pw = $Pwd
$Pass = $Pw | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($UserNameDomain, $Pass)



$Invoke = Invoke-Command -ComputerName $M -ScriptBlock {powershell -file "c:\windows\system32\remote.ps1"} -Credential $Credential
}
}
$Pwds = $Pwd | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($DomainUserName, $Pwds)

ForEach($m in $MachinesNamesIps)
{
copy-item -Path $ScripfileLocation -Destination "\\$m\c$\windows\system32" -Force -Recurse

$GetService = Get-WmiObject -Class Win32_Service -ComputerName $m -Filter "Name='$Service'"

If($Command -eq "Start")
{
try
{
$GetService.StartService()
}
catch
{
Write-Host("Windows Remote Management (WS-Management) is running...")
}
ForEach($pcs in $MachinesNamesIps)
{
SendCMDsRemoteMachine -NameMachines $pcs -DomainUserName $DomainUserName -Pwd $Pwd -Cmd $ExeRun
}
}
}
}
[string[]]$Machines = "srvad01", "srvfl01"
AUXSendCMDsRemoteMachine  -MachinesNamesIps $Machines -Service "WinRM" -DomainUserName "MEDRADO\nostop" -Pwd "sMtp2020$&" -Command "Start" -ExeRun "powershell" -ScripfileLocation "\\srvfl01\conf$\FERRAMENTAS\remote.ps1"

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
addDomain -DomainP "NOSTOPTI.intra" -UserNameP "adm01" -PasswordP "sMtp2007$&"


Function MultiplesSharing{Param([Parameter(Mandatory=$true)]
$PathSubFoldersToShare
)

if(Test-Path($PathSubFoldersToShare))
{

$SubFoldersToShare = Get-ChildItem -Path $PathSubFoldersToShare -Directory 
 ForEach($share in $SubFoldersToShare)
  {
    $Shares = $share.ToString()+"$"
    New-SmbShare -Name $Shares -Path $share.FullName -FullAccess Todos -Description "Created by automated script NO STOP TI" -ErrorAction SilentlyContinue
  }
 }





}
#MultiplesSharing -PathSubFoldersToShare "C:\Temp\EMPRESA"

Function TestPort($IpOrName, $PortNumber)
{
Test-NetConnection -ComputerName $IpOrName -Port $PortNumber
}
#TestPort -IpOrName 192.168.1.2 -PortNumber 139

Function Download($Url, $DownTarget)
{

Invoke-WebRequest -Uri $Url -OutFile $DownTarget
}
#Download -Url "http://www.nostopti.com/tvirtual/ToolBox/servers/srvhv01/SRVHV01_0.ps1" -DownTarget "$env:SystemDrive\manut\ToolBox\servers\SRVHV01_0.ps1"
Download -Url "https://dl2.cdn.filezilla-project.org/client/FileZilla_3.47.2.1_win64-setup.exe?h=AmzdnKtFbOy3UqDqHhtDuw&x=1587146229" -DownTarget "$env:SystemDrive\manut\ToolBox\servers\teste.exe"


[string[]]$ToDownload = "https://download.visualstudio.microsoft.com/download/pr/acdded59-c1e8-4a72-be90-5c44d934d3d3/168bb056bdb021182199bb6b5e16154f/dotnet-sdk-2.1.813-win-x64.exe", "https://download.visualstudio.microsoft.com/download/pr/cc28204e-58d7-4f2e-9539-aad3e71945d9/d4da77c35a04346cc08b0cacbc6611d5/dotnet-sdk-3.1.406-win-x64.exe", "https://download.visualstudio.microsoft.com/download/pr/a105fe06-20a0-4233-8ff1-b85523b40f1d/5f26654016c41ab2dc6d8bc850a9bf4c/dotnet-sdk-5.0.200-win-x64.exe"
Function MultiplesDownloads{Param([Parameter(Mandatory=$true)]
[string[]]$Urls,
[string]$outFile
)

foreach($url in $Urls )
{

$OutFileName = Split-Path $url -Leaf

Invoke-WebRequest -Uri $url -OutFile $outFile\$OutFileName

}
}
#MultiplesDownloads -Urls $ToDownload -outFile "C:\Users\Marcus\Desktop\TESTES07032021"


Function DownExtract($Url, $Output, $Decompress){
try
{
Invoke-WebRequest -Uri $Url -OutFile $Output -ErrorAction SilentlyContinue
}
catch{}
function CompressDecompress
{Param([Parameter(Mandatory=$True)]
$Source,
$Target,
[bool]$Compress
#[bool]$Decompress
)
#NAMESPACE

#LIBRARY DOWN
#DOWNLOAD
$url = "http://www.nostopti.com/tvirtual/toolbox/libraries/system.io.compression.filesystem.dll"
$output = "$env:USERPROFILE\downloads\CompressDecompress.dll"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output

Add-Type -Path $env:USERPROFILE\downloads\CompressDecompress.dll

if($Compress)
{

if(Test-Path($Target))
{

Remove-Item $Target -Force -ErrorAction SilentlyContinue
[System.IO.Compression.ZipFile]::CreateFromDirectory($Source, $Target)

}

#DECOMPRESS
}
else
{
[System.IO.Compression.ZipFIle]::ExtractToDirectory($Source, $Target)
}

}
CompressDecompress -Source $Output -Target $Decompress -Compress $false
}
#DownExtract -Url "http://www.nostopti.com/tvirtual/toolbox/workstation/workstation.ps1" -Output "$env:SystemDrive\manut\ToolBox\workstation\workstation.ps1" -Decompress ""


#endregion

#region HARDWARE TOOLS
#region Impressoras
#Install BEMATECH 4200 TH - ONLINE OR OFFLINE 
#before install, you will must disable signature driver.
Function Bema4200th{Param([Parameter(Mandatory=$False)]
$AppDriver
)

cls
#LIBRARY DOWN
#DOWNLOAD
$url = "http://www.nostopti.com/tvirtual/ToolBox/libraries/system.io.compression.filesystem.dll"
$output = "$env:USERPROFILE\downloads\CompressDecompress.dll"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
Add-Type -Path $env:USERPROFILE\downloads\CompressDecompress.dll
if($AppDriver -ne $null)
{

Write-Host @"
**********************************************
*** INSTALANDO BEMA 4200TH SPOOL DRIVER 64 ***
**********************************************
"@

start-process $AppDriver  "/verysilent"

}
else
{

#DOWNLOAD
$url = "https://www.bematech.com.br/wp-content/uploads/2018/08/Driver-de-Spooler-64-Bits.zip"
$output = "$env:USERPROFILE\downloads\BEMA4200THSPOOLDRIVER64.zip"
$Extracted = "$env:USERPROFILE\downloads\BEMA4200THSPOOLDRIVER64"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output

if(Test-Path("$env:USERPROFILE\downloads\BEMA4200THSPOOLDRIVER64\BematechSpoolerDrivers_x64_v4.4.0.3.exe"))
{
Remove-Item -Path "$env:USERPROFILE\downloads\BEMA4200THSPOOLDRIVER64\BematechSpoolerDrivers_x64_v4.4.0.3.exe" -Force -ErrorAction SilentlyContinue
}
[System.IO.Compression.ZipFile]::ExtractToDirectory($output, $Extracted)

start-process $env:USERPROFILE\downloads\BEMA4200THSPOOLDRIVER64\BematechSpoolerDrivers_x64_v4.4.0.3.exe  "/verysilent"

}

}
Bema4200th #-AppDriver "C:\Users\adm02\Downloads\BEMA4200THSPOOLDRIVER64\BematechSpoolerDrivers_x64_v4.4.0.3.exe"
#endregion
#region Disks
function DiskResizeAllFreeSpace{

#EXPANDINDO O DISCO NO SEU TAMANHO MAXIMO
$tamMax = (Get-PartitionSupportedSize -DriveLetter c).sizeMax
Resize-Partition -DriveLetter c -Size $tamMax


}
#DiskResizeAllFreeSpace
#endregion
function HardwareBasic(){

#region Disks
function DiskResizeAllFreeSpace{

#EXPANDINDO O DISCO NO SEU TAMANHO MAXIMO
$tamMax = (Get-PartitionSupportedSize -DriveLetter c).sizeMax
Resize-Partition -DriveLetter c -Size $tamMax


}
#DiskResizeAllFreeSpace
#endregion
Function GetMemory{
#Get total memory installed.
$InstalledRAM = Get-WmiObject -Class Win32_ComputerSystem
#Divide  Mbytes by gb
$Total = [Math]::Round(($InstalledRAM.TotalPhysicalMemory/ 1GB))
$MemoryPysical = Get-WmiObject -Class Win32_PhysicalMemory
$Speed = $MemoryPysical | Select-Object -ExpandProperty Speed
[string[]]$MemoryTotalBank = $MemoryPysical
$TotalReturn = $Total


$TotalReturn
$MemoryTotalBank.Count
$Speed
}
Function GetProcessor{

$Processor = Get-WmiObject Win32_Processor

$Processor.Name

$Processor.Description

}
Function GetOs {

$OSInfo = Get-WmiObject Win32_OperatingSystem

$OSInfo.Caption

$OSInfo.Version

}
Function GetDisk{

$Disk = Get-PhysicalDisk
$DisksType = $Disk | Select-Object -ExpandProperty MediaType 
[string[]]$TotalDisks = $Disk
#Free Space
$DriverLetter = $env:SystemDrive
$FreeSpace = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$DriverLetter'"  | % {[Math]::Round(($_.FreeSpace / 1GB),2)}
$TotalSystemDisk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$DriverLetter'"  | % {[Math]::Round(($_.Size / 1GB),2)}

$Ndisks.Count
$TotalSystemDisk
$FreeSpace
$DisksType
#$FormattedDisk
}
Function MBoard{

$MatherBoard = Get-WmiObject win32_baseboard 
$Product = $MatherBoard | Select-Object -ExpandProperty Product

$Manufacturer = $MatherBoard | Select-Object -ExpandProperty Manufacturer

$Product
$Manufacturer


}

#region Invoke Functions

$_TotalPhysicalMemory,$_MemoryTotalBank, $_Speed = GetMemory
$_ProcName,$_ProcDesc = GetProcessor
$_OsName, $_OsVersion = GetOs
$_TotalDisks, $_TotalSystemDisk, $_FreeSpace, $_DisksType = GetDisk
$_Product, $_Manufacturer = MBoard


#endregion
$infoObject = New-Object PSObject
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Machine Name" -value $env:COMPUTERNAME
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Processor Name" -value ($_ProcName)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Processor Description" -value ($_ProcDesc)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Processor Number Of Cores" -value $CPUInfo.NumberOfCores
Add-Member -inputObject $infoObject -memberType NoteProperty -name "O.S Name" -value ($_OsName)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "O.S Version" -value ($_OsVersion)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Total Banks" -value ($_MemoryTotalBank)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Speed Memory" -value ($_Speed)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Total Physical Disks" -value ($_TotalDisks)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "System Disk Letter" -value ($env:SystemDrive)
Add-Member -InputObject $infoObject -MemberType NoteProperty -Name "Max size System driver" -Value ($_TotalSystemDisk)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Free Space System Disk" -value ($_FreeSpace)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Type of disks" -value ($_DisksType)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "M.B Model" -value ($_Product)
Add-Member -inputObject $infoObject -memberType NoteProperty -name "M.B Manufacturer" -value ($_Manufacturer)

$infoObject #Output to the screen for a visual feedback.
}
HardwareBasic

#endregion

#region SERVERS 
#region AD
#region A.D-D.S Operations
function FindUserByLogonName ($name) {
cls
#region by SamaAccountName
if(get-aduser -Filter * | ? {$_.samaccountname -like "*$name*"})
{
return get-aduser -Filter * | ? {$_.samaccountname -like "*$name*" }
}
#endregion
#region by Name
else
{
return get-aduser -Filter * | ? {$_.Name -like "*$name*"}
}
#endregion
}
#FindUserByLogonName -name "Marcus Dias"

function SetPassUserByLogonName ($name, $Pass)
 {
cls
#region By SamaAccountName
if(get-aduser -Filter * | ? {$_.samaccountname -like "$name"})
{
$result = get-aduser -Filter * | ? {$_.samaccountname -like "$name" }

Set-ADAccountPassword -Identity $result.DistinguishedName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "123" -Force)
Write-host("Password changed!")
}
#endregion
#region By Name 
elseif(get-aduser -Filter * | ? {$_.Name -like "$name"})
{
$result = get-aduser -Filter * | ? {$_.Name -like "$name" }

Set-ADAccountPassword -Identity $result.DistinguishedName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "123" -Force)
Write-host("Password changed!")
}
#endregion
#region User not Found!
else
{
Write-Host("User not Found!")
}
#endregion

}
#SetPassUserByLogonName -name "Marcus Dias" -Pass "123"

Function GetO.SComputersDomain
{
cls
#check the O.S of the all computers in domain.
$Machines = Get-ADComputer -Filter {OperatingSystem -Like '*'} -Properties OperatingSystem
ForEach($M in $Machines)
{

$Properties = @{$M.Name = "|"  +" "+$M.OperatingSystem;}

Write-OutPut($Properties)

}

}
#ComputersDomainGet_O.S

Function GetAllComputersDomainEnabled
{
cls
#check Computer Account enabled or disbled
$Machines = Get-ADComputer -Filter {OperatingSystem -Like '*'} -Properties OperatingSystem
ForEach($M in $Machines)
{

$Properties = @{ $M.Name = " | " + $M.Enabled }


Write-Output($Properties)
}

}
#GetAllComputersDomainEnabled

Function ShowAllGroupsUserIsaMember($LogonAccount)
{
cls
ForEach($UserAcc in $LogonAccount){
Write-Host($UserAcc.ToUpper()) -ForegroundColor Red -BackgroundColor Black
try
{$Users = Get-ADPrincipalGroupMembership -Identity $UserAcc | Select-Object -Property Name, GroupCategory, GroupScope}
Catch{write-host ("NOT FOUND.") }
Write-host($Users.name)
Write-Host($Users.GroupCategory)
Write-Host($Users.GroupScope)
}
}
#ShowAllGroupsUserIsaMember -LogonAccount "Madrcus", "Adm01", "Marcos"

Function ShowMembersOfGroup($Groups)
{
cls

ForEach($g in $Groups)
{
Write-Host($g.ToUpper()) -ForegroundColor Red -BackgroundColor Black
$Group = Get-ADGroupMember -Identity $g # | Select-Object -Property ObjectClass, SamAccountName
write-host($Group.SamAccountName)
Write-Host($Group.ObjectClass)
}

}
[string[]]$Ids = "Administradores", "convidados", "Admins. do Domínio"
#ShowMembersOfGroup -Groups $Ids
#endregion
#region DHCP, DNS

Function ScopeTcpV4($ScopeName, $Start, $End, $Subnet)
{
add-dhcpServerv4Scope -Name $ScopeName -StartRange $Start -EndRange $End -SubnetMask $Subnet -ErrorAction SilentlyContinue
}
#ScopeTcpV4 -"INTERNAL DHCP" -Start 192.168.0.30 -End 192.168.0.200 -Subnet 255.255.255.0

Function ScopeTcpV4($ScopeName, $Start, $End, $Subnet)
{
add-dhcpServerv4Scope -Name $ScopeName -StartRange $Start -EndRange $End -SubnetMask $Subnet -ErrorAction SilentlyContinue
}
#ScopeTcpV4 -"INTERNAL DHCP" -Start 192.168.0.30 -End 192.168.0.200 -Subnet 255.255.255.0

Function DhcpScopeOptions([int]$OptionId, [string]$Value)
{
set-DhcpServerv4OptionValue -OptionId $OptionId -Value $Value -ErrorAction SilentlyContinue
}
#DhcpScopeOptions -OptionId 6 -Value 192.168.0.193 #dns server
#DhcpScopeOptions -OptionId 3 -Value 192.168.0.1 #Router server

function DhcpPXE($SrvDhcp, $SrvPXE)
{
start-process netsh "dhcp server $SrvDhcp add optiondef 60 PXEClient STRING 0 comment=option added for PXE support" -Wait
start-process netsh "dhcp server $SrvDhcp set optionvalue 60 STRING $SrvPXE" -Wait
start-process netsh "dhcp server $SrvDhcp set optionvalue 66 STRING $SrvPXE" -Wait
}
#DhcpPXE -SrvDhcp "192.168.0.193" -SrvPXE "192.168.0.177"

function DnsForward([string[]]$fwarder, $Reordering)
{
#setar os encaminhadores dns
set-DnsServerForwarder -EnableReordering $Reordering -PassThru
set-DnsServerForwarder -IPAddress $fWarders -PassThru
}
[string[]]$fWarders = "1.1.1.1", "8.8.8.8"
DnsForward -fwarder $fWarders -Reordering $false

function DcPromo($pwd,$CreateDnsDelegation, $DatabasePath,$DomainMode, $DomainName,$DomainNetbiosName,$ForestMode,$InstallDns,$LogPath,$NoRebootOnCompletion,$SysvolPath,$Force,$Confirm)
{
$password = $pwd | ConvertTo-SecureString -asPlainText -Force

Import-Module ADDSDeployment -ErrorAction SilentlyContinue
Install-ADDSForest `
-CreateDnsDelegation:$CreateDnsDelegation `
-DatabasePath $DatabasePath `
-DomainMode $DomainMode `
-DomainName $DomainName `
-DomainNetbiosName $DomainNetbiosName `
-ForestMode $ForestMode `
-InstallDns:$InstallDns `
-LogPath $LogPath `
-NoRebootOnCompletion:$NoRebootOnCompletion `
-SysvolPath $SysvolPath `
-SafeModeAdministratorPassword $password `
-Force:$force `
-Confirm:$Confirm`
}
#DcPromo -pwd "sMtp2007$&" -CreateDnsDelegation $false -DatabasePath "C:\Windows\NTDS" -DomainMode "Win2008" -DomainName "NACIONAL.INTRA" -DomainNetbiosName "NACIONAL" -ForestMode "Win2008" -InstallDns $false -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion $false -SysvolPath "C:\Windows\SYSVOL" -Force $true -Confirm $true






#endregion
#endregion
#region ADDSOFT

function SQL2017InstallSilent
{
#region Module _SQL SERVER
#Install-Module -Name SqlServer  -AllowClobber

#endregion
#region Downloads
#LIBRARY DOWN

#region DOWNLOAD Libray
$url = "http://www.nostopti.com/tvirtual/toolbox/libraries/system.io.compression.filesystem.dll"
$output = "$env:USERPROFILE\downloads\CompressDecompress.dll"
#INSTALAR
Invoke-WebRequest -Uri $url -OutFile $output
#endregion
#region Downoad MS2018
#DOWNLOAD Management Studio 2018
$url = "https://download.microsoft.com/download/1/9/4/1949aa9c-6536-48f2-81fa-e7bb07410b36/SSMS-Setup-PTB.exe"
$SSMS = "$env:USERPROFILE\downloads\SSMS-Setup-PTB.exe"
write-host @"
*********************************************************
***      Downloading Management Studio 2017...        ***
*********************************************************
"@ -BackgroundColor White -ForegroundColor DarkGreen

Invoke-WebRequest -Uri $url -OutFile $SSMS

#endregion
#region Download MSSQL SERVER 2017
#DOWNLOAD SQL SERVER 2017
$url = "https://download.microsoft.com/download/5/E/9/5E9B18CC-8FD5-467E-B5BF-BADE39C51F73/SQLServer2017-SSEI-Expr.exe"
$outSQLSERVER2017 = "$env:USERPROFILE\downloads\SQLServer2017.exe"
write-host @"
**********************************************
***     Downloading SQLServer 2017...      ***
**********************************************
"@ -BackgroundColor White -ForegroundColor DarkGreen
Invoke-WebRequest -Uri $url -OutFile $outSQLSERVER2017



start-process $outSQLSERVER2017 "/Language=pt-BR /MediaType=Advanced /MediaPath=C:\SQLInstalation /Action=Download /q" -Wait



#endregion
Add-Type -Path $env:USERPROFILE\downloads\CompressDecompress.dll
#endregion
#region Install sql
write-host @"
**********************************************
***      Installing SQL Server 2017...     ***
**********************************************
"@ -BackgroundColor White -ForegroundColor DarkGreen

start-process C:\SQLInstalation\SQLEXPRADV_x64_ENU.EXE "/Q /IACCEPTSQLSERVERLICENSETERMS /ACTION=`"install`" /FEATURES=SQL,AS,IS,Tools /INSTANCENAME=MSSQL`$ADDSOFT /SAPWD=`"addsoft2007$`"" -Wait

write-host @"
******************************************
***      Installing SQL MS 2017...     ***
******************************************
"@ -BackgroundColor White -ForegroundColor DarkGreen
start-process $SSMS "/install /quiet /passive /norestart" -Wait
#endregion
#region Configurations
Function PipeNamedTcp
{Param([Parameter(ValueFromPipeline)]
  $Root,
  $Path,
  $ValueName,
  $NewValue
)

If($Root -eq "LocalMachine")
{

if(Test-Path("HKLM:\$Path\$NewValue"))
{
write-Host("Já Existe!")

}
Else
{

Set-ItemProperty -Path "HKLM:\$Path" -Name $ValueName -Value $NewValue
}

}


#---------------------------------------------------------------------------#

If($Root -eq "CurrentUser")
{
if(Test-Path("HKCU:\$Path\$NewValue"))
{
write-Host("Já Existe!")
}
Else
{
Set-ItemProperty -Path "HKLM:\$Path" -Name $ValueName -Value $NewValue
}
}

Set-Service -Name SQLBrowser -StartupType Automatic
Start-Service -Name SQLBrowser

}
PipeNamedTcp -Root "LocalMachine" -Path "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQL`$ADDSOFT\MSSQLServer\SuperSocketNetLib\Np" -ValueName "Enabled" -NewValue 1
PipeNamedTcp -Root "LocalMachine" -Path "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQL`$ADDSOFT\MSSQLServer\SuperSocketNetLib\Tcp" -ValueName "Enabled" -NewValue 1
PipeNamedTcp -Root "LocalMachine" -Path "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQL`$ADDSOFT\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -ValueName "TcpPort" -NewValue 1433

#region O.S Configs
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
EnableDisableFirewall -All $true -Enabled $false

##########

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

Rename-Computer -NewName "SRVADD01"

#endregion



#endregion
cls
write-host @"
****************************
***      FINISHED...     ***
****************************
"@ -BackgroundColor Black -ForegroundColor White



}
SQL2017InstallSilent




#endregion
#region HV
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








#endregion
#region WDS

#endregion
#regions General Servers
Function ScheduleTaskWorkingDay($Executable, $Arg, $wDirectory, $GroupId, $DomainName, $Password, $ValueName, $schedulingTime){
#Schedule Task Working Days
$Dev = $Volumes | Select-Object -Property DeviceId
$VolId = $Dev[1].DeviceId
$A = New-ScheduledTaskAction -Execute $Executable -Argument $Arg  -WorkingDirectory $wDirectory
$T =New-ScheduledTaskTrigger -Weekly -DaysOfWeek "Monday", "Tuesday", "Wednesday", "Thursday", "Friday"  -At $schedulingTime
$P = New-ScheduledTaskPrincipal -GroupId $GroupId -RunLevel Highest

$D = New-ScheduledTask -Action $A -Trigger $T -Principal $P
Register-ScheduledTask Shadow_Morning -InputObject $D -User $DomainName -Password $Password
vssadmin add shadowstorage /for=$ValueName /on=$ValueName  /maxsize=10240MB
}
#ScheduleTaskWorkingDay -Executable "C:\Windows\system32\vssadmin.exe" -Arg "create shadow /for=C:" -wDirectory "%systemroot%\system32" -GroupId "Administradores" -DomainName "NOSTOPTI\adm01" -Password "sMtp2007$&" -ValueName "C:" -schedulingTime "12pm"

Function QuerySrvTimerSource(){
#Get srv time
w32tm /query /source
}
#QuerySrvTimerSync

Function QueryInfoSrvTimer(){

w32tm /query /status


}
#QueryInfoSrvTimer

<#
net stop w32time
net start w32time
w32tm.exe /config /manualpeerlist:"pool.ntp.br" /syncfromflags:manual /update
w32tm /config /reliable:yes
#>

#endregion

function activeServer2019(){
dism /online /get-targeteditions
dism /online /set-edition:serverstandard /productkey: N69G4-B89J2-4GBF4-WWYCC-J464C /accepteula
}

#endregion

#region O.S Auto
Function MountImage($MountPointWIM, [int]$Index, $PathToMount){
DISM /Mount-Image /ImageFile:$MountPointWIM /index:$Index /MountDir:$PathToMount
}
#MountImage -MountPointWIM "C:\WinPE\media\sources\boot.wim" -Index 1 -PathToMount "C:\Mount1"

Function UnMountImage($UnMount){
DISM /Unmount-Image /MountDir:$UnMount /commit
}
#UnMountImage("c:\mount1")

Function AddPackage($PathImgMounted, $PkgPath)
{
Add-WindowsPackage -Path $PathImgMounted -PackagePath $PkgPath

}
#Path content powershell Package
#cd "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs"
#AddPackage -PathImgMounted "C:\Mount1\" -PkgPath ".\WinPE-NetFx.cab"
#AddPackage -PathImgMounted "C:\Mount1\" -PkgPath ".\WinPE-Scripting.cab"
#AddPackage -PathImgMounted "C:\Mount1\" -PkgPath ".\WinPE-WMI.cab"
#AddPackage -PathImgMounted "C:\Mount1\" -PkgPath ".\WinPE-PowerShell.cab"
#endregion

#region Any without category
Function OsDetect
{

$GetReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$ProductNameSplit = $GetReg.ProductName.Split(' ')[1]
Switch($ProductNameSplit)
{
10
{
Write-host "teste"
}
8.1
{

}
2012
{

}

}
}

Function PrintScreen ($SaveTo){
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
#Screen Resolution Information
$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
$Width = $Screen.Width
$Height = $Screen.Height
$Left = $Screen.Left
$Top = $Screen.Top
#Create Bitmap using the  top-left and bottom-right bounds
$bitmap = New-Object System.Drawing.Bitmap $Width, $Height
$Graphic = [System.Drawing.Graphics]::FromImage($bitmap)
#capture screen
$Graphic.CopyFromScreen($Left, $top, 0, 0, $bitmap.Size)
#Save File
$bitmap.Save($SaveTo)
Write-Output("Screenshot saved to: $SaveTo")
}
#PrintScreen -SaveTo "C:\Users\marcus\Desktop\SCRIPTS\Screen.bmp"


Function Wait([int]$Second, $Milliseconds){
if($Second)
{
Start-Sleep -Seconds $Second
}

if($Milliseconds)
{
Start-Sleep -Milliseconds $Milliseconds
}


}
#Wait -Milliseconds 5000

#endregion

#region CREATTING
#get-all recurses installed and feature / catagory: Servers

Function InstallWFeature($FeatureName)
{
$adFeature = Get-WindowsFeature -Name $FeatureName
If($adFeature.Installed)
{
write-host("It is already installed.")
}
else
{
Install-WindowsFeature -Name $FeatureName -IncludeAllSubFeature -IncludeManagementTools
}


}
InstallWFeature -FeatureName  "Hyper-v"


#endregion

#region Interact User

Function Finish{Param([Parameter(Mandatory=$true)]
$CurrentUser,
$NewUserName,
$NewComputerName,
$NewPassword,
$AutoUpdate
)

Rename-Computer $NewComputerName

$Encry = convertto-securestring $NewPassword -asplaintext -force
$GetUserAccount = Get-LocalUser -Name $CurrentUser
$GetUserAccount | Set-LocalUser -Password $Encry

$AccountNameToChg = Get-LocalUser -Name $CurrentUser
Set-LocalUser -Name $AccountNameToChg -FullName $NewUserName
Rename-LocalUser -Name $AccountNameToChg -NewName $NewUserName
#AutoLogon Disable
$caminhoReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $caminhoReg -Name "AutoAdminLogon" -Value "0"
if($AutoUpdate -eq "false")
{
Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
}
else
{
Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
}

}
$NewUserName = Read-Host -Prompt "Nome de usuário"
$NewComputerName = Read-Host -Prompt "Nome do computador"
$NewPassword = Read-Host -Prompt "Senha de login"
Finish -CurrentUser "Adm02" -NewUserName $NewUserName -NewComputerName $NewComputerName -NewPassword $NewPassword -AutoUpdate "false"
#




#endregion