# Import-Module -Name "c:\Util\BackupModule.psm1" -Force
# $Date = Get-Date -Format "dd_MM_yyyy"
# $VmsPathsSource = @("\\srvhv01\v$\VMS\SRVAD01\SRVAD01.VHDX", "\\srvhv01\v$\VMS\SRVFL01\SRVFL01.vhdx", "\\srvhv01\v$\VMS\SRVFL01\DADOS.vhdx", "\\srvhv01\v$\VMS\SRVSH01\SRVSH01.vhdx")
# $VmsPathsDestiny = @("C:\Util\BACKUP\$($Date)\SRVAD01\SRVAD01.VHDX", "C:\Util\BACKUP\$($Date)\SRVFL01\SRVFL01.vhdx", "C:\Util\BACKUP\$($Date)\SRVFL01\DADOS.vhdx", "C:\Util\BACKUP\$($Date)\SRVSH01\SRVSH01.vhdx")
# $PathVmsToBackupCalculateAmount = "\\srvhv01\v$\VMS\"
# $ExtensionFilesToCalculateAmount = "*.vhd*"
# $DriveToBackupIsFreeSpace = "c:"
# $PathToBackupFiles = "c:\Util\BACKUP"
# $PathToDelete = "c:\Util\BACKUP\"
# $MsgSource = "VMS--(SOURCE-FILES)--(ARC-AR)-- Backup (FAIL)", "----NO STOP-TI----"
# $MsgDestiny = "VMS--(DESTINY-FILES)--(ARC-AR)-- Backup (FAIL)", "----NO STOP-TI----"
# $daysBack = 8 #total de dias que ser� preservado de backups


# Import-Module Import-Json


$headerJson = Get-Content -Path "C:\Util\BackupHeader.json" -Raw

$powerShellObj = $headerJson | ConvertFrom-Json


write-host($powerShellObj.VmsPathsSource)
Function TotalFilesToBackup{
return CalcFilesSize -pathToFile $PathVmsToBackupCalculateAmount -extension $ExtensionFilesToCalculateAmount
}

Function TotalFreeSpaceLocalDriveToBackup{
return CheckFreeSpaceDisk -DriverLetter $DriveToBackupIsFreeSpace
}



if(!(VmsCheckExists -paths $VmsPathsSource)){
SendMail($MsgSource)
#Shutdown
Invoke-Command{shutdown -s -f -t 120}
}


Function CheckDestiny{
if(!(VmsCheckExists -paths $VmsPathsDestiny)){
SendMail($MsgDestiny)
#Shutdown
Invoke-Command{shutdown -s -f -t 120}
}
}



[int]$DriveToBackup = TotalFreeSpaceLocalDriveToBackup
[int]$FilesForBack = TotalFilesToBackup

While($DriveToBackup -lt $FilesForBack){
$daysBack--
DeleteOlderFiles -PathFilesToDelete $PathToDelete -daysBack $daysBack
$DriveToBackup = TotalFreeSpaceLocalDriveToBackup
$FilesForBack = TotalFilesToBackup
Write-host($daysBack)
}


BackUpCopy -target $PathVmsToBackupCalculateAmount -destiny $PathToBackupFiles

CheckDestiny

Invoke-Command{shutdown -s -f -t 120}
Write-Host("Test of hash")