Import-Module -Name "c:\Util\BackupModule.psm1" -Force

if (!(Test-Path("c:\Util\vms.ps1"))) {
    DownloadBackupFiles
}

Update

powershell -f "c:\Util\vms.ps1"