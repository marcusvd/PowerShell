Import-Module -Name "c:\Util\BackupModule.psm1" -Force

if (Test-Path("c:\Util\host_bkp.ps1")) {
    HostBackupUpdate
}

powershell -f "c:\Util\host_bkp.ps1"