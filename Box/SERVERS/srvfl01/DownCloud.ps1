
$getPath = get-process -Name "GoogleDriveFS" | Stop-Process
invoke-command { taskkill /f /im GoogleDriveFS.exe}