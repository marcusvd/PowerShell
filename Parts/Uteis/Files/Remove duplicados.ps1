clear
 #$FolderBroser = "E:\Minas Ar"
  #$filePath = "C:\Users\nostop\Desktop\"

  Add-Type -AssemblyName System.Windows.Forms
  
  $FolderBroser = New-Object System.Windows.Forms.FolderBrowserDialog
  [void]$FolderBroser.ShowDialog()
 # Write-Host($FolderBroser.SelectedPath)


if(Test-Path $FolderBroser.SelectedPath){

$msg = 'Pesquisando por duplicados... em ' + $FolderBroser.SelectedPath + '. Por favor, aguarde...'

Write-Warning $msg
$duplicate = Get-ChildItem $FolderBroser.SelectedPath -File -Recurse -ErrorAction SilentlyContinue | Get-FileHash | Group-Object -Property Hash | Where-Object count -GT 1
}

if($duplicate.Count -lt 1){
write-warning ('Não foram encontrados arquivos duplicados.')
}
else
{

write-warning ('Duplicados encontados.')
$result = foreach($double in $duplicate){
$double.Group | Select-Object -Property path, hash
}

$date = Get-Date -Format "dd-MM-yyyy"

#$itemToRemove = $result | Out-GridView -Title "Para selecionar multiplos arquivos mantenha 'CTRL' pressionada!" -PassThru
#$itemToRemove = $result | Out-GridView -Title "Para selecionar multiplos arquivos mantenha 'CTRL' pressionada!" -PassThru

$itemToRemove = $result   
Write-Host($itemToRemove.path)


}


if($FolderBroser.SelectedPath){
[void]$FolderBroser.ShowDialog()
#$toDuplicate = New-Item -ItemType Directory -Path $env:USERPROFILE\desktop\Duplicates_$date -Force

$folderDuplicatedMoved = $FolderBroser.SelectedPath

$toDuplicate = New-Item -ItemType Directory -Path $folderDuplicatedMoved\Duplicates\$date -Force
$toDuplicate #Crating path to move duplicates


Move-Item $itemToRemove.Path -Destination $toDuplicate -Force



#$itemToRemove.Path | Add-Content $env:USERPROFILE\desktop\from.txt

#$toDuplicate.Path | Add-Content $env:USERPROFILE\desktop\to.txt


Write-Warning ('Operação de remoção de duplicadas realizada.')

Start-Process $toDuplicate
}

