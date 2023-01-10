

class Org {
    [string]$PathProFileUser
    [string[]]$AllItems
    [string[]]$Extensions
    [string[]]$ToFolder
}

$Org = [Org]::new()
$Org.PathProFileUser = "$env:USERPROFILE\desktop\"
$Org.AllItems = Get-ChildItem -Path $Org.PathProFileUser

foreach ($names in $Org.AllItems) {
    $Org.Extensions += [System.IO.Path]::GetExtension($names)
}

foreach ($Extensions in $Org.Extensions = $Org.Extensions | Sort-Object -Unique) {
   New-Item -ItemType Directory -Path $Org.PathProFileUser -Name $Extensions -ErrorAction SilentlyContinue
   $src = $Org.PathProFileUser+'*'+$Extensions
   $dty = $Org.PathProFileUser+$Extensions
   Move-Item -Path $src -Destination $dty  -ErrorAction SilentlyContinue 
}
