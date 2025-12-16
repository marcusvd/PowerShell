
class Org {
    [string]$PathProFileUser
    [string[]]$AllItems
    [string[]]$Extensions
    [string[]]$ToFolder
}

$Org = [Org]::new()
$Org.PathProFileUser = [Environment]::GetFolderPath('Desktop')

$Org.AllItems = Get-ChildItem -Path $Org.PathProFileUser

foreach ($names in $Org.AllItems) {
    $Org.Extensions += [System.IO.Path]::GetExtension($names)
}

$Org.Extensions = $Org.Extensions | Where-Object { $_ -ne "" }

$foldersPath = [System.Collections.Generic.List[string]]::new()

foreach ($Extensions in $Org.Extensions = $Org.Extensions | Sort-Object -Unique) {
    New-Item -ItemType Directory -Path $Org.PathProFileUser -Name $Extensions.Replace(".", "") -ErrorAction SilentlyContinue;

    $ddd = Join-Path -Path $Org.PathProFileUser -ChildPath  ($Extensions.Replace(".", ""));

    $foldersPath.Add($ddd)
}

foreach ($item in $foldersPath) {
    $lastPart = [System.IO.Path]::GetFileName($item)
    $lastPart

    foreach ($filesExtension in $Org.Extensions) {
        
      $file =  $filesExtension.Replace(".", "");

        if ($file -eq $lastPart) {
            $src = $item.Replace($file, "") + '*.' + $file
            Move-Item -Path $src -Destination $item  -ErrorAction SilentlyContinue 
        }
    }

   # Move-Item -Path $src -Destination $dty  -ErrorAction SilentlyContinue 
}
  
