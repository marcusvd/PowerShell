function XmlLoad($file) {
    $Manut = "$env:SystemDrive\manut\ToolBox\servers\xmls\"
    #region XML File Settings 
    $xmlFile = $Manut + $file
    $xml = New-Object System.Xml.XmlDocument
    $xml.load($xmlFile)
    return [XML]$xml = Get-Content $xmlFile
    #endregion
}
[XML]$xmlGlobal = XmlLoad("srvfl.xml")

Write-Host($xmlGlobal.ToString());