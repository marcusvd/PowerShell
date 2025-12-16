function Set-WallpaperRegistry {
    param (
        [Parameter(Mandatory = $true)]
        [string]$WallpaperPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Center","Tile","Stretch","Fit","Fill","Span","Reserved","Fill10")]
        [string]$Style
    )

    # Mapeamento dos estilos para valores numéricos
    $styleMap = @{
        "Center"   = 0
        "Tile"     = 1
        "Stretch"  = 2
        "Fit"      = 3
        "Fill"     = 4
        "Span"     = 5
        "Reserved" = 6
        "Fill10"   = 10
    }

    $styleValue = $styleMap[$Style]

    # Caminho da chave de registro
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"

    # Cria a chave se não existir
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Define os valores
    Set-ItemProperty -Path $regPath -Name "Wallpaper" -Value $WallpaperPath
    Set-ItemProperty -Path $regPath -Name "WallpaperStyle" -Value $styleValue

    Write-Host "Wallpaper registry updated to $WallpaperPath with style $Style ($styleValue)"

    # Opcional: aplicar imediatamente
    rundll32.exe user32.dll, UpdatePerUserSystemParameters
}

Set-WallpaperRegistry -WallpaperPath "D:\Profiles\Marcus\Desktop\png\Captura de tela 2025-10-17 154347.png" -Style Fit