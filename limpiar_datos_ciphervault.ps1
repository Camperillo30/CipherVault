# ============================================================
#  limpiar_datos_ciphervault.ps1 — Deja CipherVault como recién instalado
# ============================================================
#  NO borra nada: mueve todo a una carpeta de respaldo con fecha, por si
#  necesitas recuperar algo después.
#
#  Qué limpia:
#    1. %LOCALAPPDATA%\CipherVault  (cuentas, contraseñas guardadas, licencia, log)
#    2. Registro HKCU\Software\CipherVault  (fecha de la prueba; se exporta a .reg)
#    3. Copias viejas en la carpeta del proyecto (passwords.db, install_date*,
#       app_config.json, developer.license). Si se dejan, la app las vuelve a
#       importar al arrancar y "resucitan" los datos anteriores.
#
#  Uso (en la carpeta del proyecto, con CipherVault CERRADO):
#     .\limpiar_datos_ciphervault.ps1
# ============================================================
$ErrorActionPreference = "Stop"

$running = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "CipherVault*" }
if ($running) {
    Write-Host "CipherVault está abierto. Ciérralo y vuelve a ejecutar este script." -ForegroundColor Yellow
    exit 1
}

$stamp   = Get-Date -Format "yyyy-MM-dd_HHmmss"
$dataDir = Join-Path $env:LOCALAPPDATA "CipherVault"
$backup  = Join-Path $env:LOCALAPPDATA "CipherVault_respaldo_$stamp"
New-Item -ItemType Directory -Path $backup -Force | Out-Null

# 1) Carpeta de datos
if (Test-Path $dataDir) {
    Move-Item -Path $dataDir -Destination (Join-Path $backup "LOCALAPPDATA_CipherVault")
    Write-Host "Datos de la app movidos al respaldo." -ForegroundColor Green
} else {
    Write-Host "No había carpeta de datos en $dataDir."
}

# 2) Registro (fecha de la prueba)
$regKey = "HKCU\Software\CipherVault"
if (Test-Path "HKCU:\Software\CipherVault") {
    & reg.exe export $regKey (Join-Path $backup "registro_CipherVault.reg") /y | Out-Null
    Remove-Item -Path "HKCU:\Software\CipherVault" -Recurse -Force
    Write-Host "Registro de la prueba exportado y limpiado." -ForegroundColor Green
}

# 3) Copias viejas en la carpeta del proyecto
$projectBackup = Join-Path $backup "carpeta_proyecto"
$old = @("passwords.db", "passwords.db-wal", "passwords.db-shm", "install_date", "install_date.txt",
         "app_config.json", "developer.license", "dev_credentials.json")
foreach ($name in $old) {
    $path = Join-Path $PSScriptRoot $name
    if (Test-Path $path) {
        New-Item -ItemType Directory -Path $projectBackup -Force | Out-Null
        Move-Item -Path $path -Destination (Join-Path $projectBackup $name)
        Write-Host "Movido del proyecto: $name"
    }
}

Write-Host ""
Write-Host "Listo. Respaldo en: $backup" -ForegroundColor Cyan
Write-Host "Ahora: abre CipherVault, crea tu cuenta con tu email de dueño y pega el código nuevo del correo."
