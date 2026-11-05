# ============================================================
#  build.ps1 — Compila CipherVault a un ejecutable (.exe)
# ============================================================
#  Qué hace, en orden:
#    1. Verifica que los archivos del proyecto existan y tengan el
#       nombre exacto que espera PyInstaller (Test-RequiredProjectFiles).
#    2. Lee la configuración (links de Wompi, URL y secreto de activación, precios) desde
#       variables de entorno del proceso o desde un archivo .env local.
#       Las variables del modo desarrollador (CIPHERVAULT_ENABLE_DEV_TOOLS,
#       *_DEV_*) NUNCA se leen aquí ni se empaquetan: el .exe no tiene modo
#       developer. Para usarlo, ejecuta desde código con .\run.ps1.
#    3. Escribe esa configuración en desktop_runtime_config.json, el
#       archivo que CipherVault.spec empaqueta DENTRO del .exe (así el
#       código fuente nunca contiene keys ni URLs reales).
#    4. Busca una instalación de Python utilizable (venv del proyecto,
#       venv ya activo, Python Launcher, o python del PATH) y crea el
#       entorno virtual .venv311 si hace falta.
#    5. Instala las dependencias de requirements-desktop.txt.
#    6. Ejecuta PyInstaller con CipherVault.spec y genera dist\CipherVault.exe.
#    7. Si hay un certificado de firma de código configurado, firma el .exe
#       (CIPHERVAULT_SIGN_THUMBPRINT, o CIPHERVAULT_SIGN_PFX + CIPHERVAULT_SIGN_PFX_PASSWORD).
#    8. Si Inno Setup (6 o 7) está instalado, genera el instalador
#       dist\CipherVault-Setup-<versión>.exe (installer\CipherVault.iss) y también lo firma.
#
#  Uso:  .\build.ps1   (o  .\build.ps1 -PythonVersion 3.12,  .\build.ps1 -SkipInstaller)
# ============================================================
param(
    [string]$PythonVersion = "3.11",
    [string]$VenvPath = ".venv311",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"

# Verifica que existan (con el nombre EXACTO) los archivos que PyInstaller
# necesita para compilar, y sugiere el nombre correcto si detecta uno
# parecido con mayúsculas/espacios/guiones distintos.
function Test-RequiredProjectFiles {
    param([string[]]$RequiredFiles)

    $missing = @()
    foreach ($file in $RequiredFiles) {
        if (-not (Test-Path (Join-Path $PWD $file))) {
            $missing += $file
        }
    }

    if ($missing.Count -eq 0) {
        return
    }

    Write-Host ""
    Write-Host "ERROR: faltan archivos necesarios en esta carpeta:" -ForegroundColor Red

    foreach ($file in $missing) {
        Write-Host "  - $file" -ForegroundColor Red

        # Comparamos el nombre SIN extension (asi detectamos tanto extensiones
        # perdidas como espacios/guiones_bajos/mayusculas distintas)
        $expectedBase = [System.IO.Path]::GetFileNameWithoutExtension($file)
        $expectedNormalized = ($expectedBase -ireplace '[\s_\-]', '').ToLower()

        $candidates = Get-ChildItem -Path $PWD -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -ne $file -and (($_.BaseName -ireplace '[\s_\-]', '').ToLower() -eq $expectedNormalized)
        }
        foreach ($candidate in $candidates) {
            Write-Host "    -> Encontrado '$($candidate.Name)' -- probablemente deberia llamarse '$file'" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    throw "Corrige los nombres de archivo listados arriba (renombralos exactamente como se indica) y vuelve a ejecutar este script."
}

Test-RequiredProjectFiles -RequiredFiles @(
    "main.py",
    "gestor_contrasenas_secure.py",
    "cv_extras.py",
    "cv_sync.py",
    "requirements-desktop.txt",
    "CipherVault.spec"
)

# Carga manualmente el archivo .env (si existe) a un diccionario local.
# No se usan variables de entorno del sistema para esto: así el build es
# reproducible aunque .env no esté "cargado" en la sesión de PowerShell.
$localEnvPath = Join-Path $PWD ".env"
$desktopConfigPath = Join-Path $PWD "desktop_runtime_config.json"
$envFileValues = @{}

if (Test-Path $localEnvPath) {
    foreach ($rawLine in Get-Content $localEnvPath) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) {
            continue
        }
        $parts = $line.Split("=", 2)
        $envFileValues[$parts[0].Trim()] = $parts[1].Trim()
    }
}

# Prioridad: 1) variable de entorno del proceso, 2) valor leído de .env,
# 3) el valor por defecto indicado por el llamador.
function Get-ConfigValue {
    param(
        [string]$Key,
        [string]$Default = ""
    )

    $processValue = [Environment]::GetEnvironmentVariable($Key)
    if (-not [string]::IsNullOrWhiteSpace($processValue)) {
        return $processValue.Trim()
    }
    if ($envFileValues.ContainsKey($Key) -and -not [string]::IsNullOrWhiteSpace($envFileValues[$Key])) {
        return $envFileValues[$Key].Trim()
    }
    return $Default
}

# Igual que Get-ConfigValue, pero interpreta el valor como JSON (se usa
# para CIPHERVAULT_WOMPI_LINK_MAP, que es un mapa {"premium_mensual": "url", "premium_anual": "url", "premium_vida": "url"}).
function Get-ConfigJsonMap {
    param(
        [string]$Key,
        [string]$Default = "{}"
    )
    $raw = Get-ConfigValue -Key $Key -Default $Default
    try {
        return ($raw | ConvertFrom-Json)
    } catch {
        Write-Warning "No se pudo interpretar $Key como JSON valido. Se usara un mapa vacio. Valor recibido: $raw"
        return ("{}" | ConvertFrom-Json)
    }
}

# Links de pago reales de Wompi (no son secretos). Se usan si .env no define CIPHERVAULT_WOMPI_LINK_MAP.
$defaultWompiLinks = '{"premium_mensual":"https://checkout.wompi.co/l/KepI4g","premium_anual":"https://checkout.wompi.co/l/I75Zba","premium_vida":"https://checkout.wompi.co/l/nfKj8q","equipo_3":"https://checkout.wompi.co/l/eBC1hf","equipo_5":"https://checkout.wompi.co/l/5znGkS","equipo_10":"https://checkout.wompi.co/l/wnQAUN","equipo_ilimitado":"https://checkout.wompi.co/l/bwpwwK"}'
$wompiLinkMap = Get-ConfigJsonMap -Key "CIPHERVAULT_WOMPI_LINK_MAP" -Default $defaultWompiLinks
# Links viejos del plan Equipo (precios anteriores): si el .env todavía los trae, se reemplazan.
$retiredWompiLinks = @("https://checkout.wompi.co/l/5fZGtj", "https://checkout.wompi.co/l/1TY6Z1", "https://checkout.wompi.co/l/KUzO5b")
# Completa con los links por defecto los planes que el .env no trae (por ejemplo, los de Equipo).
foreach ($prop in ($defaultWompiLinks | ConvertFrom-Json).PSObject.Properties) {
    if (-not ($wompiLinkMap.PSObject.Properties.Name -contains $prop.Name)) {
        $wompiLinkMap | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
    } elseif ($retiredWompiLinks -contains ([string]$wompiLinkMap.($prop.Name)).Trim()) {
        Write-Warning "El .env trae un link viejo para $($prop.Name); se usa el nuevo: $($prop.Value)"
        $wompiLinkMap.($prop.Name) = $prop.Value
    }
}

# Este es el conjunto de valores que terminará embebido dentro del .exe
# (a través de desktop_runtime_config.json, incluido por CipherVault.spec).
# La app los lee en tiempo de ejecución con load_runtime_config().
$embeddedDesktopConfig = [ordered]@{
    CIPHERVAULT_WOMPI_LINK_MAP          = $wompiLinkMap
    CIPHERVAULT_ACTIVATION_URL          = Get-ConfigValue -Key "CIPHERVAULT_ACTIVATION_URL"
    CIPHERVAULT_ACTIVATION_SECRET       = Get-ConfigValue -Key "CIPHERVAULT_ACTIVATION_SECRET"
    CIPHERVAULT_PRICE_PREMIUM_MENSUAL_COP = Get-ConfigValue -Key "CIPHERVAULT_PRICE_PREMIUM_MENSUAL_COP" -Default "9900"
    CIPHERVAULT_PRICE_PREMIUM_ANUAL_COP   = Get-ConfigValue -Key "CIPHERVAULT_PRICE_PREMIUM_ANUAL_COP" -Default "89900"
    CIPHERVAULT_PRICE_PREMIUM_VIDA_COP    = Get-ConfigValue -Key "CIPHERVAULT_PRICE_PREMIUM_VIDA_COP" -Default "149900"
    CIPHERVAULT_PRICE_EQUIPO_3_COP          = $(if ((Get-ConfigValue -Key "CIPHERVAULT_PRICE_EQUIPO_3_COP" -Default "24900") -eq "39900") { "24900" } else { Get-ConfigValue -Key "CIPHERVAULT_PRICE_EQUIPO_3_COP" -Default "24900" })
    CIPHERVAULT_PRICE_EQUIPO_5_COP          = $(if ((Get-ConfigValue -Key "CIPHERVAULT_PRICE_EQUIPO_5_COP" -Default "37900") -eq "59900") { "37900" } else { Get-ConfigValue -Key "CIPHERVAULT_PRICE_EQUIPO_5_COP" -Default "37900" })
    CIPHERVAULT_PRICE_EQUIPO_10_COP         = $(if ((Get-ConfigValue -Key "CIPHERVAULT_PRICE_EQUIPO_10_COP" -Default "64900") -eq "99900") { "64900" } else { Get-ConfigValue -Key "CIPHERVAULT_PRICE_EQUIPO_10_COP" -Default "64900" })
    CIPHERVAULT_PRICE_EQUIPO_ILIMITADO_COP  = Get-ConfigValue -Key "CIPHERVAULT_PRICE_EQUIPO_ILIMITADO_COP" -Default "199900"
}


$linkMapProps = @($wompiLinkMap.PSObject.Properties)
if ($linkMapProps.Count -eq 0) {
    Write-Warning "CIPHERVAULT_WOMPI_LINK_MAP esta vacio o no es JSON valido. El boton 'Comprar plan' no va a funcionar."
} else {
    foreach ($planKey in @("premium_mensual", "premium_anual", "premium_vida", "equipo_3", "equipo_5", "equipo_10", "equipo_ilimitado")) {
        $match = $linkMapProps | Where-Object { $_.Name -eq $planKey -and -not [string]::IsNullOrWhiteSpace([string]$_.Value) }
        if (-not $match) {
            Write-Warning "CIPHERVAULT_WOMPI_LINK_MAP no tiene un link configurado para el plan '$planKey'."
        }
    }
}
if ([string]::IsNullOrWhiteSpace($embeddedDesktopConfig.CIPHERVAULT_ACTIVATION_URL) -or
    [string]::IsNullOrWhiteSpace($embeddedDesktopConfig.CIPHERVAULT_ACTIVATION_SECRET)) {
    Write-Warning "CIPHERVAULT_ACTIVATION_URL o CIPHERVAULT_ACTIVATION_SECRET estan vacios. La app no podra activar licencias."
}

# Escribe desktop_runtime_config.json en la carpeta del proyecto. CipherVault.spec
# lo toma de aquí y lo copia dentro del .exe al compilar.
$embeddedDesktopConfig | ConvertTo-Json -Depth 6 | Set-Content $desktopConfigPath -Encoding UTF8

# Verificación: ninguna clave de desarrollador puede haber llegado al archivo que se empaqueta.
$writtenKeys = @((Get-Content $desktopConfigPath -Raw | ConvertFrom-Json).PSObject.Properties.Name)
$leaked = @($writtenKeys | Where-Object { $_ -match "_DEV_" -or $_ -match "ENABLE_DEV_TOOLS" })
if ($leaked.Count -gt 0) {
    throw "desktop_runtime_config.json contiene claves de desarrollador ($($leaked -join ', ')). Build cancelado."
}

# Prueba si un comando de Python (ruta directa, o "py -3.11") realmente
# funciona en este equipo, antes de confiar en él.
function Test-PythonWorks {
    param([string[]]$Command)
    try {
        if ($Command.Count -eq 2) {
            & $Command[0] $Command[1] -c "import sys" 2>$null | Out-Null
        } else {
            & $Command[0] -c "import sys" 2>$null | Out-Null
        }
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

# Decide qué Python usar para crear/reusar el entorno virtual, probando
# en orden (ver los comentarios numerados dentro de la función):
# venv del proyecto -> venv ya activo -> Python Launcher (version pedida)
# -> Python Launcher (cualquier 3.x) -> python del PATH.
function Resolve-PythonExecutable {
    param(
        [string]$PreferredVersion,
        [string]$ProjectVenvPath
    )

    $venvPython = Join-Path $PWD "$ProjectVenvPath\Scripts\python.exe"

    # 1. Ya existe un venv completo del proyecto -> usarlo directo, no crear nada
    if (Test-Path $venvPython) {
        return [PSCustomObject]@{ Command = @($venvPython); NeedsVenvCreation = $false }
    }

    # 2. Si ya hay un venv activo en esta sesion (ej. el .venv de PyCharm),
    #    usarlo como base en vez de exigir una version exacta de Python
    if ($env:VIRTUAL_ENV) {
        $activePython = Join-Path $env:VIRTUAL_ENV "Scripts\python.exe"
        if ((Test-Path $activePython) -and (Test-PythonWorks -Command @($activePython))) {
            Write-Host "Usando el entorno virtual ya activo: $env:VIRTUAL_ENV"
            return [PSCustomObject]@{ Command = @($activePython); NeedsVenvCreation = $true }
        }
    }

    # 3. Intentar el Python Launcher con la version exacta solicitada
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        if (Test-PythonWorks -Command @("py", "-$PreferredVersion")) {
            return [PSCustomObject]@{ Command = @("py", "-$PreferredVersion"); NeedsVenvCreation = $true }
        }

        # 4. Esa version exacta no esta instalada -> usar la mejor version 3.x disponible
        if (Test-PythonWorks -Command @("py", "-3")) {
            Write-Warning "Python $PreferredVersion no esta instalado. Usando la version 3.x mas reciente que detecto Windows."
            Write-Warning "Ejecuta 'py --list' para ver todas las versiones disponibles en tu equipo."
            return [PSCustomObject]@{ Command = @("py", "-3"); NeedsVenvCreation = $true }
        }
    }

    # 5. Ultimo recurso: python directo del PATH
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd -and (Test-PythonWorks -Command @($pythonCmd.Source))) {
        return [PSCustomObject]@{ Command = @($pythonCmd.Source); NeedsVenvCreation = $true }
    }

    throw "No se encontro ninguna instalacion de Python utilizable en este equipo.`n" +
          "Soluciones:`n" +
          "  1. Instala Python desde https://www.python.org/downloads/ (marca 'Add to PATH' durante la instalacion)`n" +
          "  2. O ejecuta 'py --list' en PowerShell para ver que versiones detecta Windows`n" +
          "  3. O activa manualmente un entorno virtual existente antes de correr build.ps1"
}

$resolved = Resolve-PythonExecutable -PreferredVersion $PythonVersion -ProjectVenvPath $VenvPath
$venvPython = Join-Path $PWD "$VenvPath\Scripts\python.exe"
$distExePath = Join-Path $PWD "dist\CipherVault.exe"
$buildFolderPath = Join-Path $PWD "build\CipherVault"

if ($resolved.NeedsVenvCreation) {
    # Si quedo una carpeta de un intento anterior fallido (sin python.exe adentro), la limpiamos primero
    if ((Test-Path $VenvPath) -and (-not (Test-Path $venvPython))) {
        Write-Warning "Se encontro un entorno virtual incompleto en $VenvPath (de un intento anterior). Eliminandolo antes de recrearlo..."
        Remove-Item $VenvPath -Recurse -Force
    }

    Write-Host "Creando entorno virtual en $VenvPath ..."
    $cmd = $resolved.Command
    if ($cmd.Count -eq 2) {
        & $cmd[0] $cmd[1] -m venv $VenvPath
    } else {
        & $cmd[0] -m venv $VenvPath
    }

    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPython)) {
        throw "No se pudo crear el entorno virtual en $VenvPath (python -m venv fallo).`n" +
              "Revisa que Python este correctamente instalado y vuelve a intentar."
    }
}

# Instala/actualiza pip y las dependencias de escritorio (cryptography,
# pyinstaller) dentro del entorno virtual resuelto arriba.
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Fallo 'pip install --upgrade pip'. Revisa tu conexion a internet o el entorno virtual." }

& $venvPython -m pip install -r requirements-desktop.txt
if ($LASTEXITCODE -ne 0) { throw "Fallo la instalacion de requirements-desktop.txt. Revisa el mensaje de pip arriba." }

# Limpia builds anteriores para evitar mezclar archivos viejos con el nuevo .exe.
if (Test-Path $buildFolderPath) {
    Remove-Item $buildFolderPath -Recurse -Force
}
if (Test-Path $distExePath) {
    Remove-Item $distExePath -Force
}

# Compila el ejecutable siguiendo CipherVault.spec (que ya sabe incluir
# desktop_runtime_config.json y los íconos de assets/).
& $venvPython -m PyInstaller --clean --noconfirm "CipherVault.spec"

if (-not (Test-Path $distExePath)) {
    throw "No se genero el ejecutable esperado en $distExePath"
}

# ── Firma de código (opcional) ─────────────────────────────────
# Los datos del certificado se leen de .env / variables de entorno y NUNCA se
# escriben en desktop_runtime_config.json (no forman parte de $embeddedDesktopConfig).
#   Opción A (certificado instalado en Windows o token USB):  CIPHERVAULT_SIGN_THUMBPRINT=<huella SHA1>
#   Opción B (archivo .pfx):  CIPHERVAULT_SIGN_PFX=C:\ruta\cert.pfx  y  CIPHERVAULT_SIGN_PFX_PASSWORD=...
$signThumbprint = Get-ConfigValue -Key "CIPHERVAULT_SIGN_THUMBPRINT"
$signPfx        = Get-ConfigValue -Key "CIPHERVAULT_SIGN_PFX"
$signPfxPass    = Get-ConfigValue -Key "CIPHERVAULT_SIGN_PFX_PASSWORD"
$timestampUrl   = Get-ConfigValue -Key "CIPHERVAULT_SIGN_TIMESTAMP_URL" -Default "http://timestamp.digicert.com"

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path $kits) {
        $found = Get-ChildItem $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -match "\\x64\\" } | Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

# Firma un archivo si hay certificado configurado. Devuelve $true si quedó firmado.
function Invoke-CodeSign {
    param([string]$FilePath)
    if ([string]::IsNullOrWhiteSpace($signThumbprint) -and [string]::IsNullOrWhiteSpace($signPfx)) {
        return $false
    }
    $signtool = Find-SignTool
    if (-not $signtool) {
        Write-Warning "Hay certificado configurado pero no se encontro signtool.exe. Instala el 'Windows SDK' (componente Signing Tools)."
        return $false
    }
    $signArgs = @("sign", "/fd", "SHA256", "/tr", $timestampUrl, "/td", "SHA256", "/d", "CipherVault")
    if (-not [string]::IsNullOrWhiteSpace($signThumbprint)) {
        $signArgs += @("/sha1", $signThumbprint)
    } else {
        if (-not (Test-Path $signPfx)) { throw "No existe el certificado indicado en CIPHERVAULT_SIGN_PFX: $signPfx" }
        $signArgs += @("/f", $signPfx)
        if (-not [string]::IsNullOrWhiteSpace($signPfxPass)) { $signArgs += @("/p", $signPfxPass) }
    }
    & $signtool @signArgs $FilePath | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "signtool no pudo firmar $FilePath (revisa el certificado y la conexion al servidor de sello de tiempo)." }
    & $signtool verify /pa $FilePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "La firma de $FilePath no se pudo verificar." }
    Write-Host "Firmado:" $FilePath -ForegroundColor Green
    return $true
}

$exeSigned = Invoke-CodeSign -FilePath $distExePath

# Resumen final para confirmar que el .exe quedó listo.
$exeInfo = Get-Item $distExePath
Write-Host "Build listo:" $exeInfo.FullName
Write-Host "Ultima modificacion:" $exeInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "Tamano (bytes):" $exeInfo.Length
Write-Host "SHA-256:" (Get-FileHash $distExePath -Algorithm SHA256).Hash

# ── Instalador con Inno Setup (opcional) ───────────────────────
# Version de la app: se lee de APP_VERSION en Gestor_contrasenas_secure.py.
$appVersion = "0.0.0"
$versionLine = Select-String -Path "Gestor_contrasenas_secure.py" -Pattern '^APP_VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1
if ($versionLine) { $appVersion = $versionLine.Matches[0].Groups[1].Value }

$setupPath = $null
if (-not $SkipInstaller) {
    # Busca ISCC.exe de cualquier version de Inno Setup (6, 7...) en las rutas habituales.
    $iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
    $isccPath = if ($iscc) { $iscc.Source } else {
        $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:LOCALAPPDATA "Programs")) |
                 Where-Object { $_ -and (Test-Path $_) }
        Get-ChildItem -Path $roots -Directory -Filter "Inno Setup*" -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName "ISCC.exe" } |
            Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if ($isccPath) {
        & $isccPath "/DAppVersion=$appVersion" "installer\CipherVault.iss"
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup no pudo generar el instalador." }
        $setupPath = Join-Path $PWD "dist\CipherVault-Setup-$appVersion.exe"
        $null = Invoke-CodeSign -FilePath $setupPath
        Write-Host "Instalador listo:" $setupPath
        Write-Host "SHA-256 instalador:" (Get-FileHash $setupPath -Algorithm SHA256).Hash
    } else {
        Write-Warning "Inno Setup no esta instalado: no se genero el instalador (descargalo gratis en jrsoftware.org/isinfo.php)."
    }
}

Write-Host ""
if (-not $exeSigned) {
    Write-Host "El .exe NO esta firmado. Para quitar los avisos de SmartScreen y antivirus, configura" -ForegroundColor Yellow
    Write-Host "CIPHERVAULT_SIGN_THUMBPRINT o CIPHERVAULT_SIGN_PFX en .env (ver README, 'Firma de codigo')." -ForegroundColor Yellow
}