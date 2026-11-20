# ============================================================
#  run.ps1 — Ejecuta CipherVault directamente con Python (sin compilar)
# ============================================================
#  Pensado para desarrollo rápido: crea (o reutiliza) un entorno virtual,
#  instala las dependencias de requirements-desktop.txt si hace falta, y
#  lanza main.py con ese Python. A diferencia de build.ps1, NO genera un
#  .exe ni escribe desktop_runtime_config.json — en este modo la app lee
#  la configuración directamente de un archivo .env local (ver
#  load_dotenv_file() en Gestor_contrasenas_secure.py).
#
#  Uso:  .\run.ps1
# ============================================================
param(
    [string]$PythonVersion = "3.12",
    [string]$VenvPath = ".venv312"
)

$ErrorActionPreference = "Stop"

# Prueba si un comando de Python realmente funciona antes de confiar en él.
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

# Igual que en build.ps1: busca un Python utilizable, en orden de
# preferencia (venv del proyecto -> venv activo -> Python Launcher -> PATH).
function Resolve-PythonExecutable {
    param(
        [string]$PreferredVersion,
        [string]$ProjectVenvPath
    )

    $venvPython = Join-Path $PWD "$ProjectVenvPath\Scripts\python.exe"

    if (Test-Path $venvPython) {
        return [PSCustomObject]@{ Command = @($venvPython); NeedsVenvCreation = $false }
    }

    if ($env:VIRTUAL_ENV) {
        $activePython = Join-Path $env:VIRTUAL_ENV "Scripts\python.exe"
        if ((Test-Path $activePython) -and (Test-PythonWorks -Command @($activePython))) {
            Write-Host "Usando el entorno virtual ya activo: $env:VIRTUAL_ENV"
            return [PSCustomObject]@{ Command = @($activePython); NeedsVenvCreation = $true }
        }
    }

    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        if (Test-PythonWorks -Command @("py", "-$PreferredVersion")) {
            return [PSCustomObject]@{ Command = @("py", "-$PreferredVersion"); NeedsVenvCreation = $true }
        }
        if (Test-PythonWorks -Command @("py", "-3")) {
            Write-Warning "Python $PreferredVersion no esta instalado. Usando la version 3.x mas reciente que detecto Windows."
            return [PSCustomObject]@{ Command = @("py", "-3"); NeedsVenvCreation = $true }
        }
    }

    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd -and (Test-PythonWorks -Command @($pythonCmd.Source))) {
        return [PSCustomObject]@{ Command = @($pythonCmd.Source); NeedsVenvCreation = $true }
    }

    throw "No se encontro ninguna instalacion de Python utilizable en este equipo.`n" +
          "Instala Python desde https://www.python.org/downloads/ (marca 'Add to PATH')`n" +
          "o ejecuta 'py --list' para ver que versiones detecta Windows."
}

$resolved = Resolve-PythonExecutable -PreferredVersion $PythonVersion -ProjectVenvPath $VenvPath
$venvPython = Join-Path $PWD "$VenvPath\Scripts\python.exe"

# Solo crea el entorno virtual e instala dependencias si no existía uno ya
# usable (evita reinstalar todo cada vez que se ejecuta el script).
if ($resolved.NeedsVenvCreation) {
    if ((Test-Path $VenvPath) -and (-not (Test-Path $venvPython))) {
        Write-Warning "Se encontro un entorno virtual incompleto en $VenvPath. Eliminandolo antes de recrearlo..."
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
        throw "No se pudo crear el entorno virtual en $VenvPath."
    }

    & $venvPython -m pip install --upgrade pip
    & $venvPython -m pip install -r requirements-desktop.txt
}

# Lanza la app tal cual (sin empaquetar); usa .env si existe en esta carpeta.
& $venvPython main.py