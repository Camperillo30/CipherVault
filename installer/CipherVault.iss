; ============================================================
;  CipherVault.iss — instalador de Windows (Inno Setup 6)
;  Lo compila build.ps1 automáticamente si Inno Setup está instalado:
;    ISCC.exe /DAppVersion=3.1.0 installer\CipherVault.iss
;  Resultado: dist\CipherVault-Setup-<versión>.exe
;
;  - Instala solo para el usuario actual (no pide permisos de administrador).
;  - Crea acceso directo en el menú Inicio y, si el usuario quiere, en el escritorio.
;  - Al desinstalar NO borra la bóveda (%LOCALAPPDATA%\CipherVault): los datos
;    del usuario solo se borran a mano, para que nadie los pierda por error.
; ============================================================

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#define AppName "CipherVault"
#define AppPublisher "S.C.A"
#define AppExe "CipherVault.exe"

[Setup]
; AppId identifica la app para actualizaciones/desinstalación: NO lo cambies nunca.
AppId={{6F1C8E2A-4B7D-4E9A-9C3B-5A2D7E8F1C04}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppSupportURL=mailto:ciphervaultpass@gmail.com
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=CipherVault-Setup-{#AppVersion}
SetupIconFile=..\Assets\icono.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
; Puente que usa la extensión del navegador (la app lo registra al abrirse)
Source: "..\dist\CipherVaultBridge.exe"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
; Al desinstalar se borra el registro del puente en Chrome, Edge y Brave.
Root: HKCU; Subkey: "Software\Google\Chrome\NativeMessagingHosts\com.sca.ciphervault"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Microsoft\Edge\NativeMessagingHosts\com.sca.ciphervault"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.sca.ciphervault"; Flags: uninsdeletekey dontcreatekey

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent
