!include "EnvVarUpdate.nsh"

!macro customInstall
    DetailPrint "Agregando Sentinel al PATH del sistema..."

    ; System PATH (HKLM) - para todos los usuarios (requiere Admin)
    ${EnvVarUpdate} $0 "PATH" "A" "HKLM" "$INSTDIR"

    ; User PATH como fallback
    ${EnvVarUpdate} $0 "PATH" "A" "HKCU" "$INSTDIR"

    ; Crear shims (sentinel y sntl) con ruta absoluta
    FileOpen $0 "$INSTDIR\sentinel.cmd" w
    FileWrite $0 "@echo off$\r$\n"
    FileWrite $0 "$\"$INSTDIR\Sentinel.exe$\" %*$\r$\n"
    FileClose $0

    FileOpen $0 "$INSTDIR\sntl.cmd" w
    FileWrite $0 "@echo off$\r$\n"
    FileWrite $0 "$\"$INSTDIR\Sentinel.exe$\" %*$\r$\n"
    FileClose $0

    MessageBox MB_OK|MB_ICONINFORMATION "✅ Sentinel instalado correctamente!$\n$\nLos comandos 'sentinel' y 'sntl' ya están disponibles.$\n$\nAbre una NUEVA terminal (PowerShell o CMD) y prueba:$\n   sentinel --version"
!macroend

!macro customUninstall
    # Remover de PATH (Opcional pero recomendado)
    ${un.EnvVarUpdate} $0 "PATH" "R" "HKLM" "$INSTDIR"
    ${un.EnvVarUpdate} $0 "PATH" "R" "HKCU" "$INSTDIR"
!macroend
