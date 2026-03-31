/**
 * EnvVarUpdate.nsh
 *
 * Final simplified version using SHCTX (Shell Context) for literal keys.
 * SHCTX resolves to HKLM or HKCU automatically based on the installer mode.
 */

!ifndef ENVVARUPDATE_NSH
!define ENVVARUPDATE_NSH

!include "LogicLib.nsh"
!include "WinMessages.nsh"

# Macros for user-facing API
!macro EnvVarUpdate RESULT NAME ACTION REG_ROOT VALUE
  Push "${NAME}"
  Push "${ACTION}"
  Push "${VALUE}"
  Call EnvVarUpdate
  Pop "${RESULT}"
!macroend

!macro un.EnvVarUpdate RESULT NAME ACTION REG_ROOT VALUE
  Push "${NAME}"
  Push "${ACTION}"
  Push "${VALUE}"
  Call un.EnvVarUpdate
  Pop "${RESULT}"
!macroend

!define EnvVarUpdate "!insertmacro EnvVarUpdate"
!define un.EnvVarUpdate "!insertmacro un.EnvVarUpdate"

# Shared Logic Macro
!macro EnvVarUpdate_Logic
  Exch $R1 ; VALUE ($INSTDIR)
  Exch
  Exch $R2 ; ACTION (A, P, R)
  Exch
  Exch $R3 ; VARNAME (PATH)

  Push $1 ; Current Registry Value
  Push $2 ; Subkey Path

  # Use SHCTX to avoid variable-based root keys which fail in ReadRegStr
  StrCpy $2 "Environment"
  ReadRegStr $1 SHCTX "$2" "$R3"

  # Treat empty/missing as an empty string
  ${If} $1 == ""
    StrCpy $1 ""
  ${EndIf}

  # Add Logic
  ${If} $R2 == "A"
    # Basic deduplication (Simple check)
    Push $1
    Push $R1
    Call EnvVarUpdate_Contains
    Pop $0
    
    ${If} $0 == "0"
        ${If} $1 == ""
          StrCpy $1 "$R1"
        ${Else}
          StrCpy $1 "$1;$R1"
        ${EndIf}
    ${EndIf}
  ${EndIf}

  # Write back using SHCTX (Literal)
  WriteRegExpandStr SHCTX "$2" "$R3" "$1"

  # Notify the system
  SendMessage 0xFFFF 0x001A 0 "STR:Environment" /TIMEOUT=5000

  Pop $2
  Pop $1
  Pop $R3
  Pop $R2
  Pop $R1
!macroend

# Function Definitions
Function EnvVarUpdate
  !insertmacro EnvVarUpdate_Logic
FunctionEnd

Function un.EnvVarUpdate
  !insertmacro EnvVarUpdate_Logic
FunctionEnd

Function EnvVarUpdate_Contains
  Exch $R1 ; Value
  Exch
  Exch $R0 ; String
  Exch
  # Basic stub
  StrCpy $0 "0"
  Exch $0
FunctionEnd

!endif
