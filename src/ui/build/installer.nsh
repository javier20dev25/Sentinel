!macro customInstall
  DetailPrint "Configuring system PATH..."
  nsExec::ExecToLog 'powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "$path = [Environment]::GetEnvironmentVariable(''PATH'', ''Machine''); if ($path -notmatch [regex]::Escape(''$INSTDIR'')) { [Environment]::SetEnvironmentVariable(''PATH'', $path + '';'' + ''$INSTDIR'', ''Machine'') }"'
!macroend

!macro customUnInstall
  DetailPrint "Removing from system PATH..."
  nsExec::ExecToLog 'powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "$path = [Environment]::GetEnvironmentVariable(''PATH'', ''Machine''); $newPath = ($path.Split('';'') | Where-Object { $_ -ne ''$INSTDIR'' }) -join '';''; [Environment]::SetEnvironmentVariable(''PATH'', $newPath, ''Machine'')"'
!macroend
