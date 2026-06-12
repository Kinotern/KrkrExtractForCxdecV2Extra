@echo off
setlocal
set "ROOT=%~dp0"

del /s /q "%ROOT%*.pdb" "%ROOT%*.lib" "%ROOT%*.exp" >nul 2>nul

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$root=[System.IO.Path]::GetFullPath('%ROOT%');" ^
  "$keep=[System.IO.Path]::GetFullPath((Join-Path $root 'Release'));" ^
  "Get-ChildItem -LiteralPath $root -Directory -Recurse | Where-Object { ($_.Name -in 'Debug','Release') -and ([System.IO.Path]::GetFullPath($_.FullName) -ne $keep) } | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force };"

echo Cleaned build byproducts and project intermediate directories.
endlocal
