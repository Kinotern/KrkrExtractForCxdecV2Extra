@echo off
setlocal EnableExtensions

rem ============================================================
rem  Build + cleanup for KrkrExtractForCxdecV2Extra
rem  Place this file next to KrkrZCxdecV2.sln.
rem ============================================================

set "SOLUTION_DIR=%~dp0"
set "SOLUTION=%SOLUTION_DIR%KrkrZCxdecV2.sln"

rem --- Locate MSBuild -----------------------------------------
set "MSBUILD="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        if not defined MSBUILD set "MSBUILD=%%i"
    )
)
if not defined MSBUILD set "MSBUILD=D:\Program\VSStudioCode\Community\MSBuild\Current\Bin\MSBuild.exe"

if not exist "%MSBUILD%" (
    echo [ERROR] MSBuild.exe not found. Edit the MSBUILD fallback path.
    pause
    exit /b 1
)
if not exist "%SOLUTION%" (
    echo [ERROR] Solution not found: %SOLUTION%
    pause
    exit /b 1
)

echo [INFO] MSBuild : %MSBUILD%
echo [INFO] Solution: %SOLUTION%
echo [INFO] Config  : Release / x86 / PlatformToolset=v145
echo.

"%MSBUILD%" "%SOLUTION%" /p:Configuration=Release /p:Platform=x86 /p:PlatformToolset=v145 /m /v:minimal /nologo

if errorlevel 1 (
    echo.
    echo [FAIL] Build failed, exit code %errorlevel%
) else (
    echo.
    echo [OK] Build succeeded
    echo [INFO] Removing .pdb / .exp / .lib ...
    for /r "%SOLUTION_DIR%" %%f in (*.pdb *.exp *.lib) do del /q "%%f" 2>nul
    echo [INFO] Cleanup done
)

echo.
pause
endlocal
