@echo off
setlocal
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python "%~dp0supaguard" %*
    exit /b %ERRORLEVEL%
)
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -3 "%~dp0supaguard" %*
    exit /b %ERRORLEVEL%
)
echo [SupaGuard Error] Python 3 not found in PATH.
exit /b 1
