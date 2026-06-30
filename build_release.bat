@echo off
setlocal EnableDelayedExpansion

echo ==========================================
echo   wallet-mpc-node release build
echo   targets: linux/amd64, linux/arm64, windows/amd64
echo ==========================================

set CGO_ENABLED=0
set LDFLAGS=-s -w

if exist "output" rmdir /s /q output
mkdir output

call :build_one linux amd64 wallet-mpc-node-linux-amd64
if %errorlevel% neq 0 goto :failed

call :build_one linux arm64 wallet-mpc-node-linux-arm64
if %errorlevel% neq 0 goto :failed

call :build_one windows amd64 wallet-mpc-node-windows-amd64.exe
if %errorlevel% neq 0 goto :failed

echo.
echo ==========================================
echo   Done. Binaries in output\
echo     wallet-mpc-node-linux-amd64
echo     wallet-mpc-node-linux-arm64
echo     wallet-mpc-node-windows-amd64.exe
echo ==========================================
exit /b 0

:build_one
set GOOS=%~1
set GOARCH=%~2
set OUT=output\%~3
echo.
echo --- build %GOOS%/%GOARCH% ---
go build -installsuffix cgo -ldflags="%LDFLAGS%" -o "%OUT%" .
if %errorlevel% neq 0 (
    echo [ERROR] go build failed for %GOOS%/%GOARCH%
    exit /b 1
)
exit /b 0

:failed
echo [ERROR] release build aborted.
exit /b 1
