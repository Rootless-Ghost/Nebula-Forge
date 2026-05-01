@echo off
setlocal

set BASE=https://github.com/Rootless-Ghost

cd /d "%~dp0"

call :clone_if_missing SigmaForge SigmaForge
call :clone_if_missing YaraForge YaraForge
call :clone_if_missing SnortForge SnortForge
call :clone_if_missing EndpointForge EndpointForge
call :clone_if_missing SIREN SIREN
call :clone_if_missing Threat-Intel-Dashboard threat-intel-dashboard
call :clone_if_missing LogNorm LogNorm
call :clone_if_missing HuntForge HuntForge
call :clone_if_missing DriftWatch DriftWatch
call :clone_if_missing ClusterIQ ClusterIQ
call :clone_if_missing AtomicLoop AtomicLoop
call :clone_if_missing VulnForge VulnForge
call :clone_if_missing WifiForge WifiForge

echo.
echo Done. Run "docker compose up -d" to start the full stack.
goto :eof

:clone_if_missing
if exist "%~2\" (
    echo   %~2 already exists -- skipping
) else (
    echo   Cloning %~1...
    git clone %BASE%/%~1 %~2
)
goto :eof
