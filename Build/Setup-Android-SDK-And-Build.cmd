@echo off
setlocal EnableExtensions

set "BUILD_DIR=%~dp0"
for %%I in ("%BUILD_DIR%..") do set "ROOT=%%~fI"

set "SDK=C:\Android\SDK"
set "LOCAL_PROPERTIES=%ROOT%\android\local.properties"

if not exist "%SDK%\platforms" (
    echo ERROR: Android SDK platforms not found:
    echo   %SDK%\platforms
    echo.
    echo Open Android Studio SDK Manager and install Android SDK Platform.
    pause
    exit /b 1
)

if not exist "%SDK%\build-tools" (
    echo ERROR: Android SDK Build-Tools not found:
    echo   %SDK%\build-tools
    echo.
    echo Open Android Studio SDK Manager and install Android SDK Build-Tools.
    pause
    exit /b 1
)

if not exist "%ROOT%\android" (
    echo ERROR: Android project directory not found:
    echo   %ROOT%\android
    pause
    exit /b 1
)

> "%LOCAL_PROPERTIES%" echo sdk.dir=C\:/Android/SDK

set "ANDROID_HOME=%SDK%"
set "ANDROID_SDK_ROOT=%SDK%"

setx ANDROID_HOME "%SDK%" >nul
setx ANDROID_SDK_ROOT "%SDK%" >nul

echo.
echo Android SDK configured:
echo   %SDK%
echo.
echo Created:
echo   %LOCAL_PROPERTIES%
echo.
echo Contents:
type "%LOCAL_PROPERTIES%"
echo.

if not exist "%BUILD_DIR%fedmes-build.exe" (
    echo ERROR: fedmes-build.exe not found:
    echo   %BUILD_DIR%fedmes-build.exe
    pause
    exit /b 1
)

echo Starting FedMes Builder...
echo.

"%BUILD_DIR%fedmes-build.exe"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%EXIT_CODE%"=="0" (
    echo Build failed with exit code %EXIT_CODE%.
) else (
    echo Build completed successfully.
)

pause
exit /b %EXIT_CODE%
