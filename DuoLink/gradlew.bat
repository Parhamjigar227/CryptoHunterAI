@echo off
setlocal
set "GRADLE_HOME=%USERPROFILE%\.gradle\duolink\gradle-8.9"
if not exist "%GRADLE_HOME%\bin\gradle.bat" (
  if not exist "%USERPROFILE%\.gradle\duolink" mkdir "%USERPROFILE%\.gradle\duolink"
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$u='https://services.gradle.org/distributions/gradle-8.9-bin.zip'; $z=Join-Path $env:TEMP 'duolink-gradle-8.9.zip'; Invoke-WebRequest $u -OutFile $z; Expand-Archive -Path $z -DestinationPath (Join-Path $env:USERPROFILE '.gradle\duolink') -Force; Remove-Item $z"
  if errorlevel 1 exit /b 1
)
call "%GRADLE_HOME%\bin\gradle.bat" %*
