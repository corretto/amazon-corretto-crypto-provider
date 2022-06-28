@echo on
set SRC_ROOT=%cd%
set BUILD_DIR=%SRC_ROOT%\test_build_dir

@rem This script was taken from AWS-LC and can be adjusted when ACCP adds support for Windows.
@rem %1 contains the path to the setup batch file for the version of of visual studio that was passed into AWS-LC's build spec file.
@rem x64 comes from the architecture options https://docs.microsoft.com/en-us/cpp/build/building-on-the-command-line
set MSVC_PATH=%1
call %MSVC_PATH% x64 || goto error
SET

call :build_and_test test "" || goto error
call :build_and_test test "-DTEST_JAVA_HOME=%TEST_JAVA_HOME%" || goto error
call :build_and_test integration "" || goto error
call :build_and_test integration "-DTEST_JAVA_HOME=%TEST_JAVA_HOME%" || goto error

goto :EOF

@rem %1 is the build type release/test_integration
@rem %2 are any additional gradle args
:build_and_test
@echo on
@echo  LOG: %date%-%time% %1 %2 gradle build and test started.
./gradlew.bat %1 %2 || goto error
@echo  LOG: %date%-%time% %1 %2 tests complete.
exit /b 0

:error
echo Failed with error #%errorlevel%.
exit /b 1
