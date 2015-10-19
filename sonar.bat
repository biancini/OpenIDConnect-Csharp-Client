SET BUILD=Debug
SET NUNIT_PATH=packages\NUnit.Runners.2.6.4\tools
SET COVERAGE_PATH=packages\OpenCover.4.6.166\tools

"%COVERAGE_PATH%\OpenCover.Console.exe" -target:"%NUNIT_PATH%\nunit-console.exe" -targetargs:"OIDCTests\bin\%BUILD%\OIDC.Tests.dll /noshadow /xml=TestResult.xml" -register:user -output:coverage.xml - filter:+[OpenIDClient]*
sonar-runner.bat
