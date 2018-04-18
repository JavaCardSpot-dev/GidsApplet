rem set directories
set DIR_LOG=log
set DIR_EXTOOLS=ext
set DIR_JCBUILD=build/javacard
rem set filenames
set JCBUILD_EXPORTER=%DIR_EXTOOLS%/gp.jar
set JCBUILD_TARGET=%DIR_JCBUILD%/GidsApplet.cap
set JCBUILD_LOG=%DIR_LOG%/javacard-install.log
rem init log file
if not exist %DIR_LOG% mkdir %DIR_LOG%
echo [%DATE% - %TIME%] > %JCBUILD_LOG%%
rem uninstall previous version if it exists
java -jar %JCBUILD_EXPORTER% -uninstall %JCBUILD_TARGET% >> %JCBUILD_LOG%
rem install new version and log all information
java -jar %JCBUILD_EXPORTER% -install %JCBUILD_TARGET% -default -d -v -i >> %JCBUILD_LOG%
rem check installation
java -jar %JCBUILD_EXPORTER% -list >> %JCBUILD_LOG%