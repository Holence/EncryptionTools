@echo off

SET current=%~dp0
SET current=%current:~0,-1%
SET current=%current:\=\\%
echo %current%

powershell -c "(gc '%current%\context_menu.reg') -replace 'ROOT_PATH', '%current%' | Out-File -encoding ASCII '%current%\context_menu_new.reg'"

echo "%current%\\context_menu_new.reg"
"%current%\\context_menu_new.reg"