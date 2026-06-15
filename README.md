# XfremeUnlocker v0.1 Beta

[![Version](https://img.shields.io/badge/version-0.1_beta-red)](https://github.com/xfreme-security/xfremeunlocker/releases)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue)](https://github.com/xfreme-security/xfremeunlocker)
[![.NET](https://img.shields.io/badge/.NET%20Framework-4.7.2-purple)](https://dotnet.microsoft.com/)

> Бета-версия! Используйте с осторожностью. Рекомендуется резервное копирование перед использованием.

---

## Описание

**XfremeUnlocker** — продвинутый инструмент для очистки системы Windows от вредоносного ПО. Предназначен для специалистов по информационной безопасности, системных администраторов и опытных пользователей.

Работает в:
- Обычной Windows
- Безопасном режиме (Safe Mode)
- Безопасном режиме с командной строкой
- Среде восстановления (WinRE/WinPE)

## Возможности

| Модуль | Описание |
|--------|----------|
| FileIntegrityChecker | Проверка целостности системных файлов (UtilMan.exe, sethc.exe, osk.exe и др.) |
| HostsFileAnalyzer | Обнаружение вредоносных записей в файле hosts |
| RegistryAnalyzer | Сканирование реестра (Run, Winlogon, IFEO, AppInit_DLLs) |
| TaskSchedulerScanner | Поиск подозрительных задач в планировщике |
| UACManager | Проверка и принудительное усиление настроек UAC |
| SubstDriveManager | Отключение виртуальных дисков SUBST (только WinRE) |
| SystemScanner | Сбор информации о системе |
| PrivilegeManager | Управление привилегиями процесса |

| Ошибка | Причина | Решение |
|--------|---------|---------|
| Нет доступа к реестру | Нет прав администратора | Запустить от администратора |
| Не видит системный диск | WinPE без драйверов | Загрузить драйверы дисков |
| Файл занят процессом | Файл используется системой | Загрузиться в WinRE |
| Не работает в Windows | Опасные операции отключены | Загрузиться в WinRE |
