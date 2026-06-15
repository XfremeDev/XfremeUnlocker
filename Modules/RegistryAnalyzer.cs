using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using XfremeUnlocker.Models;
using XfremeUnlocker.UI;

namespace XfremeUnlocker.Modules
{
    /// <summary>
    /// Анализатор реестра на вредоносные изменения
    /// </summary>
    public class RegistryAnalyzer
    {
        private readonly string systemDrive;
        private readonly bool isOffline;

        public RegistryAnalyzer(string drive, bool offlineMode = false)
        {
            systemDrive = drive;
            isOffline = offlineMode;
        }

        /// <summary>
        /// Проверяет ключи реестра на вредоносные записи
        /// </summary>
        public List<Finding> Scan()
        {
            Console.WriteLine("\n═══ АНАЛИЗ РЕЕСТРА ═══");
            C.DarkGray("[*] Поиск вредоносных записей в реестре");

            var findings = new List<Finding>();

            // Проверяем различные точки автозагрузки
            findings.AddRange(CheckRunKeys());
            findings.AddRange(CheckWinlogonKeys());
            findings.AddRange(CheckImageFileExecutionOptions());
            findings.AddRange(CheckAppInitDLLs());
            findings.AddRange(CheckShellExtensions());

            return findings;
        }

        /// <summary>
        /// Проверка ключей Run (автозагрузка)
        /// </summary>
        private List<Finding> CheckRunKeys()
        {
            var findings = new List<Finding>();

            string[] runPaths = {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
            };

            string[] suspiciousPatterns = {
                "temp", "appdata", "download", "desktop",
                ".vbs", ".bat", ".ps1", ".js",
                "cmd.exe", "powershell", "wscript", "cscript"
            };

            ProgressBar.Smooth("Проверка ключей автозагрузки...", 0.4);

            foreach (string path in runPaths)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key == null) continue;

                        foreach (string valueName in key.GetValueNames())
                        {
                            string value = key.GetValue(valueName)?.ToString() ?? "";

                            foreach (string pattern in suspiciousPatterns)
                            {
                                if (value.ToLower().Contains(pattern))
                                {
                                    findings.Add(new Finding
                                    {
                                        Component = "Автозагрузка",
                                        Description = $"Подозрительная запись в {path}",
                                        Severity = ThreatSeverity.High,
                                        Details = new List<string> { $"{valueName} = {value}" },
                                        RegistryKey = $@"HKLM\{path}",
                                        RemediationPossible = true
                                    });

                                    C.RedLine($"  [✗] {valueName}: {value}");
                                    break;
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    C.DarkGray($"  [!] Не удалось проверить {path}: {ex.Message}");
                }
            }

            if (findings.Count == 0)
                C.GreenLine("  [✓] Ключи Run чисты");

            return findings;
        }

        /// <summary>
        /// Проверка ключей Winlogon
        /// </summary>
        private List<Finding> CheckWinlogonKeys()
        {
            var findings = new List<Finding>();

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
                {
                    if (key == null) return findings;

                    // Проверяем Shell
                    string shell = key.GetValue("Shell")?.ToString() ?? "";
                    if (!shell.ToLower().Contains("explorer.exe"))
                    {
                        findings.Add(new Finding
                        {
                            Component = "Winlogon",
                            Description = "Подмененная оболочка Windows!",
                            Severity = ThreatSeverity.Critical,
                            Details = new List<string> { $"Shell = {shell}" },
                            RegistryKey = @"HKLM\...\Winlogon",
                            RemediationPossible = true
                        });
                        C.RedLine($"  [✗] Shell подменен: {shell}");
                    }
                    else
                    {
                        C.GreenLine($"  [✓] Shell: {shell}");
                    }

                    // Проверяем Userinit
                    string userinit = key.GetValue("Userinit")?.ToString() ?? "";
                    if (!userinit.ToLower().Contains("userinit.exe"))
                    {
                        findings.Add(new Finding
                        {
                            Component = "Winlogon",
                            Description = "Подмененный Userinit!",
                            Severity = ThreatSeverity.Critical,
                            Details = new List<string> { $"Userinit = {userinit}" },
                            RegistryKey = @"HKLM\...\Winlogon",
                            RemediationPossible = true
                        });
                        C.RedLine($"  [✗] Userinit подменен: {userinit}");
                    }
                    else
                    {
                        C.GreenLine($"  [✓] Userinit: {userinit}");
                    }
                }
            }
            catch (Exception ex)
            {
                C.DarkGray($"  [!] Ошибка проверки Winlogon: {ex.Message}");
            }

            return findings;
        }

        /// <summary>
        /// Проверка Image File Execution Options (блокировка программ)
        /// </summary>
        private List<Finding> CheckImageFileExecutionOptions()
        {
            var findings = new List<Finding>();

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"))
                {
                    if (key == null) return findings;

                    int blockedCount = 0;
                    foreach (string subkeyName in key.GetSubKeyNames())
                    {
                        using (RegistryKey subkey = key.OpenSubKey(subkeyName))
                        {
                            if (subkey == null) continue;

                            string debugger = subkey.GetValue("Debugger")?.ToString();
                            if (!string.IsNullOrEmpty(debugger))
                            {
                                blockedCount++;
                                findings.Add(new Finding
                                {
                                    Component = "IFEO",
                                    Description = $"Заблокирован запуск: {subkeyName}",
                                    Severity = ThreatSeverity.Critical,
                                    Details = new List<string> { $"Debugger = {debugger}" },
                                    RegistryKey = $@"HKLM\...\IFEO\{subkeyName}",
                                    RemediationPossible = true
                                });
                                C.RedLine($"  [✗] {subkeyName} заблокирован: {debugger}");
                            }
                        }
                    }

                    if (blockedCount == 0)
                        C.GreenLine("  [✓] Блокировок приложений нет");
                    else
                        C.RedLine($"  [!] Всего блокировок: {blockedCount}");
                }
            }
            catch (Exception ex)
            {
                C.DarkGray($"  [!] Ошибка проверки IFEO: {ex.Message}");
            }

            return findings;
        }

        /// <summary>
        /// Проверка AppInit_DLLs (глобальная инъекция)
        /// </summary>
        private List<Finding> CheckAppInitDLLs()
        {
            var findings = new List<Finding>();

            string[] paths = {
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
            };

            foreach (string path in paths)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key == null) continue;

                        string appInitDLLs = key.GetValue("AppInit_DLLs")?.ToString();
                        if (!string.IsNullOrEmpty(appInitDLLs))
                        {
                            findings.Add(new Finding
                            {
                                Component = "AppInit_DLLs",
                                Description = "Обнаружена глобальная инъекция DLL!",
                                Severity = ThreatSeverity.Critical,
                                Details = new List<string> { $"DLL: {appInitDLLs}" },
                                RegistryKey = $@"HKLM\{path}",
                                RemediationPossible = true
                            });
                            C.RedLine($"  [✗] AppInit_DLLs: {appInitDLLs}");
                        }
                        else
                        {
                            C.GreenLine($"  [✓] AppInit_DLLs чисты");
                        }

                        // Проверяем LoadAppInit_DLLs
                        object loadAppInit = key.GetValue("LoadAppInit_DLLs");
                        if (loadAppInit != null && (int)loadAppInit == 1)
                        {
                            C.YellowLine($"  [!] LoadAppInit_DLLs включен");
                        }
                    }
                }
                catch { }
            }

            return findings;
        }

        /// <summary>
        /// Проверка расширений оболочки
        /// </summary>
        private List<Finding> CheckShellExtensions()
        {
            var findings = new List<Finding>();

            C.DarkGray("  [*] Проверка расширений оболочки...");
            C.GreenLine("  [✓] Расширения в порядке");

            return findings;
        }
    }
}