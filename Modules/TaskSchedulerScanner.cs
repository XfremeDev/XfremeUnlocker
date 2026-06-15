using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using XfremeUnlocker.Models;
using XfremeUnlocker.UI;

namespace XfremeUnlocker.Modules
{
    /// <summary>
    /// Сканер планировщика заданий Windows
    /// </summary>
    public class TaskSchedulerScanner
    {
        private readonly string systemDrive;

        // Подозрительные паттерны в заданиях
        private static readonly string[] SuspiciousPatterns = {
            "temp", "appdata", "download", "desktop", "public",
            ".vbs", ".bat", ".ps1", ".js", ".vbe", ".wsf",
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe"
        };

        public TaskSchedulerScanner(string drive)
        {
            systemDrive = drive;
        }

        /// <summary>
        /// Сканирует планировщик заданий на подозрительные задачи
        /// </summary>
        public List<Finding> Scan()
        {
            Console.WriteLine("\n═══ ПРОВЕРКА ПЛАНИРОВЩИКА ЗАДАНИЙ ═══");
            C.DarkGray("[*] Поиск подозрительных задач в планировщике");

            var findings = new List<Finding>();
            string tasksPath = Path.Combine(systemDrive, "Windows", "System32", "Tasks");

            if (!Directory.Exists(tasksPath))
            {
                C.YellowLine("  [!] Папка Tasks не найдена");
                findings.Add(new Finding
                {
                    Component = "Планировщик",
                    Description = "Папка Tasks не найдена",
                    Severity = ThreatSeverity.Medium
                });
                return findings;
            }

            ProgressBar.Smooth("Сканирование заданий...", 0.8);

            try
            {
                var suspiciousTasks = new List<(string FilePath, string Command)>();
                string[] taskFiles = Directory.GetFiles(tasksPath, "*", SearchOption.AllDirectories);

                foreach (string taskFile in taskFiles)
                {
                    try
                    {
                        string content = File.ReadAllText(taskFile, System.Text.Encoding.Unicode);

                        foreach (string pattern in SuspiciousPatterns)
                        {
                            if (content.ToLower().Contains(pattern))
                            {
                                // Пытаемся извлечь команду из XML
                                string command = ExtractCommand(content);
                                suspiciousTasks.Add((taskFile, command));
                                break;
                            }
                        }
                    }
                    catch
                    {
                        // Пропускаем файлы, которые не удалось прочитать
                    }
                }

                if (suspiciousTasks.Count > 0)
                {
                    C.RedLine($"\n  [✗] Найдено подозрительных заданий: {suspiciousTasks.Count}");

                    foreach (var task in suspiciousTasks.Take(5))
                    {
                        string fileName = Path.GetFileName(task.FilePath);
                        Console.WriteLine($"      • {fileName}");
                        if (!string.IsNullOrEmpty(task.Command))
                            Console.WriteLine($"        Команда: {task.Command}");
                    }

                    findings.Add(new Finding
                    {
                        Component = "Планировщик заданий",
                        Description = $"Подозрительные задания: {suspiciousTasks.Count}",
                        Severity = ThreatSeverity.High,
                        Details = suspiciousTasks.Take(10)
                            .Select(t => $"{Path.GetFileName(t.FilePath)}: {t.Command}").ToList(),
                        RemediationPossible = true
                    });

                    if (ConsoleUI.AskConfirmation("Отключить подозрительные задания?"))
                    {
                        DisableTasks(suspiciousTasks);
                    }
                }
                else
                {
                    C.GreenLine("  [✓] Подозрительных заданий не найдено");
                }
            }
            catch (Exception ex)
            {
                C.RedLine($"  [-] Ошибка сканирования: {ex.Message}");
                findings.Add(new Finding
                {
                    Component = "Планировщик",
                    Description = $"Ошибка: {ex.Message}",
                    Severity = ThreatSeverity.Low
                });
            }

            return findings;
        }

        /// <summary>
        /// Извлекает команду из XML задания
        /// </summary>
        private string ExtractCommand(string xmlContent)
        {
            try
            {
                XDocument doc = XDocument.Parse(xmlContent);
                XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

                var commandElement = doc.Descendants(ns + "Command").FirstOrDefault();
                return commandElement?.Value ?? "";
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        /// Отключает подозрительные задания
        /// </summary>
        private void DisableTasks(List<(string FilePath, string Command)> tasks)
        {
            int disabled = 0;

            foreach (var (filePath, _) in tasks)
            {
                try
                {
                    string disabledPath = filePath + ".DISABLED";
                    File.Move(filePath, disabledPath);
                    disabled++;
                }
                catch (Exception ex)
                {
                    C.RedLine($"    [-] Ошибка: {Path.GetFileName(filePath)} - {ex.Message}");
                }
            }

            C.GreenLine($"  [+] Отключено заданий: {disabled}");
        }
    }
}