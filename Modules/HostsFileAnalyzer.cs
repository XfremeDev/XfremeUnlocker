using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using XfremeUnlocker.Models;
using XfremeUnlocker.UI;

namespace XfremeUnlocker.Modules
{
    /// <summary>
    /// Анализатор файла hosts на вредоносные записи
    /// </summary>
    public class HostsFileAnalyzer
    {
        private readonly string systemDrive;

        // Список доменов безопасности для проверки
        private static readonly string[] SecurityDomains = {
            "kaspersky", "eset", "drweb", "avast", "avg", "bitdefender",
            "mcafee", "symantec", "norton", "malwarebytes", "windowsupdate",
            "trendmicro", "comodo", "f-secure", "sophos", "avira", "gdata",
            "emsisoft", "pandasecurity", "zonealarm", "adaware", "spybot",
            "microsoft.com/security", "update.microsoft.com"
        };

        public HostsFileAnalyzer(string drive)
        {
            systemDrive = drive;
        }

        /// <summary>
        /// Сканирует файл hosts на вредоносные записи
        /// </summary>
        public List<Finding> Scan()
        {
            Console.WriteLine("\n═══ ПРОВЕРКА ФАЙЛА HOSTS ═══");
            C.DarkGray("[*] Поиск блокировок антивирусных сайтов");

            var findings = new List<Finding>();
            string hostsPath = Path.Combine(systemDrive,
                "Windows", "System32", "drivers", "etc", "hosts");

            if (!File.Exists(hostsPath))
            {
                C.YellowLine("  [!] Файл hosts не найден");
                findings.Add(new Finding
                {
                    Component = "Hosts",
                    Description = "Файл hosts отсутствует",
                    Severity = ThreatSeverity.Low,
                    FilePath = hostsPath
                });
                return findings;
            }

            ProgressBar.Smooth("Анализ hosts файла...", 0.5);

            try
            {
                string[] lines = File.ReadAllLines(hostsPath, Encoding.UTF8);
                var maliciousEntries = new List<(int LineNumber, string Content, string Domain)>();

                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();

                    // Пропускаем комментарии и пустые строки
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                        continue;

                    // Проверяем на наличие блокировок
                    foreach (string domain in SecurityDomains)
                    {
                        if (line.ToLower().Contains(domain))
                        {
                            maliciousEntries.Add((i + 1, line, domain));
                            break;
                        }
                    }
                }

                if (maliciousEntries.Count > 0)
                {
                    C.RedLine($"\n  [✗] Обнаружены вредоносные записи: {maliciousEntries.Count} шт.");

                    // Показываем первые 5 записей
                    foreach (var entry in maliciousEntries.Take(5))
                    {
                        Console.WriteLine($"      Строка {entry.LineNumber}: блокирует {entry.Domain}");
                        Console.WriteLine($"      {entry.Content.Substring(0, Math.Min(70, entry.Content.Length))}");
                    }

                    findings.Add(new Finding
                    {
                        Component = "Hosts файл",
                        Description = $"Обнаружены вредоносные записи: {maliciousEntries.Count} шт.",
                        Severity = ThreatSeverity.High,
                        Details = maliciousEntries.Take(10)
                            .Select(e => $"Строка {e.LineNumber}: {e.Content}").ToList(),
                        FilePath = hostsPath,
                        RemediationPossible = true
                    });

                    // Предложение очистки
                    if (ConsoleUI.AskConfirmation("Очистить вредоносные записи?"))
                    {
                        CleanHostsFile(hostsPath, maliciousEntries, lines);
                    }
                }
                else
                {
                    C.GreenLine("  [✓] Файл hosts чист");
                }
            }
            catch (Exception ex)
            {
                C.RedLine($"  [-] Ошибка анализа: {ex.Message}");
                findings.Add(new Finding
                {
                    Component = "Hosts",
                    Description = $"Ошибка: {ex.Message}",
                    Severity = ThreatSeverity.Low
                });
            }

            return findings;
        }

        /// <summary>
        /// Очищает файл hosts от вредоносных записей
        /// </summary>
        private void CleanHostsFile(string hostsPath,
            List<(int LineNumber, string Content, string Domain)> maliciousEntries,
            string[] originalLines)
        {
            try
            {
                // Создаем резервную копию
                string backupPath = hostsPath + ".xfreme_backup";
                File.Copy(hostsPath, backupPath, true);
                Console.WriteLine($"  [*] Резервная копия: {backupPath}");

                // Удаляем вредоносные строки
                var maliciousLineNumbers = new HashSet<int>(
                    maliciousEntries.Select(e => e.LineNumber));

                var cleanLines = new List<string>();
                for (int i = 0; i < originalLines.Length; i++)
                {
                    if (!maliciousLineNumbers.Contains(i + 1))
                    {
                        cleanLines.Add(originalLines[i]);
                    }
                }

                File.WriteAllLines(hostsPath, cleanLines, Encoding.UTF8);
                C.GreenLine("  [+] Файл hosts успешно очищен");
            }
            catch (Exception ex)
            {
                C.RedLine($"  [-] Ошибка очистки: {ex.Message}");
            }
        }
    }
}