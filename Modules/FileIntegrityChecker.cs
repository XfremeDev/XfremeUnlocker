using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using XfremeUnlocker.Models;
using XfremeUnlocker.UI;
using XfremeUnlocker.Utils;

namespace XfremeUnlocker.Modules
{
    public class FileIntegrityChecker
    {
        private readonly string systemDrive;
        private static readonly Dictionary<string, SysFileInfo> database;

        static FileIntegrityChecker()
        {
            database = new Dictionary<string, SysFileInfo>
            {
                ["utilman.exe"] = new SysFileInfo { DisplayName = "Диспетчер служебных программ", MinSize = 45000, MaxSize = 1500000 },
                ["sethc.exe"] = new SysFileInfo { DisplayName = "Залипание клавиш", MinSize = 70000, MaxSize = 280000 },
                ["osk.exe"] = new SysFileInfo { DisplayName = "Экранная клавиатура", MinSize = 250000, MaxSize = 1200000 },
                ["narrator.exe"] = new SysFileInfo { DisplayName = "Экранный диктор", MinSize = 300000, MaxSize = 330000 },
                ["magnify.exe"] = new SysFileInfo { DisplayName = "Экранная лупа", MinSize = 500000, MaxSize = 2600000 },
                ["AtBroker.exe"] = new SysFileInfo { DisplayName = "Брокер спец. возможностей", MinSize = 120000, MaxSize = 170000 },
                ["displayswitch.exe"] = new SysFileInfo { DisplayName = "Переключение дисплеев", MinSize = 80000, MaxSize = 110000 }
            };
        }

        public FileIntegrityChecker(string drive)
        {
            systemDrive = drive;
        }

        public List<Finding> Scan()
        {
            Console.WriteLine("\n═══ ПРОВЕРКА ЦЕЛОСТНОСТИ СИСТЕМНЫХ ФАЙЛОВ ═══");
            C.DarkGray("[*] Анализ на предмет подмены UtilMan.exe и других компонентов");

            var findings = new List<Finding>();
            string sys32 = Path.Combine(systemDrive, "Windows", "System32");

            if (!Directory.Exists(sys32))
            {
                findings.Add(new Finding
                {
                    Component = "System32",
                    Description = "Папка System32 не найдена",
                    Severity = ThreatSeverity.Critical
                });
                return findings;
            }

            // Получаем хеши cmd.exe для сравнения
            var cmdHashes = new HashSet<string>();
            string[] cmdPaths = {
                Path.Combine(sys32, "cmd.exe"),
                Path.Combine(systemDrive, "Windows", "SysWOW64", "cmd.exe")
            };

            foreach (string path in cmdPaths)
            {
                if (File.Exists(path))
                {
                    string hash = HashCalculator.CalculateSHA256(path);
                    if (hash != null) cmdHashes.Add(hash);
                }
            }

            var pb = new ProgressBar(database.Count, "[Сканирование]");

            foreach (var kvp in database)
            {
                string filename = kvp.Key;
                var info = kvp.Value;
                string filePath = Path.Combine(sys32, filename);

                if (!File.Exists(filePath))
                {
                    findings.Add(new Finding
                    {
                        Component = filename,
                        Description = $"Файл отсутствует: {info.DisplayName}",
                        Severity = ThreatSeverity.Medium,
                        FilePath = filePath
                    });
                    pb.Update();
                    Thread.Sleep(30);
                    continue;
                }

                try
                {
                    var fi = new FileInfo(filePath);
                    long size = fi.Length;
                    string hash = HashCalculator.CalculateSHA256(filePath);
                    var problems = new List<string>();

                    if (size < info.MinSize)
                        problems.Add($"Размер меньше минимального: {size:N0} байт (мин: {info.MinSize:N0})");
                    else if (size > info.MaxSize)
                        problems.Add($"Размер превышает максимальный: {size:N0} байт (макс: {info.MaxSize:N0})");

                    if (hash != null && cmdHashes.Contains(hash))
                        problems.Add("КРИТИЧЕСКИ: Файл является точной копией cmd.exe!");

                    if (problems.Count > 0)
                    {
                        findings.Add(new Finding
                        {
                            Component = filename,
                            Description = $"ОБНАРУЖЕНА ПОДМЕНА: {info.DisplayName}",
                            Severity = ThreatSeverity.Critical,
                            Details = problems,
                            FilePath = filePath,
                            RemediationPossible = true
                        });
                    }
                }
                catch (Exception ex)
                {
                    findings.Add(new Finding
                    {
                        Component = filename,
                        Description = $"Ошибка проверки: {ex.Message}",
                        Severity = ThreatSeverity.Low,
                        FilePath = filePath
                    });
                }

                pb.Update();
                Thread.Sleep(30);
            }

            pb.Finish();

            // Вывод результатов
            PrintResults(findings, database.Count);

            return findings;
        }

        private void PrintResults(List<Finding> findings, int total)
        {
            var critical = findings.Where(f => f.Severity == ThreatSeverity.Critical).ToList();
            var medium = findings.Where(f => f.Severity == ThreatSeverity.Medium).ToList();

            if (critical.Any())
            {
                C.RedLine("\n[!!!] ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ ПОДМЕНЫ:");
                foreach (var f in critical)
                {
                    C.RedLine($"  [✗] {f.Component}");
                    foreach (string detail in f.Details)
                        Console.WriteLine($"      {detail}");
                }
            }

            if (medium.Any())
            {
                C.YellowLine("\n[!] Отсутствующие файлы:");
                foreach (var f in medium)
                    C.YellowLine($"  [!] {f.Component}");
            }

            int ok = total - findings.Count;
            if (ok > 0)
                C.GreenLine($"\n  [✓] В порядке: {ok}/{total}");
        }
    }
}