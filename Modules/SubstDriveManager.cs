using System;
using System.Collections.Generic;
using System.Diagnostics;
using XfremeUnlocker.Models;
using XfremeUnlocker.UI;

namespace XfremeUnlocker.Modules
{
    /// <summary>
    /// Управление виртуальными SUBST дисками
    /// </summary>
    public class SubstDriveManager
    {
        private readonly bool canModify;

        public SubstDriveManager(bool fullAccess)
        {
            canModify = fullAccess;
        }

        /// <summary>
        /// Проверяет и отключает виртуальные диски SUBST
        /// </summary>
        public void Scan()
        {
            Console.WriteLine("\n═══ ПРОВЕРКА ВИРТУАЛЬНЫХ ДИСКОВ (SUBST) ═══");
            C.DarkGray("[*] Поиск виртуальных дисков, созданных вредоносным ПО");

            if (!canModify)
            {
                C.YellowLine("  [!] Операция недоступна в текущем режиме");
                C.YellowLine("  [!] Требуется среда восстановления (WinRE/WinPE)");
                return;
            }

            ProgressBar.Smooth("Поиск виртуальных дисков...", 0.6);

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "subst",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    if (process == null)
                    {
                        C.RedLine("  [-] Не удалось запустить SUBST");
                        return;
                    }

                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (string.IsNullOrWhiteSpace(output))
                    {
                        C.GreenLine("  [✓] Виртуальных дисков SUBST не обнаружено");
                        return;
                    }

                    // Парсим вывод
                    var drives = new List<(string Drive, string Target)>();
                    string[] lines = output.Trim().Split('\n');

                    foreach (string line in lines)
                    {
                        if (line.Contains(":\\"))
                        {
                            string drive = line.Split(new[] { ":\\" },
                                StringSplitOptions.None)[0] + ":";
                            string target = line.Contains("=>") ?
                                line.Split(new[] { "=>" },
                                    StringSplitOptions.None)[1].Trim() : "неизвестно";
                            drives.Add((drive, target));
                        }
                    }

                    if (drives.Count > 0)
                    {
                        C.RedLine($"\n  [✗] Найдено виртуальных дисков: {drives.Count}");

                        foreach (var (drive, target) in drives)
                        {
                            Console.WriteLine($"      {drive} -> {target}");
                        }

                        if (ConsoleUI.AskConfirmation("Отключить все виртуальные диски?"))
                        {
                            RemoveDrives(drives);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                C.RedLine($"  [-] Ошибка: {ex.Message}");
            }
        }

        /// <summary>
        /// Отключает виртуальные диски
        /// </summary>
        private void RemoveDrives(List<(string Drive, string Target)> drives)
        {
            int removed = 0;
            int failed = 0;

            foreach (var (drive, _) in drives)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "subst",
                        Arguments = $"{drive} /d",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (Process process = Process.Start(psi))
                    {
                        process?.WaitForExit(3000);

                        if (process?.ExitCode == 0)
                        {
                            C.GreenLine($"    [+] {drive} отключен");
                            removed++;
                        }
                        else
                        {
                            C.RedLine($"    [-] Ошибка отключения {drive}");
                            failed++;
                        }
                    }
                }
                catch
                {
                    C.RedLine($"    [-] Ошибка отключения {drive}");
                    failed++;
                }
            }

            Console.WriteLine($"\n  Отключено: {removed}, ошибок: {failed}");
        }
    }
}