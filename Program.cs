using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using XfremeUnlocker.Core;
using XfremeUnlocker.Models;
using XfremeUnlocker.Modules;
using XfremeUnlocker.UI;

namespace XfremeUnlocker
{
    class Program
    {
        static SystemInfo sysInfo;
        static List<Finding> allFindings = new List<Finding>();
        static DateTime scanStartTime;

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "XfremeUnlocker v0.1 Beta";

            // Проверка прав администратора
            if (!PrivilegeManager.IsAdministrator())
            {
                Console.WriteLine("[*] Требуются права администратора. Перезапуск...");
                Thread.Sleep(1000);
                PrivilegeManager.RestartAsAdministrator();
                return;
            }

            // Включаем необходимые привилегии
            PrivilegeManager.EnableRequiredPrivileges();

            // Очистка и баннер
            Console.Clear();
            ConsoleUI.PrintBanner();

            // Загрузка
            LoadingAnimation();

            // Системная информация
            ConsoleUI.SmoothProgress("Сканирование системы...", 1.0);

            var scanner = new SystemScanner();
            sysInfo = scanner.FullScan();
            sysInfo.IsAdmin = PrivilegeManager.IsAdministrator();

            // Вывод информации
            Console.WriteLine();
            ConsoleUI.PrintSystemInfo(sysInfo);

            // Показ привилегий
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(PrivilegeManager.GetPrivilegeInfo());
            Console.ResetColor();

            // Запуск проверок
            scanStartTime = DateTime.Now;
            RunAllScans();

            // Итоги
            PrintSummary();

            // Завершение
            TimeSpan elapsed = DateTime.Now - scanStartTime;
            Console.WriteLine($"\n  Время сканирования: {elapsed.TotalSeconds:F0} сек");
            Console.WriteLine("\nНажмите любую клавишу для выхода...");
            Console.ReadKey();
        }

        static void LoadingAnimation()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[*] Инициализация XfremeUnlocker v0.1 Beta...");
            Console.ResetColor();

            string[] stages = {
                "Загрузка модулей ядра",
                "Инициализация сканера",
                "Подготовка анализатора",
                "Настройка детектора",
                "Активация привилегий",
                "Калибровка системы"
            };

            for (int i = 0; i < stages.Length; i++)
            {
                Console.Write($"    [{i + 1}/{stages.Length}] {stages[i]}...");
                Thread.Sleep(200);
                for (int j = 0; j < 8; j++)
                {
                    Console.Write(".");
                    Thread.Sleep(40);
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(" OK");
                Console.ResetColor();
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[✓] Система готова к работе");
            Console.ResetColor();
            Thread.Sleep(300);
        }

        static void RunAllScans()
        {
            if (sysInfo.SystemDrive == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[!!!] Системный диск не найден!");
                Console.ResetColor();
                return;
            }

            bool fullAccess = (sysInfo.Mode == OperationMode.Full);

            // Этап 1: Системные компоненты
            PrintStage(1, 4, "ПРОВЕРКА СИСТЕМНЫХ КОМПОНЕНТОВ");

            var fileChecker = new FileIntegrityChecker(sysInfo.SystemDrive);
            allFindings.AddRange(fileChecker.Scan());
            Thread.Sleep(300);

            var hostsAnalyzer = new HostsFileAnalyzer(sysInfo.SystemDrive);
            allFindings.AddRange(hostsAnalyzer.Scan());
            Thread.Sleep(300);

            // Этап 2: Реестр и автозагрузка
            PrintStage(2, 4, "АНАЛИЗ РЕЕСТРА И АВТОЗАГРУЗКИ");

            var registryAnalyzer = new RegistryAnalyzer(sysInfo.SystemDrive);
            allFindings.AddRange(registryAnalyzer.Scan());
            Thread.Sleep(300);

            var taskScanner = new TaskSchedulerScanner(sysInfo.SystemDrive);
            allFindings.AddRange(taskScanner.Scan());
            Thread.Sleep(300);

            // Этап 3: Безопасность
            PrintStage(3, 4, "ПРОВЕРКА БЕЗОПАСНОСТИ");

            var uacManager = new UACManager(sysInfo.SystemDrive, sysInfo.IsAdmin);
            allFindings.AddRange(uacManager.Scan());
            Thread.Sleep(300);

            // Этап 4: Очистка
            PrintStage(4, 4, "ОЧИСТКА СИСТЕМЫ");

            var substManager = new SubstDriveManager(fullAccess);
            substManager.Scan();
        }

        static void PrintStage(int current, int total, string name)
        {
            Console.WriteLine($"\n┌──────────────────────────────────────────────┐");
            Console.WriteLine($"│  ЭТАП {current}/{total}: {name.PadRight(30)}│");
            Console.WriteLine($"└──────────────────────────────────────────────┘");
            Thread.Sleep(200);
        }

        static void PrintSummary()
        {
            int critical = allFindings.FindAll(f => f.Severity == ThreatSeverity.Critical).Count;
            int high = allFindings.FindAll(f => f.Severity == ThreatSeverity.High).Count;
            int medium = allFindings.FindAll(f => f.Severity == ThreatSeverity.Medium).Count;
            int low = allFindings.FindAll(f => f.Severity == ThreatSeverity.Low).Count;

            Console.WriteLine("\n\n╔═══════════════════ РЕЗУЛЬТАТЫ ПРОВЕРКИ ═══════════════════╗");
            Console.WriteLine("║                                                              ");

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"║  КРИТИЧЕСКИХ УГРОЗ: {critical}");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"║  Серьезных проблем: {high}");
            Console.ResetColor();
            Console.WriteLine($"║  Подозрительных находок: {medium}");
            Console.WriteLine($"║  Мелких замечаний: {low}");
            Console.WriteLine($"║  ВСЕГО НАХОДОК: {allFindings.Count}");
            Console.WriteLine("║                                                              ");

            if (critical > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("║  [!!!] ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ УГРОЗЫ БЕЗОПАСНОСТИ!");
                Console.WriteLine("║  [!!!] НЕМЕДЛЕННО загрузитесь в WinRE для полной очистки!");
            }
            else if (high > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("║  [!] Требуется внимание специалиста по безопасности");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("║  [✓] Критических угроз не обнаружено");
            }

            Console.ResetColor();
            Console.WriteLine("║                                                              ");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");

            // Показываем детали критических находок
            if (critical > 0)
            {
                Console.WriteLine("\n  Детали критических находок:");
                foreach (var finding in allFindings.Where(f => f.Severity == ThreatSeverity.Critical))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"    • {finding.Component}: {finding.Description}");
                    Console.ResetColor();
                }
            }
        }
    }
}