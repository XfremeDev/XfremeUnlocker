using System;
using System.Threading;

namespace XfremeUnlocker.UI
{
    public static class ConsoleUI
    {
        public static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗  ██╗███████╗██████╗ ███████╗███╗   ███╗███████╗       ║
║   ╚██╗██╔╝██╔════╝██╔══██╗██╔════╝████╗ ████║██╔════╝       ║
║    ╚███╔╝ █████╗  ██████╔╝█████╗  ██╔████╔██║█████╗         ║
║    ██╔██╗ ██╔══╝  ██╔══██╗██╔══╝  ██║╚██╔╝██║██╔══╝         ║
║   ██╔╝ ██╗██║     ██║  ██║███████╗██║ ╚═╝ ██║███████╗       ║
║   ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝       ║
║                                                              ║
║        Инструмент очистки системы от вредоносного ПО         ║
║                 Версия 0.1 Beta (Open Source)                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
");
            Console.ResetColor();
        }

        public static void PrintSystemInfo(Models.SystemInfo info)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔══════════════ ИНФОРМАЦИЯ О СИСТЕМЕ ══════════════╗");
            Console.ResetColor();

            Console.WriteLine($"║  Режим загрузки: {info.BootMode}");
            Console.WriteLine($"║  Системный диск: {info.SystemDrive ?? "Не найден"}");
            Console.WriteLine($"║  Версия Windows: {info.WindowsVersion}");
            Console.WriteLine($"║  Архитектура: {info.Architecture ?? "Неизвестно"}");
            Console.WriteLine($"║  Имя компьютера: {info.ComputerName}");
            Console.WriteLine($"║  Права: {(info.IsAdmin ? "Администратор" : "Пользователь")}");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╚════════════════════════════════════════════════════╝");
            Console.ResetColor();
        }

        public static bool AskConfirmation(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"[?] {message} (Д/Н): ");
            Console.ResetColor();

            string response = Console.ReadLine()?.Trim().ToLower();
            return response == "д" || response == "да" || response == "y" || response == "yes";
        }

        /// <summary>
        /// Плавный прогресс-бар
        /// </summary>
        public static void SmoothProgress(string message, double duration = 0.6)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[*] {message}");
            Console.ResetColor();

            int steps = 15;
            for (int i = 0; i <= steps; i++)
            {
                int percent = (int)(100.0 * i / steps);
                string bar = new string('█', i * 2) + new string('░', 30 - i * 2);
                Console.Write($"\r    |{bar}| {percent}%");
                Thread.Sleep((int)(duration * 1000 / steps));
            }
            Console.WriteLine();
        }
    }
}