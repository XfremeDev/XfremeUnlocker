using System;
using System.Collections.Generic;
using Microsoft.Win32;
using XfremeUnlocker.Models;
using XfremeUnlocker.UI;

namespace XfremeUnlocker.Modules
{
    /// <summary>
    /// Управление настройками User Account Control (UAC)
    /// </summary>
    public class UACManager
    {
        private readonly bool isAdmin;
        private readonly string systemDrive;

        // Безопасные значения параметров UAC
        private static readonly Dictionary<string, (int SafeValue, string Description, string Risk)> UACParameters =
            new Dictionary<string, (int, string, string)>
            {
                ["EnableLUA"] = (1, "Включение UAC",
                "Без UAC любая программа может получить права администратора"),
                ["ConsentPromptBehaviorAdmin"] = (2, "Запрос подтверждения для админов",
                "Без запроса вредоносное ПО незаметно повышает привилегии"),
                ["EnableInstallerDetection"] = (1, "Обнаружение установщиков",
                "Установщики могут запускаться без ведома пользователя"),
                ["PromptOnSecureDesktop"] = (1, "Запрос на безопасном рабочем столе",
                "Вредоносное ПО может симулировать нажатия на запросах UAC"),
                ["EnableVirtualization"] = (1, "Виртуализация файлов и реестра",
                "Старые программы могут повредить системные файлы"),
                ["FilterAdministratorToken"] = (1, "Фильтрация токенов администратора",
                "Вредоносное ПО может использовать токены для повышения прав"),
                ["ValidateAdminCodeSignatures"] = (1, "Проверка цифровых подписей",
                "Неподписанный код может выполняться с повышенными правами")
            };

        public UACManager(string drive, bool adminRights)
        {
            systemDrive = drive;
            isAdmin = adminRights;
        }

        /// <summary>
        /// Проверяет и усиливает настройки UAC
        /// </summary>
        public List<Finding> Scan()
        {
            Console.WriteLine("\n═══ ПРОВЕРКА НАСТРОЕК UAC ═══");
            C.DarkGray("[*] UAC (Контроль учетных записей) - защита от повышения прав");

            var findings = new List<Finding>();

            if (!isAdmin)
            {
                C.YellowLine("  [!] Требуются права администратора для проверки UAC");
                findings.Add(new Finding
                {
                    Component = "UAC",
                    Description = "Нет прав для проверки",
                    Severity = ThreatSeverity.Info
                });
                return findings;
            }

            ProgressBar.Smooth("Анализ параметров безопасности...", 0.6);

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", true))
                {
                    if (key == null)
                    {
                        C.RedLine("  [-] Ключ реестра UAC не найден");
                        return findings;
                    }

                    var fixesNeeded = new List<(string Name, int SafeValue, string Description)>();

                    Console.WriteLine("\n  Текущие настройки UAC:");
                    Console.WriteLine("  " + new string('─', 50));

                    foreach (var kvp in UACParameters)
                    {
                        string paramName = kvp.Key;
                        int safeValue = kvp.Value.SafeValue;
                        string description = kvp.Value.Description;
                        string risk = kvp.Value.Risk;

                        object currentValue = key.GetValue(paramName);

                        if (currentValue == null)
                        {
                            C.YellowLine($"  [!] {description}: параметр отсутствует");
                            Console.WriteLine($"      Риск: {risk}");
                            fixesNeeded.Add((paramName, safeValue, description));
                        }
                        else if ((int)currentValue != safeValue)
                        {
                            C.RedLine($"  [✗] {description}: {(int)currentValue} (безопасное: {safeValue})");
                            Console.WriteLine($"      Риск: {risk}");
                            fixesNeeded.Add((paramName, safeValue, description));
                        }
                        else
                        {
                            C.GreenLine($"  [✓] {description}: {(int)currentValue}");
                        }
                    }

                    Console.WriteLine("  " + new string('─', 50));

                    // Если нужны исправления
                    if (fixesNeeded.Count > 0)
                    {
                        C.YellowLine($"\n  [!] Найдено небезопасных параметров: {fixesNeeded.Count}");

                        if (ConsoleUI.AskConfirmation("Установить МАКСИМАЛЬНЫЙ уровень защиты UAC?"))
                        {
                            ApplyFixes(key, fixesNeeded);

                            findings.Add(new Finding
                            {
                                Component = "UAC",
                                Description = $"Исправлено параметров: {fixesNeeded.Count}",
                                Severity = ThreatSeverity.Info,
                                RemediationPossible = true
                            });
                        }
                    }
                    else
                    {
                        C.GreenLine("\n  [✓] Все параметры UAC настроены безопасно");
                    }
                }
            }
            catch (Exception ex)
            {
                C.RedLine($"  [-] Ошибка проверки UAC: {ex.Message}");
                findings.Add(new Finding
                {
                    Component = "UAC",
                    Description = $"Ошибка: {ex.Message}",
                    Severity = ThreatSeverity.High
                });
            }

            return findings;
        }

        /// <summary>
        /// Применяет безопасные настройки UAC
        /// </summary>
        private void ApplyFixes(RegistryKey key,
            List<(string Name, int SafeValue, string Description)> fixes)
        {
            ProgressBar.Smooth("Применение безопасных настроек...", 0.5);

            int applied = 0;
            foreach (var (name, safeValue, description) in fixes)
            {
                try
                {
                    key.SetValue(name, safeValue, RegistryValueKind.DWord);
                    C.GreenLine($"  [+] {description}: установлено {safeValue}");
                    applied++;
                }
                catch (Exception ex)
                {
                    C.RedLine($"  [-] Ошибка {description}: {ex.Message}");
                }
            }

            Console.WriteLine($"\n  Применено: {applied}/{fixes.Count}");
            C.YellowLine("  [!] Изменения вступят в силу после перезагрузки системы");
        }
    }
}