using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using XfremeUnlocker.Models;
using XfremeUnlocker.UI;

namespace XfremeUnlocker.Core
{
    /// <summary>
    /// Основной сканер системы - собирает информацию о системе
    /// </summary>
    public class SystemScanner
    {
        #region Win32 API

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll")]
        static extern void GlobalMemoryStatusEx(out MEMORYSTATUSEX lpBuffer);

        [DllImport("kernel32.dll")]
        static extern uint GetSystemMetrics(uint smIndex);

        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        const uint SM_CLEANBOOT = 67;

        #endregion

        private SystemInfo systemInfo;

        public SystemScanner()
        {
            systemInfo = new SystemInfo();
        }

        /// <summary>
        /// Выполняет полное сканирование системы
        /// </summary>
        public SystemInfo FullScan()
        {
            Console.WriteLine("\n═══ СКАНИРОВАНИЕ СИСТЕМЫ ═══");

            ProgressBar.Smooth("Сбор информации о системе...", 1.0);

            DetectBootMode();
            DetectWindowsVersion();
            DetectArchitecture();
            DetectHardware();
            DetectSystemDrive();
            DetectPrivileges();
            DetectRunningProcesses();
            DetectInstalledSoftware();
            DetectSecuritySoftware();

            return systemInfo;
        }

        /// <summary>
        /// Определяет режим загрузки системы
        /// </summary>
        private void DetectBootMode()
        {
            try
            {
                uint cleanBoot = GetSystemMetrics(SM_CLEANBOOT);

                if (cleanBoot == 0)
                {
                    string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
                    if (systemDrive.ToUpper() == "X:")
                    {
                        systemInfo.BootMode = BootMode.RecoveryEnvironment;
                        systemInfo.Mode = OperationMode.Full;
                    }
                    else
                    {
                        systemInfo.BootMode = BootMode.Normal;
                        systemInfo.Mode = OperationMode.ReadOnly;
                    }
                }
                else
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\SafeBoot\Option"))
                    {
                        if (key != null)
                        {
                            string optionValue = key.GetValue("OptionValue") as string;
                            switch (optionValue)
                            {
                                case "Minimal":
                                    systemInfo.BootMode = BootMode.SafeMode;
                                    systemInfo.Mode = OperationMode.Full;
                                    break;
                                case "Network":
                                    systemInfo.BootMode = BootMode.SafeModeWithNetworking;
                                    systemInfo.Mode = OperationMode.Full;
                                    break;
                                case "DsRepair":
                                    systemInfo.BootMode = BootMode.SafeModeWithCommandPrompt;
                                    systemInfo.Mode = OperationMode.Full;
                                    break;
                            }
                        }
                    }
                }

                C.GreenLine($"  [✓] Режим загрузки: {systemInfo.BootMode}");
            }
            catch (Exception ex)
            {
                C.RedLine($"  [-] Ошибка определения режима: {ex.Message}");
            }
        }

        /// <summary>
        /// Определяет версию Windows
        /// </summary>
        private void DetectWindowsVersion()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        string productName = key.GetValue("ProductName") as string;
                        string releaseId = key.GetValue("ReleaseId") as string;
                        string buildNumber = key.GetValue("CurrentBuild") as string;

                        systemInfo.WindowsVersion = $"{productName}";
                        if (!string.IsNullOrEmpty(releaseId))
                            systemInfo.WindowsVersion += $" ({releaseId})";
                        if (!string.IsNullOrEmpty(buildNumber))
                            systemInfo.WindowsVersion += $" Build {buildNumber}";
                    }
                }

                if (string.IsNullOrEmpty(systemInfo.WindowsVersion))
                {
                    systemInfo.WindowsVersion = Environment.OSVersion.VersionString;
                }

                C.GreenLine($"  [✓] Версия: {systemInfo.WindowsVersion}");
            }
            catch
            {
                systemInfo.WindowsVersion = Environment.OSVersion.VersionString;
                C.YellowLine($"  [!] Версия: {systemInfo.WindowsVersion}");
            }
        }

        /// <summary>
        /// Определяет архитектуру системы
        /// </summary>
        private void DetectArchitecture()
        {
            try
            {
                systemInfo.Architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86";
                C.GreenLine($"  [✓] Архитектура: {systemInfo.Architecture}");
            }
            catch
            {
                systemInfo.Architecture = "Неизвестно";
                C.RedLine("  [-] Ошибка определения архитектуры");
            }
        }

        /// <summary>
        /// Определяет аппаратное обеспечение
        /// </summary>
        private void DetectHardware()
        {
            // Процессор
            try
            {
                SYSTEM_INFO sysInfo;
                GetSystemInfo(out sysInfo);
                systemInfo.ProcessorCount = (int)sysInfo.dwNumberOfProcessors;
                C.GreenLine($"  [✓] CPU: {systemInfo.ProcessorCount} ядер");
            }
            catch
            {
                systemInfo.ProcessorCount = Environment.ProcessorCount;
                C.GreenLine($"  [✓] CPU: {systemInfo.ProcessorCount} ядер");
            }

            // Память
            try
            {
                MEMORYSTATUSEX memStatus = new MEMORYSTATUSEX();
                memStatus.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
                GlobalMemoryStatusEx(out memStatus);
                systemInfo.TotalMemory = (long)(memStatus.ullTotalPhys / (1024 * 1024));
                C.GreenLine($"  [✓] RAM: {systemInfo.TotalMemory} MB");
            }
            catch
            {
                systemInfo.TotalMemory = 0;
                C.YellowLine("  [!] Не удалось определить объем RAM");
            }
        }

        /// <summary>
        /// Находит системный диск
        /// </summary>
        private void DetectSystemDrive()
        {
            try
            {
                string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";

                if (Directory.Exists(Path.Combine(systemDrive, "Windows", "System32")))
                {
                    systemInfo.SystemDrive = systemDrive;
                }
                else
                {
                    for (char c = 'C'; c <= 'Z'; c++)
                    {
                        string drive = $"{c}:";
                        try
                        {
                            if (Directory.Exists(Path.Combine(drive, "Windows", "System32")))
                            {
                                systemInfo.SystemDrive = drive;
                                break;
                            }
                        }
                        catch { }
                    }
                }

                if (systemInfo.SystemDrive != null)
                {
                    DriveInfo di = new DriveInfo(systemInfo.SystemDrive);
                    long freeGB = di.TotalFreeSpace / (1024 * 1024 * 1024);
                    long totalGB = di.TotalSize / (1024 * 1024 * 1024);

                    C.GreenLine($"  [✓] Системный диск: {systemInfo.SystemDrive} " +
                               $"(свободно: {freeGB} GB из {totalGB} GB)");
                }
                else
                {
                    C.RedLine("  [-] Системный диск не найден!");
                }
            }
            catch (Exception ex)
            {
                C.RedLine($"  [-] Ошибка определения диска: {ex.Message}");
            }
        }

        /// <summary>
        /// Проверяет привилегии
        /// </summary>
        private void DetectPrivileges()
        {
            try
            {
                systemInfo.IsAdmin = PrivilegeManager.IsAdministrator();
                systemInfo.ComputerName = Environment.MachineName;

                if (systemInfo.IsAdmin)
                {
                    C.GreenLine($"  [✓] Права: Администратор");
                    C.GreenLine($"  [✓] Компьютер: {systemInfo.ComputerName}");

                    if (PrivilegeManager.EnableRequiredPrivileges())
                    {
                        C.GreenLine("  [✓] Привилегии активированы");
                    }
                }
                else
                {
                    C.YellowLine("  [!] Права: Пользователь");
                    C.GreenLine($"  [✓] Компьютер: {systemInfo.ComputerName}");
                }
            }
            catch (Exception ex)
            {
                C.RedLine($"  [-] Ошибка: {ex.Message}");
            }
        }

        /// <summary>
        /// Анализирует запущенные процессы
        /// </summary>
        private void DetectRunningProcesses()
        {
            try
            {
                Process[] processes = Process.GetProcesses();
                C.GreenLine($"  [✓] Запущено процессов: {processes.Length}");
            }
            catch (Exception ex)
            {
                C.RedLine($"  [-] Ошибка: {ex.Message}");
            }
        }

        /// <summary>
        /// Обнаруживает установленное ПО
        /// </summary>
        private void DetectInstalledSoftware()
        {
            try
            {
                int count = 0;
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                {
                    if (key != null)
                    {
                        count += key.GetSubKeyNames().Length;
                    }
                }

                if (Environment.Is64BitOperatingSystem)
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"))
                    {
                        if (key != null)
                        {
                            count += key.GetSubKeyNames().Length;
                        }
                    }
                }

                C.GreenLine($"  [✓] Установлено программ: ~{count}");
            }
            catch
            {
                C.DarkGray("  [i] Не удалось подсчитать программы");
            }
        }

        /// <summary>
        /// Обнаруживает защитное ПО
        /// </summary>
        private void DetectSecuritySoftware()
        {
            try
            {
                var securityProcesses = new Dictionary<string, string>
                {
                    ["MsMpEng"] = "Windows Defender",
                    ["avp"] = "Kaspersky",
                    ["avast"] = "Avast",
                    ["egui"] = "ESET"
                };

                bool found = false;
                foreach (Process process in Process.GetProcesses())
                {
                    try
                    {
                        if (securityProcesses.ContainsKey(process.ProcessName))
                        {
                            C.GreenLine($"  [✓] Защита: {securityProcesses[process.ProcessName]}");
                            found = true;
                            break;
                        }
                    }
                    catch { }
                }

                if (!found)
                {
                    C.RedLine("  [✗] Антивирус не обнаружен!");
                }
            }
            catch
            {
                C.DarkGray("  [i] Не удалось проверить антивирус");
            }
        }
    }
}