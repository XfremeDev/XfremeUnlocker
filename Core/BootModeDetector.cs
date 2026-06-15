using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using XfremeUnlocker.Models;

namespace XfremeUnlocker.Core
{
    public class BootModeDetector
    {
        [DllImport("kernel32.dll")]
        static extern uint GetSystemMetrics(uint smIndex);

        const uint SM_CLEANBOOT = 67;

        public static SystemInfo Detect()
        {
            var info = new SystemInfo();

            // Определение режима загрузки
            info.BootMode = DetectBootMode();

            // Определение системного диска
            info.SystemDrive = FindSystemDrive();

            // Определение архитектуры
            if (info.SystemDrive != null)
            {
                info.Architecture = Directory.Exists(
                    Path.Combine(info.SystemDrive, "Windows", "SysWOW64")) ? "x64" : "x86";
            }

            // Версия Windows
            info.WindowsVersion = GetWindowsVersion();

            // Имя компьютера
            info.ComputerName = Environment.MachineName;

            return info;
        }

        private static BootMode DetectBootMode()
        {
            try
            {
                uint cleanBoot = GetSystemMetrics(SM_CLEANBOOT);

                if (cleanBoot == 0)
                    return BootMode.Normal;

                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SafeBoot\Option"))
                {
                    if (key != null)
                    {
                        string optionValue = key.GetValue("OptionValue") as string;
                        if (optionValue != null)
                        {
                            switch (optionValue)
                            {
                                case "Minimal": return BootMode.SafeMode;
                                case "Network": return BootMode.SafeModeWithNetworking;
                                case "DsRepair": return BootMode.SafeModeWithCommandPrompt;
                            }
                        }
                    }
                }

                // Проверка WinPE/WinRE
                string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
                if (systemDrive.ToUpper() == "X:")
                    return BootMode.RecoveryEnvironment;
            }
            catch { }

            return BootMode.Unknown;
        }

        private static string FindSystemDrive()
        {
            string sd = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
            if (Directory.Exists(Path.Combine(sd, "Windows", "System32")))
                return sd;

            for (char c = 'C'; c <= 'Z'; c++)
            {
                string drive = $"{c}:";
                try
                {
                    if (Directory.Exists(Path.Combine(drive, "Windows", "System32")))
                        return drive;
                }
                catch { }
            }
            return null;
        }

        private static string GetWindowsVersion()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        string productName = key.GetValue("ProductName") as string;
                        string buildNumber = key.GetValue("CurrentBuild") as string;
                        return $"{productName} (Build {buildNumber})";
                    }
                }
            }
            catch { }
            return "Неизвестно";
        }
    }
}