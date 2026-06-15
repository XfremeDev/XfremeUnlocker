using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace XfremeUnlocker.Core
{
    /// <summary>
    /// Управление привилегиями и правами доступа
    /// </summary>
    public class PrivilegeManager
    {
        #region Win32 API для токенов и привилегий

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public long Luid;
            public uint Attributes;
        }

        const uint TOKEN_QUERY = 0x0008;
        const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        // Необходимые привилегии
        private static readonly string[] RequiredPrivileges = {
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeSecurityPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeDebugPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeLoadDriverPrivilege",
            "SeShutdownPrivilege"
        };

        #endregion

        /// <summary>
        /// Проверяет, запущена ли программа от администратора
        /// </summary>
        public static bool IsAdministrator()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Перезапускает программу с правами администратора
        /// </summary>
        public static void RestartAsAdministrator()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = Process.GetCurrentProcess().MainModule?.FileName ??
                               System.Reflection.Assembly.GetExecutingAssembly().Location,
                    UseShellExecute = true,
                    Verb = "runas"
                };

                Process.Start(psi);
                Environment.Exit(0);
            }
            catch (Win32Exception)
            {
                Console.WriteLine("[!] Для работы программы требуются права администратора");
            }
        }

        /// <summary>
        /// Получает все привилегии, необходимые для работы
        /// </summary>
        public static bool EnableRequiredPrivileges()
        {
            IntPtr tokenHandle;

            if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                out tokenHandle))
            {
                return false;
            }

            try
            {
                foreach (string privilege in RequiredPrivileges)
                {
                    EnablePrivilege(tokenHandle, privilege);
                }
                return true;
            }
            finally
            {
                CloseHandle(tokenHandle);
            }
        }

        /// <summary>
        /// Включает конкретную привилегию для текущего процесса
        /// </summary>
        private static bool EnablePrivilege(IntPtr tokenHandle, string privilege)
        {
            try
            {
                long luid;
                if (!LookupPrivilegeValue(null, privilege, out luid))
                    return false;

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = SE_PRIVILEGE_ENABLED
                };

                return AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Проверяет целостность токена (защита от подделки)
        /// </summary>
        public static bool IsTokenIntegrityHigh()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    foreach (IdentityReference group in identity.Groups)
                    {
                        SecurityIdentifier sid = group as SecurityIdentifier;
                        if (sid != null)
                        {
                            // SID для высокого уровня целостности: S-1-16-12288
                            if (sid.Value == "S-1-16-12288")
                                return true;

                            // Системный уровень: S-1-16-16384
                            if (sid.Value == "S-1-16-16384")
                                return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// Проверяет, не отключен ли UAC через реестр
        /// </summary>
        public static bool IsUACDisabled()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    if (key == null) return false;

                    object enableLUA = key.GetValue("EnableLUA");
                    return enableLUA != null && (int)enableLUA == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Получает информацию о текущих привилегиях процесса
        /// </summary>
        public static string GetPrivilegeInfo()
        {
            var sb = new System.Text.StringBuilder();

            sb.AppendLine("Информация о привилегиях:");
            sb.AppendLine($"  Администратор: {IsAdministrator()}");
            sb.AppendLine($"  Высокая целостность: {IsTokenIntegrityHigh()}");
            sb.AppendLine($"  UAC отключен: {IsUACDisabled()}");

            return sb.ToString();
        }
    }
}