namespace XfremeUnlocker.Models
{
    public class SystemInfo
    {
        public string SystemDrive { get; set; }
        public BootMode BootMode { get; set; } = BootMode.Unknown;
        public OperationMode Mode { get; set; } = OperationMode.Restricted;
        public string WindowsVersion { get; set; }
        public string Architecture { get; set; }
        public bool IsAdmin { get; set; }
        public string ComputerName { get; set; }
        public int ProcessorCount { get; set; }
        public long TotalMemory { get; set; }
    }
}