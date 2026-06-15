namespace XfremeUnlocker.Models
{
    public enum BootMode
    {
        Normal,
        SafeMode,
        SafeModeWithNetworking,
        SafeModeWithCommandPrompt,
        RecoveryEnvironment,
        Unknown
    }

    public enum ThreatSeverity
    {
        Critical,
        High,
        Medium,
        Low,
        Info
    }

    public enum OperationMode
    {
        Full,
        ReadOnly,
        Restricted
    }
}