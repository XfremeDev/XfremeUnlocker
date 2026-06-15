using System.Collections.Generic;

namespace XfremeUnlocker.Models
{
    public class Finding
    {
        public string Component { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public List<string> Details { get; set; } = new List<string>();
        public string FilePath { get; set; }
        public string RegistryKey { get; set; }
        public bool RemediationPossible { get; set; }
    }
}