using System;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using PluginSDK;
using SharedTypes.Watchers.RegistryWatcherTypes;

namespace BeSafeRegistryScanner.Scanners
{
    internal class ConstantScanner : IScanner
    {
        private List<BadValueItem> badValueItems = new List<BadValueItem>
        {
            new BadValueItem{BadValue = ".exe", Description = "Windows stnadard executable file", Risk = ThreatRiskRates.HighRisk},
            new BadValueItem{BadValue = ".bat", Description = "Batch file that possible to run malicious scripts", Risk = ThreatRiskRates.HighRisk},
            new BadValueItem{BadValue = ".com", Description = "COM file that possible to run malicious code", Risk = ThreatRiskRates.HighRisk},
            new BadValueItem{BadValue = ".bin", Description = "Binary file that possible to run malicious code", Risk = ThreatRiskRates.HighRisk},
            new BadValueItem{BadValue = ".vbs", Description = "Windows VBScript file that possible to run malicious scripts", Risk = ThreatRiskRates.HighRisk},
            new BadValueItem{BadValue = ".cpl", Description = "Windows ControlPanel component which is type of standard Windows executable file", Risk = ThreatRiskRates.LowRisk},
            new BadValueItem{BadValue = ".ps1", Description = "Windows Powershell script file that possible to run malicious scripts", Risk = ThreatRiskRates.HighRisk},
            new BadValueItem{BadValue = "rundll32", Description = "Rundll32 loads 32-bit DLL into memory and invoke exported function", Risk = ThreatRiskRates.HighRisk},
            new BadValueItem{BadValue = "cmd", Description = "Rundll32 loads 32-bit DLL into memory and invoke exported function", Risk = ThreatRiskRates.HighRisk},
            new BadValueItem{BadValue = "powershell", Description = "Rundll32 loads 32-bit DLL into memory and invoke exported function", Risk = ThreatRiskRates.HighRisk},
        };

        public PluginResult Scan(ChangedValueInfo valueToScan)
        {
            PluginResult pluginResult = new PluginResult { RiskRate = ThreatRiskRates.NoRisk };
            try
            {
                if (string.IsNullOrEmpty(valueToScan?.ChangedObject?.Value))
                    return pluginResult;

                BadValueItem badValueItem = badValueItems.FirstOrDefault(s => valueToScan.ChangedObject.Value.ToLower().Contains(s.BadValue.ToLower()));

                if (badValueItem == null)
                    return pluginResult;

                pluginResult.RiskRate = badValueItem.Risk;
                pluginResult.Message = badValueItem.Description;

                return pluginResult;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                return null;
            }
        }
    }
}