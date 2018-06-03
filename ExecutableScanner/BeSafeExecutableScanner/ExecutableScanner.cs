using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using BeSafeExecutableScanner.Scanners;
using PluginSDK;
using PluginSDK.PluginInterfaces;

namespace BeSafeExecutableScanner
{
    public class ExecutableScanner : IBeSafeFilePlugin
    {
        private PluginInfo _pluginInfo;

        private readonly List<IScanner> _scanners = new List<IScanner>
        {
            
        };

        public PluginInfo GetPluginInfo()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();

            _pluginInfo = new PluginInfo
            {
                Name = "Executable Scanner",
                Type = PluginType.File,
                Version = new Version(FileVersionInfo.GetVersionInfo(assembly.Location).FileVersion),
                Description = ".exe,.dll,.scr"
            };

            return _pluginInfo;
        }

        public PluginResult Scan(string filePath, bool canFightWithThreat)
        {
            try
            {
                PluginResult result = new PluginResult
                {
                    PluginInfo = _pluginInfo,
                    ScannedObject = filePath,
                    RiskRate = ThreatRiskRates.NoRisk,
                };

                foreach (IScanner scanner in _scanners)
                {
                    PluginResult tempResut = scanner.Scan(filePath);

                    // On first threat found return the threat and ignore other scanners
                    if (tempResut.RiskRate != ThreatRiskRates.NoRisk)
                    {
                        result.RiskRate = tempResut.RiskRate;
                        result.Message = tempResut.Message;
                        break;
                    }
                }

                if (canFightWithThreat)
                {
                    // Fight with the registry value! for example remove it :)
                }

                return result;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"EX : {ex.Message}");
                return null;
            }
        }
    }
}