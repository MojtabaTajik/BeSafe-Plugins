using System;
using System.Diagnostics;
using System.Collections.Generic;
using PluginSDK;
using BeSafeRegistryScanner.Scanners;
using SharedTypes.Watchers.RegistryWatcherTypes;

namespace BeSafeRegistryScanner
{
    public class RegistryScanner : IBeSafePlugin
    {
        private PluginInfo _pluginInfo;


        private List<IScanner> _scanners = new List<IScanner>
        {
            new ConstantScanner(),
        };

        public RegistryScanner()
        {
            _pluginInfo = new PluginInfo
            {
                Name = "Registry Scanner",
                Version = new Version(1, 0),
                Type = PluginType.Registry,
                Description = "This plugin scan registry values for threats"
            };
        }

        public PluginInfo GetPluginInfo()
        {
            return _pluginInfo;
        }

        public PluginResult ScanFile(dynamic parameters, bool canFightWithThreat)
        {
            throw new NotImplementedException();
        }

        public PluginResult ScanModule(dynamic parameters, bool canFightWithThreat)
        {
            throw new NotImplementedException();
        }

        public PluginResult ScanProcess(dynamic parameters, bool canFightWithThreat)
        {
            throw new NotImplementedException();
        }

        public PluginResult ScanRegistry(dynamic parameters, bool canFightWithThreat)
        {
            try
            {
                ChangedValueInfo regitryValueInfo = (ChangedValueInfo)parameters;

                PluginResult result = new PluginResult
                {
                    PluginInfo = _pluginInfo,
                    ScannedObject = parameters,
                    RiskRate = ThreatRiskRates.NoRisk,
                };

                foreach (IScanner scanner in _scanners)
                {
                    PluginResult tempResut = new ConstantScanner().Scan(regitryValueInfo);

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