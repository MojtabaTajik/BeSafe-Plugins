using System;
using PluginSDK;

namespace BeSafeExecutableScanner
{
    public class ExecutableScanner : IBeSafePlugin
    {
        public PluginInfo GetPluginInfo()
        {
            throw new NotImplementedException();
        }

        public PluginResult ScanFile(dynamic parameters, bool canFightWithThreat)
        {
            throw new NotImplementedException();
        }

        public PluginResult ScanRegistry(dynamic parameters, bool canFightWithThreat)
        {
            throw new NotImplementedException();
        }

        public PluginResult ScanProcess(dynamic parameters, bool canFightWithThreat)
        {
            throw new NotImplementedException();
        }

        public PluginResult ScanModule(dynamic parameters, bool canFightWithThreat)
        {
            throw new NotImplementedException();
        }
    }
}