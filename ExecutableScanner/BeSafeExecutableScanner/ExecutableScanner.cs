using System;
using System.Diagnostics;
using System.Reflection;
using PluginSDK;
using PluginSDK.PluginInterfaces;

namespace BeSafeExecutableScanner
{
    public class ExecutableScanner : IBeSafeFilePlugin
    {
        private PluginInfo _pluginInfo;

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
            throw new NotImplementedException();
        }
    }
}