using PluginSDK;
using SharedTypes.Watchers.RegistryWatcherTypes;

namespace BeSafeRegistryScanner.Scanners
{
    interface IScanner
    {
        PluginResult Scan(ChangedValueInfo valueToScan);
    }
}