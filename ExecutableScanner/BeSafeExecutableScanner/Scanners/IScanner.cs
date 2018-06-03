using PluginSDK;

namespace BeSafeExecutableScanner.Scanners
{
    interface IScanner
    {
        PluginResult Scan(string executablePath);
    }
}