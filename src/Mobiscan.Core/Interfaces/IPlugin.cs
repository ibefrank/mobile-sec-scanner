using Mobiscan.Core.Plugins;

namespace Mobiscan.Core.Interfaces;

public interface IPlugin
{
    string Name { get; }
    void Register(PluginRegistry registry);
}
