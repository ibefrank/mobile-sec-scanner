using System.Reflection;
using Mobiscan.Core.Interfaces;

namespace Mobiscan.Core.Plugins;

public static class PluginLoader
{
    public static PluginRegistry LoadPlugins(string pluginsPath)
    {
        var registry = new PluginRegistry();

        if (!Directory.Exists(pluginsPath))
        {
            return registry;
        }

        foreach (var dll in Directory.EnumerateFiles(pluginsPath, "*.dll", SearchOption.AllDirectories))
        {
            TryLoadPlugin(dll, registry);
        }

        return registry;
    }

    private static void TryLoadPlugin(string dllPath, PluginRegistry registry)
    {
        try
        {
            var assembly = Assembly.LoadFrom(dllPath);
            var pluginTypes = assembly.GetTypes()
                .Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsAbstract && t.GetConstructor(Type.EmptyTypes) != null);

            foreach (var pluginType in pluginTypes)
            {
                if (Activator.CreateInstance(pluginType) is IPlugin plugin)
                {
                    plugin.Register(registry);
                }
            }
        }
        catch
        {
            // Ignore plugin load failures to avoid blocking scans.
        }
    }
}
