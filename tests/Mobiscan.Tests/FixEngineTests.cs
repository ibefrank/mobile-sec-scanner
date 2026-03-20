using System.Text.Json;
using Mobiscan.Core.Models;
using Mobiscan.Core.Plugins;
using Mobiscan.FixEngine;
using Mobiscan.RuleEngine;

namespace Mobiscan.Tests;

public class FixEngineTests
{
    [Fact]
    public async Task Fixes_Android_Debuggable_Flag()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        var manifestPath = Path.Combine(tempDir, "AndroidManifest.xml");
        await File.WriteAllTextAsync(manifestPath, "<application android:debuggable=\"true\"></application>");

        var rulesPath = Path.Combine(tempDir, "rules");
        Directory.CreateDirectory(rulesPath);
        var rules = new List<RuleDefinition>
        {
            new()
            {
                Id = "ANDROID_DEBUG_ENABLED",
                Title = "Android debug mode enabled",
                Severity = Severity.Medium,
                Pattern = "android:debuggable\\s*=\\s*\\\"true\\\"",
                Description = "Debug enabled",
                Recommendation = "Disable"
            }
        };
        await File.WriteAllTextAsync(Path.Combine(rulesPath, "android.json"), JsonSerializer.Serialize(rules));

        var plugins = new PluginRegistry();
        var ruleEngine = new RuleEngineService(rulesPath, plugins);
        var context = new ScanContext
        {
            Options = new ScanOptions { TargetPath = tempDir, Platform = Platform.Android },
            RuleEngine = ruleEngine,
            SecretScanner = null!,
            DependencyScanner = null!,
            ReverseAnalyzer = null!,
            FixEngine = null!,
            Plugins = plugins
        };

        var findings = await ruleEngine.EvaluateAsync(manifestPath, await File.ReadAllTextAsync(manifestPath), Platform.Android, CancellationToken.None);
        var fixEngine = new FixEngineService(plugins);
        var results = await fixEngine.ApplyFixesAsync(context, findings, CancellationToken.None);

        var updated = await File.ReadAllTextAsync(manifestPath);
        Assert.Contains("android:debuggable=\"false\"", updated);
        Assert.Contains(results, r => r.Success);
        Assert.True(Directory.EnumerateFiles(tempDir, "AndroidManifest.xml.bak.*").Any());
    }
}
