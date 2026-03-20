using System.Text.Json;
using Mobiscan.Core.Models;
using Mobiscan.Core.Plugins;
using Mobiscan.RuleEngine;

namespace Mobiscan.Tests;

public class RuleEngineTests
{
    [Fact]
    public async Task Detects_Rule_Patterns()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var rulesPath = Path.Combine(tempDir, "rules");
        Directory.CreateDirectory(rulesPath);

        var rules = new List<RuleDefinition>
        {
            new()
            {
                Id = "TEST_RULE",
                Title = "Test Rule",
                Severity = Severity.Medium,
                Pattern = "insecure",
                Description = "Test",
                Recommendation = "Fix"
            }
        };

        var json = JsonSerializer.Serialize(rules, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(rulesPath, "test.json"), json);

        var engine = new RuleEngineService(rulesPath, new PluginRegistry());
        var findings = await engine.EvaluateAsync("file.txt", "this is insecure", Platform.Android, CancellationToken.None);

        Assert.Single(findings);
        Assert.Equal("TEST_RULE", findings[0].Id);
    }
}
