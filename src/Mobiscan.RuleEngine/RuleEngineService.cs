using System.Text.Json;
using System.Text.RegularExpressions;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;
using Mobiscan.Core.Plugins;
using Mobiscan.Core.Utilities;

namespace Mobiscan.RuleEngine;

public sealed class RuleEngineService : IRuleEngine
{
    private readonly List<RuleDefinition> _rules = new();

    public RuleEngineService(string rulesPath, PluginRegistry plugins)
    {
        LoadRules(rulesPath);
        LoadPluginRules(plugins);
    }

    public IReadOnlyList<RuleDefinition> GetRules() => _rules;

    public Task<IReadOnlyList<Finding>> EvaluateAsync(string filePath, string content, Platform platform, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var fileName = Path.GetFileName(filePath);

        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!IsRuleForPlatform(rule, platform))
            {
                continue;
            }

            if (!IsTargetFile(rule, fileName))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(rule.Pattern))
            {
                continue;
            }

            var matches = Regex.Matches(content, rule.Pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            foreach (Match match in matches)
            {
                var line = FileUtils.GetLineNumber(content, match.Index);
                findings.Add(new Finding
                {
                    Id = rule.Id,
                    RuleId = rule.Id,
                    Title = rule.Title,
                    Severity = rule.Severity,
                    FilePath = filePath,
                    Line = line,
                    Description = rule.Description,
                    Recommendation = rule.Recommendation,
                    OwaspCategory = rule.OwaspCategory,
                    Source = "RuleEngine"
                });
            }
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }

    private void LoadRules(string rulesPath)
    {
        if (!Directory.Exists(rulesPath))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(rulesPath, "*.json", SearchOption.AllDirectories))
        {
            try
            {
                var json = File.ReadAllText(file);
                var rules = JsonSerializer.Deserialize<List<RuleDefinition>>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (rules is not null)
                {
                    _rules.AddRange(rules);
                }
            }
            catch
            {
                // Skip malformed rule files.
            }
        }
    }

    private void LoadPluginRules(PluginRegistry plugins)
    {
        foreach (var provider in plugins.RuleProviders)
        {
            _rules.AddRange(provider.GetRules());
        }
    }

    private static bool IsTargetFile(RuleDefinition rule, string fileName)
    {
        if (rule.TargetFiles is null || rule.TargetFiles.Length == 0)
        {
            return true;
        }

        return rule.TargetFiles.Any(target => fileName.EndsWith(target, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsRuleForPlatform(RuleDefinition rule, Platform platform)
    {
        if (platform == Platform.Any)
        {
            return true;
        }

        if (string.Equals(rule.Platform, "any", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (platform == Platform.Android && string.Equals(rule.Platform, "android", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (platform == Platform.iOS && string.Equals(rule.Platform, "ios", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
}
