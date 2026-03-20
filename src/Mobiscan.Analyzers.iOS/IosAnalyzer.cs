using System.Text.RegularExpressions;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;
using Mobiscan.Core.Utilities;

namespace Mobiscan.Analyzers.iOS;

public sealed class IosAnalyzer : IAnalyzer
{
    public string Name => "iOS Analyzer";
    public Platform Platform => Platform.iOS;

    public async Task<IReadOnlyList<Finding>> AnalyzeAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var root = context.Options.TargetPath;

        var plistFiles = FileUtils.EnumerateFiles(root, ".plist").ToList();
        foreach (var plist in plistFiles)
        {
            var content = FileUtils.ReadAllTextSafe(plist);
            findings.AddRange(await context.RuleEngine.EvaluateAsync(plist, content, Platform.iOS, cancellationToken));
            findings.AddRange(AnalyzePlist(plist, content));
        }

        var sourceFiles = FileUtils.EnumerateFiles(root, ".swift", ".m", ".mm", ".h").ToList();
        foreach (var file in sourceFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var content = FileUtils.ReadAllTextSafe(file);
            findings.AddRange(await context.RuleEngine.EvaluateAsync(file, content, Platform.iOS, cancellationToken));
            findings.AddRange(AnalyzeHttpUsage(file, content));
            findings.AddRange(AnalyzeDebugConfig(file, content));
        }

        return findings;
    }

    private static IEnumerable<Finding> AnalyzePlist(string plistPath, string content)
    {
        var findings = new List<Finding>();

        var atsMatch = Regex.Match(content, "NSAllowsArbitraryLoads\\s*</key>\\s*<true/>", RegexOptions.IgnoreCase);
        if (atsMatch.Success)
        {
            findings.Add(new Finding
            {
                Id = "IOS_ATS_DISABLED",
                RuleId = "IOS_ATS_DISABLED",
                Title = "App Transport Security disabled",
                Severity = Severity.High,
                FilePath = plistPath,
                Line = FileUtils.GetLineNumber(content, atsMatch.Index),
                Description = "Disabling ATS allows insecure HTTP traffic.",
                Recommendation = "Enable ATS or configure exceptions for specific domains only.",
                OwaspCategory = "M3: Insecure Communication",
                Source = "IosAnalyzer"
            });
        }

        return findings;
    }

    private static IEnumerable<Finding> AnalyzeHttpUsage(string filePath, string content)
    {
        var findings = new List<Finding>();

        var httpMatch = Regex.Match(content, "http://", RegexOptions.IgnoreCase);
        if (httpMatch.Success)
        {
            findings.Add(new Finding
            {
                Id = "IOS_INSECURE_HTTP",
                RuleId = "IOS_INSECURE_HTTP",
                Title = "Insecure HTTP usage",
                Severity = Severity.Medium,
                FilePath = filePath,
                Line = FileUtils.GetLineNumber(content, httpMatch.Index),
                Description = "Plain HTTP traffic can be intercepted.",
                Recommendation = "Use HTTPS for all network communication.",
                OwaspCategory = "M3: Insecure Communication",
                Source = "IosAnalyzer"
            });
        }

        return findings;
    }

    private static IEnumerable<Finding> AnalyzeDebugConfig(string filePath, string content)
    {
        var findings = new List<Finding>();

        var debugMatch = Regex.Match(content, "#if\\s+DEBUG", RegexOptions.IgnoreCase);
        if (debugMatch.Success)
        {
            findings.Add(new Finding
            {
                Id = "IOS_DEBUG_BUILD",
                RuleId = "IOS_DEBUG_BUILD",
                Title = "Debug-only code found",
                Severity = Severity.Low,
                FilePath = filePath,
                Line = FileUtils.GetLineNumber(content, debugMatch.Index),
                Description = "Debug-only code can leak diagnostics or disable protections if shipped.",
                Recommendation = "Ensure debug-only code is excluded from production builds.",
                OwaspCategory = "M7: Client Code Quality",
                Source = "IosAnalyzer"
            });
        }

        return findings;
    }
}
