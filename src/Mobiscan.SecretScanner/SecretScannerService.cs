using System.Text.RegularExpressions;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;
using Mobiscan.Core.Utilities;

namespace Mobiscan.SecretScanner;

public sealed class SecretScannerService : ISecretScanner
{
    private static readonly SecretPattern[] Patterns =
    {
        new("AWS Access Key", "AWS_ACCESS_KEY", new Regex("AKIA[0-9A-Z]{16}", RegexOptions.Compiled)),
        new("AWS Secret Key", "AWS_SECRET_KEY", new Regex("(?i)aws(.{0,20})?['\"]?[0-9a-zA-Z/+]{40}['\"]?", RegexOptions.Compiled)),
        new("Firebase API Key", "FIREBASE_KEY", new Regex("AIza[0-9A-Za-z-_]{35}", RegexOptions.Compiled)),
        new("Generic API Token", "GENERIC_API_TOKEN", new Regex("(?i)(api[_-]?key|token|secret|client[_-]?secret)\\s*[:=]\\s*['\"](?<value>[^'\"]{8,})['\"]", RegexOptions.Compiled)),
        new("JWT Token", "JWT_TOKEN", new Regex("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", RegexOptions.Compiled))
    };

    public Task<IReadOnlyList<Finding>> ScanAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var root = context.Options.TargetPath;
        var files = FileUtils.EnumerateFiles(root, ".java", ".kt", ".swift", ".m", ".mm", ".h", ".xml", ".plist", ".gradle", ".properties", ".json", ".yml", ".yaml");

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var content = FileUtils.ReadAllTextSafe(file);
            findings.AddRange(ScanWithPatterns(file, content));
            findings.AddRange(ScanWithEntropy(file, content));
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }

    private static IEnumerable<Finding> ScanWithPatterns(string filePath, string content)
    {
        var findings = new List<Finding>();

        foreach (var pattern in Patterns)
        {
            foreach (Match match in pattern.Regex.Matches(content))
            {
                var line = FileUtils.GetLineNumber(content, match.Index);
                findings.Add(new Finding
                {
                    Id = pattern.Id,
                    RuleId = pattern.Id,
                    Title = $"{pattern.Name} detected",
                    Severity = Severity.High,
                    FilePath = filePath,
                    Line = line,
                    Description = "Potential hardcoded secret detected in source code.",
                    Recommendation = "Move secrets to secure storage or environment variables.",
                    OwaspCategory = "M9: Insecure Data Storage",
                    Source = "SecretScanner"
                });
            }
        }

        return findings;
    }

    private static IEnumerable<Finding> ScanWithEntropy(string filePath, string content)
    {
        var findings = new List<Finding>();
        var tokenRegex = new Regex("['\"](?<token>[A-Za-z0-9+/=_-]{20,})['\"]", RegexOptions.Compiled);

        foreach (Match match in tokenRegex.Matches(content))
        {
            var token = match.Groups["token"].Value;
            var entropy = EntropyCalculator.ShannonEntropy(token);
            if (entropy < 4.0)
            {
                continue;
            }

            findings.Add(new Finding
            {
                Id = "ENTROPY_SECRET",
                RuleId = "ENTROPY_SECRET",
                Title = "High-entropy secret-like value detected",
                Severity = Severity.Medium,
                FilePath = filePath,
                Line = FileUtils.GetLineNumber(content, match.Index),
                Description = "High-entropy values often indicate secrets or tokens.",
                Recommendation = "Confirm this value is not a secret or move it to secure storage.",
                OwaspCategory = "M9: Insecure Data Storage",
                Source = "SecretScanner"
            });
        }

        return findings;
    }
}

public sealed record SecretPattern(string Name, string Id, Regex Regex);
