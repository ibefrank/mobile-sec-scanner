using System.Text.Json;
using System.Text.RegularExpressions;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;
using Mobiscan.Core.Utilities;

namespace Mobiscan.DependencyScanner;

public sealed class DependencyScannerService : IDependencyScanner
{
    public async Task<IReadOnlyList<Finding>> ScanAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var dependencies = new List<DependencyRecord>();

        var root = context.Options.TargetPath;
        dependencies.AddRange(ParseGradleFiles(root));
        dependencies.AddRange(ParseGradleLockFiles(root));
        dependencies.AddRange(ParsePodfiles(root));
        dependencies.AddRange(ParseSwiftPackages(root));

        var db = await LoadDatabaseAsync(context.Options.VulnerabilityDbPath, cancellationToken);
        if (db.Vulnerabilities.Count == 0)
        {
            return findings;
        }

        foreach (var dependency in dependencies)
        {
            foreach (var vuln in db.Vulnerabilities)
            {
                if (!dependency.Matches(vuln))
                {
                    continue;
                }

                findings.Add(new Finding
                {
                    Id = vuln.Id,
                    RuleId = vuln.Id,
                    Title = $"Vulnerable dependency: {dependency.Name}",
                    Severity = vuln.Severity,
                    FilePath = dependency.SourceFile,
                    Line = dependency.Line,
                    Description = vuln.Description,
                    Recommendation = vuln.Recommendation,
                    OwaspCategory = vuln.OwaspCategory,
                    Source = "DependencyScanner"
                });
            }
        }

        return findings;
    }

    private static List<DependencyRecord> ParseGradleFiles(string root)
    {
        var results = new List<DependencyRecord>();
        var files = FileUtils.EnumerateFiles(root, ".gradle").ToList();
        var regex = new Regex("['\"](?<group>[^:'\"]+):(?<name>[^:'\"]+):(?<version>[^'\"]+)['\"]", RegexOptions.IgnoreCase);

        foreach (var file in files)
        {
            var content = FileUtils.ReadAllTextSafe(file);
            foreach (Match match in regex.Matches(content))
            {
                results.Add(new DependencyRecord
                {
                    Name = $"{match.Groups["group"].Value}:{match.Groups["name"].Value}",
                    Version = match.Groups["version"].Value,
                    Platform = Platform.Android,
                    SourceFile = file,
                    Line = FileUtils.GetLineNumber(content, match.Index)
                });
            }
        }

        return results;
    }

    private static List<DependencyRecord> ParseGradleLockFiles(string root)
    {
        var results = new List<DependencyRecord>();
        var files = Directory.EnumerateFiles(root, "gradle.lockfile", SearchOption.AllDirectories).ToList();
        var regex = new Regex("(?<group>[^:]+):(?<name>[^:]+):(?<version>[^=\s]+)", RegexOptions.IgnoreCase);

        foreach (var file in files)
        {
            var content = FileUtils.ReadAllTextSafe(file);
            foreach (Match match in regex.Matches(content))
            {
                results.Add(new DependencyRecord
                {
                    Name = $"{match.Groups["group"].Value}:{match.Groups["name"].Value}",
                    Version = match.Groups["version"].Value,
                    Platform = Platform.Android,
                    SourceFile = file,
                    Line = FileUtils.GetLineNumber(content, match.Index)
                });
            }
        }

        return results;
    }

    private static List<DependencyRecord> ParsePodfiles(string root)
    {
        var results = new List<DependencyRecord>();
        var files = Directory.EnumerateFiles(root, "Podfile", SearchOption.AllDirectories).ToList();
        var regex = new Regex("pod\\s+['\"](?<name>[^'\"]+)['\"]\\s*,\\s*['\"](?<version>[^'\"]+)['\"]", RegexOptions.IgnoreCase);

        foreach (var file in files)
        {
            var content = FileUtils.ReadAllTextSafe(file);
            foreach (Match match in regex.Matches(content))
            {
                results.Add(new DependencyRecord
                {
                    Name = match.Groups["name"].Value,
                    Version = match.Groups["version"].Value,
                    Platform = Platform.iOS,
                    SourceFile = file,
                    Line = FileUtils.GetLineNumber(content, match.Index)
                });
            }
        }

        return results;
    }

    private static List<DependencyRecord> ParseSwiftPackages(string root)
    {
        var results = new List<DependencyRecord>();
        var files = Directory.EnumerateFiles(root, "Package.swift", SearchOption.AllDirectories).ToList();
        var regex = new Regex("\\.package\\(url:\\s*['\"](?<url>[^'\"]+)['\"].*?(from:|exact:)\\s*['\"](?<version>[^'\"]+)['\"]", RegexOptions.IgnoreCase | RegexOptions.Singleline);

        foreach (var file in files)
        {
            var content = FileUtils.ReadAllTextSafe(file);
            foreach (Match match in regex.Matches(content))
            {
                results.Add(new DependencyRecord
                {
                    Name = match.Groups["url"].Value,
                    Version = match.Groups["version"].Value,
                    Platform = Platform.iOS,
                    SourceFile = file,
                    Line = FileUtils.GetLineNumber(content, match.Index)
                });
            }
        }

        return results;
    }

    private static async Task<VulnerabilityDatabase> LoadDatabaseAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new VulnerabilityDatabase();
            }

            await using var stream = File.OpenRead(path);
            var db = await JsonSerializer.DeserializeAsync<VulnerabilityDatabase>(stream, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }, cancellationToken);

            return db ?? new VulnerabilityDatabase();
        }
        catch
        {
            return new VulnerabilityDatabase();
        }
    }
}

public sealed record DependencyRecord
{
    public string Name { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public Platform Platform { get; init; }
    public string SourceFile { get; init; } = string.Empty;
    public int Line { get; init; }

    public bool Matches(VulnerabilityEntry entry)
    {
        if (!string.Equals(Name, entry.Package, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(entry.Version) && string.Equals(Version, entry.Version, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (entry.AffectedVersions.Length > 0 && entry.AffectedVersions.Any(v => string.Equals(Version, v, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(entry.VersionPattern))
        {
            return Regex.IsMatch(Version, entry.VersionPattern, RegexOptions.IgnoreCase);
        }

        return false;
    }
}

public sealed record VulnerabilityDatabase
{
    public List<VulnerabilityEntry> Vulnerabilities { get; init; } = new();
}

public sealed record VulnerabilityEntry
{
    public string Id { get; init; } = string.Empty;
    public string Package { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public string[] AffectedVersions { get; init; } = Array.Empty<string>();
    public string VersionPattern { get; init; } = string.Empty;
    public Severity Severity { get; init; } = Severity.Medium;
    public string Description { get; init; } = string.Empty;
    public string Recommendation { get; init; } = string.Empty;
    public string OwaspCategory { get; init; } = "M9: Insecure Data Storage";
}
