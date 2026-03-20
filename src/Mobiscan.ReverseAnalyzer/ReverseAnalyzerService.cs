using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;

namespace Mobiscan.ReverseAnalyzer;

public sealed class ReverseAnalyzerService : IReverseAnalyzer
{
    private static readonly Regex SecretRegex = new("AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}", RegexOptions.Compiled);
    private static readonly Regex HttpRegex = new("http://", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex DebugRegex = new("debuggable|debug\\s*=\\s*true", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex InsecureCertRegex = new("trustAll|allowAllSSL|InsecureTrustManager", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public async Task<IReadOnlyList<Finding>> ScanApkAsync(ScanContext context, string apkPath, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        if (!File.Exists(apkPath))
        {
            return findings;
        }

        await using var stream = File.OpenRead(apkPath);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);

        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (entry.Length == 0 || entry.Length > 1_000_000)
            {
                continue;
            }

            var content = await ReadEntryAsync(entry, cancellationToken);
            if (string.IsNullOrWhiteSpace(content))
            {
                continue;
            }

            findings.AddRange(ScanContent(apkPath, entry.FullName, content));
        }

        return findings;
    }

    private static async Task<string> ReadEntryAsync(ZipArchiveEntry entry, CancellationToken cancellationToken)
    {
        await using var entryStream = entry.Open();
        using var memory = new MemoryStream();
        await entryStream.CopyToAsync(memory, cancellationToken);
        return Encoding.UTF8.GetString(memory.ToArray());
    }

    private static IEnumerable<Finding> ScanContent(string apkPath, string entryName, string content)
    {
        var findings = new List<Finding>();

        if (SecretRegex.IsMatch(content))
        {
            findings.Add(new Finding
            {
                Id = "APK_EMBEDDED_SECRET",
                RuleId = "APK_EMBEDDED_SECRET",
                Title = "Embedded secret found in APK",
                Severity = Severity.High,
                FilePath = $"{apkPath}:{entryName}",
                Line = 1,
                Description = "APK contains embedded secrets that can be extracted by attackers.",
                Recommendation = "Remove secrets from the app and store them securely server-side.",
                OwaspCategory = "M9: Insecure Data Storage",
                Source = "ReverseAnalyzer"
            });
        }

        if (DebugRegex.IsMatch(content))
        {
            findings.Add(new Finding
            {
                Id = "APK_DEBUG_FLAG",
                RuleId = "APK_DEBUG_FLAG",
                Title = "Debug flags detected in APK",
                Severity = Severity.Medium,
                FilePath = $"{apkPath}:{entryName}",
                Line = 1,
                Description = "Debug flags may expose internal functionality or reduce security.",
                Recommendation = "Ensure release builds disable debug flags.",
                OwaspCategory = "M7: Client Code Quality",
                Source = "ReverseAnalyzer"
            });
        }

        if (HttpRegex.IsMatch(content))
        {
            findings.Add(new Finding
            {
                Id = "APK_HTTP_ENDPOINT",
                RuleId = "APK_HTTP_ENDPOINT",
                Title = "Insecure HTTP endpoint found",
                Severity = Severity.Medium,
                FilePath = $"{apkPath}:{entryName}",
                Line = 1,
                Description = "APK references insecure HTTP endpoints.",
                Recommendation = "Switch endpoints to HTTPS.",
                OwaspCategory = "M3: Insecure Communication",
                Source = "ReverseAnalyzer"
            });
        }

        if (InsecureCertRegex.IsMatch(content))
        {
            findings.Add(new Finding
            {
                Id = "APK_INSECURE_CERT",
                RuleId = "APK_INSECURE_CERT",
                Title = "Insecure certificate handling",
                Severity = Severity.High,
                FilePath = $"{apkPath}:{entryName}",
                Line = 1,
                Description = "Found indicators of insecure certificate validation.",
                Recommendation = "Remove trust-all certificate handlers.",
                OwaspCategory = "M3: Insecure Communication",
                Source = "ReverseAnalyzer"
            });
        }

        return findings;
    }
}
