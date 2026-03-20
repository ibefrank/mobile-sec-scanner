using System.Text.Json;
using Mobiscan.Core.Models;
using Mobiscan.DependencyScanner;

namespace Mobiscan.Tests;

public class DependencyScannerTests
{
    [Fact]
    public async Task Matches_Vulnerable_Dependency()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        var gradlePath = Path.Combine(tempDir, "build.gradle");
        await File.WriteAllTextAsync(gradlePath, "implementation 'com.squareup.okhttp3:okhttp:4.9.0'");

        var dbPath = Path.Combine(tempDir, "vuln.json");
        var db = new VulnerabilityDatabase
        {
            Vulnerabilities = new List<VulnerabilityEntry>
            {
                new()
                {
                    Id = "CVE-TEST",
                    Package = "com.squareup.okhttp3:okhttp",
                    Version = "4.9.0",
                    Severity = Severity.High,
                    Description = "Test vuln",
                    Recommendation = "Upgrade"
                }
            }
        };

        await File.WriteAllTextAsync(dbPath, JsonSerializer.Serialize(db));

        var scanner = new DependencyScannerService();
        var context = new ScanContext { Options = new ScanOptions { TargetPath = tempDir, VulnerabilityDbPath = dbPath } };
        var findings = await scanner.ScanAsync(context, CancellationToken.None);

        Assert.Contains(findings, f => f.Id == "CVE-TEST");
    }
}
