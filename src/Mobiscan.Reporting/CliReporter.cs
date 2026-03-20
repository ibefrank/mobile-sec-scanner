using System.Text;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;

namespace Mobiscan.Reporting;

public sealed class CliReporter : IReporter
{
    public string Name => "cli";

    public async Task WriteAsync(ScanResult result, Stream output, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Mobiscan Security Scan");
        builder.AppendLine();
        builder.AppendLine($"{result.Findings.Count} vulnerabilities detected");
        builder.AppendLine();

        foreach (var finding in result.Findings.OrderByDescending(f => f.Severity))
        {
            builder.AppendLine($"[{finding.Severity.ToString().ToUpperInvariant()}] {finding.Title}");
            builder.AppendLine($"File: {finding.FilePath}:{finding.Line}");
            builder.AppendLine();
            builder.AppendLine("Explanation:");
            builder.AppendLine(finding.Description);
            builder.AppendLine();
            builder.AppendLine("Recommended Fix:");
            builder.AppendLine(finding.Recommendation);
            builder.AppendLine();
        }

        var bytes = Encoding.UTF8.GetBytes(builder.ToString());
        await output.WriteAsync(bytes, cancellationToken);
    }
}
