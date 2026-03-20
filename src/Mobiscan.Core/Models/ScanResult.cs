using System.Collections.ObjectModel;

namespace Mobiscan.Core.Models;

public sealed record ScanResult
{
    public string ScanPath { get; init; } = string.Empty;
    public Platform Platform { get; init; } = Platform.Any;
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset FinishedAt { get; init; } = DateTimeOffset.UtcNow;
    public IReadOnlyList<Finding> Findings { get; init; } = new ReadOnlyCollection<Finding>(Array.Empty<Finding>());

    public ScanSummary Summary => new()
    {
        Total = Findings.Count,
        Critical = Findings.Count(f => f.Severity == Severity.Critical),
        High = Findings.Count(f => f.Severity == Severity.High),
        Medium = Findings.Count(f => f.Severity == Severity.Medium),
        Low = Findings.Count(f => f.Severity == Severity.Low),
        Info = Findings.Count(f => f.Severity == Severity.Info)
    };
}

public sealed record ScanSummary
{
    public int Total { get; init; }
    public int Critical { get; init; }
    public int High { get; init; }
    public int Medium { get; init; }
    public int Low { get; init; }
    public int Info { get; init; }
}
