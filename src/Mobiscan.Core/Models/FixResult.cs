namespace Mobiscan.Core.Models;

public sealed record FixResult
{
    public string IssueId { get; init; } = string.Empty;
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public string? FilePath { get; init; }
    public string? BackupPath { get; init; }
}
