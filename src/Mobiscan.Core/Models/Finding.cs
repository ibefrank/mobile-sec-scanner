namespace Mobiscan.Core.Models;

public sealed record Finding
{
    public string Id { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public Severity Severity { get; init; } = Severity.Low;
    public string FilePath { get; init; } = string.Empty;
    public int Line { get; init; }
    public string Description { get; init; } = string.Empty;
    public string Recommendation { get; init; } = string.Empty;
    public string OwaspCategory { get; init; } = string.Empty;
    public string RuleId { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
}
