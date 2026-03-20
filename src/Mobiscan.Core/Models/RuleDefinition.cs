namespace Mobiscan.Core.Models;

public sealed record RuleDefinition
{
    public string Id { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public Severity Severity { get; init; } = Severity.Medium;
    public string Pattern { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string Recommendation { get; init; } = string.Empty;
    public string Fix { get; init; } = string.Empty;
    public string OwaspCategory { get; init; } = string.Empty;
    public string Platform { get; init; } = "any";
    public string[] TargetFiles { get; init; } = Array.Empty<string>();
}
