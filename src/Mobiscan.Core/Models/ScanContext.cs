using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Plugins;

namespace Mobiscan.Core.Models;

public sealed record ScanContext
{
    public ScanOptions Options { get; init; } = new();
    public IRuleEngine RuleEngine { get; init; } = default!;
    public ISecretScanner SecretScanner { get; init; } = default!;
    public IDependencyScanner DependencyScanner { get; init; } = default!;
    public IReverseAnalyzer ReverseAnalyzer { get; init; } = default!;
    public IFixEngine FixEngine { get; init; } = default!;
    public PluginRegistry Plugins { get; init; } = new();
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.UtcNow;
}
