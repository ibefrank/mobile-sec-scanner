using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;

namespace Mobiscan.ScanEngine;

internal sealed class NullRuleEngine : IRuleEngine
{
    public Task<IReadOnlyList<Finding>> EvaluateAsync(string filePath, string content, Platform platform, CancellationToken cancellationToken)
        => Task.FromResult<IReadOnlyList<Finding>>(Array.Empty<Finding>());

    public IReadOnlyList<RuleDefinition> GetRules() => Array.Empty<RuleDefinition>();
}
