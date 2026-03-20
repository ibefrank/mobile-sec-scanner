using Mobiscan.Core.Models;

namespace Mobiscan.Core.Interfaces;

public interface IRuleEngine
{
    Task<IReadOnlyList<Finding>> EvaluateAsync(string filePath, string content, Platform platform, CancellationToken cancellationToken);
    IReadOnlyList<RuleDefinition> GetRules();
}
