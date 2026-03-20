using Mobiscan.Core.Models;

namespace Mobiscan.Core.Interfaces;

public interface IRuleProvider
{
    IReadOnlyList<RuleDefinition> GetRules();
}
