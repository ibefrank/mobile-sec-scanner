using Mobiscan.Core.Interfaces;

namespace Mobiscan.Core.Plugins;

public sealed class PluginRegistry
{
    private readonly List<IAnalyzer> _analyzers = new();
    private readonly List<IRuleProvider> _ruleProviders = new();
    private readonly List<IFixProvider> _fixProviders = new();

    public IReadOnlyList<IAnalyzer> Analyzers => _analyzers;
    public IReadOnlyList<IRuleProvider> RuleProviders => _ruleProviders;
    public IReadOnlyList<IFixProvider> FixProviders => _fixProviders;

    public void AddAnalyzer(IAnalyzer analyzer) => _analyzers.Add(analyzer);
    public void AddRuleProvider(IRuleProvider provider) => _ruleProviders.Add(provider);
    public void AddFixProvider(IFixProvider provider) => _fixProviders.Add(provider);
}
