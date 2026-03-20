using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;
using Mobiscan.Core.Plugins;

namespace Mobiscan.ScanEngine;

public sealed class ScanEngineService
{
    private readonly IReadOnlyList<IAnalyzer> _analyzers;
    private readonly IDependencyScanner _dependencyScanner;
    private readonly ISecretScanner _secretScanner;
    private readonly IReverseAnalyzer _reverseAnalyzer;
    private readonly Func<ScanOptions, PluginRegistry, IRuleEngine> _ruleEngineFactory;

    public ScanEngineService(
        IReadOnlyList<IAnalyzer> analyzers,
        IDependencyScanner dependencyScanner,
        ISecretScanner secretScanner,
        IReverseAnalyzer reverseAnalyzer,
        Func<ScanOptions, PluginRegistry, IRuleEngine> ruleEngineFactory)
    {
        _analyzers = analyzers;
        _dependencyScanner = dependencyScanner;
        _secretScanner = secretScanner;
        _reverseAnalyzer = reverseAnalyzer;
        _ruleEngineFactory = ruleEngineFactory;
    }

    public async Task<ScanResult> ScanAsync(ScanOptions options, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var plugins = PluginLoader.LoadPlugins(options.PluginsPath);
        var ruleEngine = options.IncludeRuleAnalysis
            ? _ruleEngineFactory(options, plugins)
            : new NullRuleEngine();
        var platform = options.Platform != Platform.Any
            ? options.Platform
            : PlatformDetector.Detect(options.TargetPath);

        var context = new ScanContext
        {
            Options = options,
            RuleEngine = ruleEngine,
            SecretScanner = _secretScanner,
            DependencyScanner = _dependencyScanner,
            ReverseAnalyzer = _reverseAnalyzer,
            FixEngine = _fixEngine,
            Plugins = plugins,
            StartedAt = started
        };

        var findings = new List<Finding>();
        var analyzers = _analyzers.Concat(plugins.Analyzers).ToList();

        foreach (var analyzer in analyzers)
        {
            if (analyzer.Platform != Platform.Any && analyzer.Platform != platform)
            {
                continue;
            }

            findings.AddRange(await analyzer.AnalyzeAsync(context, cancellationToken));
        }

        if (options.IncludeDependencyScan)
        {
            findings.AddRange(await _dependencyScanner.ScanAsync(context, cancellationToken));
        }

        if (options.IncludeSecretScan)
        {
            findings.AddRange(await _secretScanner.ScanAsync(context, cancellationToken));
        }

        if (options.IncludeReverseAnalysis && !string.IsNullOrWhiteSpace(options.ApkPath))
        {
            findings.AddRange(await _reverseAnalyzer.ScanApkAsync(context, options.ApkPath!, cancellationToken));
        }

        var finished = DateTimeOffset.UtcNow;
        return new ScanResult
        {
            ScanPath = options.TargetPath,
            Platform = platform,
            StartedAt = started,
            FinishedAt = finished,
            Findings = findings
        };
    }
}
