namespace Mobiscan.Core.Models;

public sealed record ScanOptions
{
    public string TargetPath { get; init; } = string.Empty;
    public string? ApkPath { get; init; }
    public Platform Platform { get; init; } = Platform.Any;
    public Severity? FailOnSeverity { get; init; }
    public bool IncludeDependencyScan { get; init; } = true;
    public bool IncludeSecretScan { get; init; } = true;
    public bool IncludeReverseAnalysis { get; init; } = true;
    public bool IncludeRuleAnalysis { get; init; } = true;
    public bool EnableAutoFix { get; init; }
    public bool WatchMode { get; init; }
    public string RulesPath { get; init; } = "rules";
    public string VulnerabilityDbPath { get; init; } = "cve/vulnerability_database.json";
    public string PluginsPath { get; init; } = "plugins";
}
