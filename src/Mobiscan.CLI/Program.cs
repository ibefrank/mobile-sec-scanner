using System.CommandLine;
using System.Text.Json;
using Mobiscan.Analyzers.Android;
using Mobiscan.Analyzers.iOS;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;
using Mobiscan.Core.Plugins;
using Mobiscan.Core.Utilities;
using Mobiscan.DependencyScanner;
using Mobiscan.FixEngine;
using Mobiscan.Reporting;
using Mobiscan.ReverseAnalyzer;
using Mobiscan.RuleEngine;
using Mobiscan.ScanEngine;
using Mobiscan.SecretScanner;
using Mobiscan.WatchMode;

var rootCommand = new RootCommand("Mobiscan - mobile security scanner");

var pathArgument = new Argument<string>("path", () => Directory.GetCurrentDirectory(), "Path to the mobile project");
var platformOption = new Option<string>("--platform", () => "any", "Target platform: android, ios, or any");
var apkOption = new Option<string?>("--apk", "Path to an APK for reverse analysis");
var formatOption = new Option<string>("--format", () => "cli", "Report format: cli, json, html");
var outputOption = new Option<string?>("--output", "Output file path (defaults to stdout)");
var failOnOption = new Option<string?>("--fail-on", "Fail when findings reach this severity (low, medium, high, critical)");
var fixOption = new Option<bool>("--fix", "Apply auto-fixes where possible");

var scanCommand = new Command("scan", "Scan a mobile project")
{
    pathArgument,
    platformOption,
    apkOption,
    formatOption,
    outputOption,
    failOnOption,
    fixOption
};

scanCommand.SetHandler(async (string path, string platform, string? apk, string format, string? output, string? failOn, bool fix) =>
{
    var options = BuildScanOptions(path, platform, apk, failOn, fix);
    var scanEngine = BuildScanEngine();

    var result = await scanEngine.ScanAsync(options, CancellationToken.None);
    await WriteReportAsync(result, format, output);

    if (fix)
    {
        var plugins = PluginLoader.LoadPlugins(options.PluginsPath);
        var fixEngine = new FixEngineService(plugins);
        var context = new ScanContext
        {
            Options = options,
            RuleEngine = new RuleEngineService(options.RulesPath, plugins),
            SecretScanner = new SecretScannerService(),
            DependencyScanner = new DependencyScannerService(),
            ReverseAnalyzer = new ReverseAnalyzerService(),
            FixEngine = fixEngine,
            Plugins = plugins
        };

        var fixResults = await fixEngine.ApplyFixesAsync(context, result.Findings, CancellationToken.None);
        Console.WriteLine();
        Console.WriteLine("Auto-fix summary:");
        foreach (var fixResult in fixResults)
        {
            Console.WriteLine($"{fixResult.IssueId}: {(fixResult.Success ? "Fixed" : "Skipped")} - {fixResult.Message}");
        }
    }

    if (ShouldFail(result, options.FailOnSeverity))
    {
        Environment.Exit(2);
    }
}, pathArgument, platformOption, apkOption, formatOption, outputOption, failOnOption, fixOption);

var auditCommand = new Command("audit", "Run dependency audit only")
{
    pathArgument,
    formatOption,
    outputOption,
    failOnOption
};

auditCommand.SetHandler(async (string path, string format, string? output, string? failOn) =>
{
    var options = BuildScanOptions(path, "any", null, failOn, false) with
    {
        IncludeRuleAnalysis = false,
        IncludeSecretScan = false,
        IncludeReverseAnalysis = false,
        IncludeDependencyScan = true
    };

    var scanEngine = BuildScanEngine();
    var result = await scanEngine.ScanAsync(options, CancellationToken.None);
    await WriteReportAsync(result, format, output);

    if (ShouldFail(result, options.FailOnSeverity))
    {
        Environment.Exit(2);
    }
}, pathArgument, formatOption, outputOption, failOnOption);

var inputOption = new Option<string>("--input", "Path to JSON scan result") { IsRequired = true };
var reportCommand = new Command("report", "Generate a report from a saved JSON scan")
{
    inputOption,
    formatOption,
    outputOption
};

reportCommand.SetHandler(async (string input, string format, string? output) =>
{
    if (!File.Exists(input))
    {
        Console.Error.WriteLine("Input file not found.");
        Environment.Exit(1);
    }

    var json = await File.ReadAllTextAsync(input);
    var result = JsonSerializer.Deserialize<ScanResult>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    if (result is null)
    {
        Console.Error.WriteLine("Failed to parse scan result.");
        Environment.Exit(1);
    }

    await WriteReportAsync(result, format, output);
}, inputOption, formatOption, outputOption);

var watchCommand = new Command("watch", "Watch for file changes and rescan")
{
    pathArgument,
    platformOption
};

watchCommand.SetHandler(async (string path, string platform) =>
{
    var options = BuildScanOptions(path, platform, null, null, false) with { WatchMode = true };
    var scanEngine = BuildScanEngine();
    var watchService = new WatchService(scanEngine);

    Console.WriteLine("Watching for changes. Press Ctrl+C to stop.");

    await watchService.StartAsync(options, result =>
    {
        Console.WriteLine();
        Console.WriteLine("New scan result:");
        Console.WriteLine($"{result.Findings.Count} issues detected");
        foreach (var finding in result.Findings)
        {
            Console.WriteLine($"[{finding.Severity}] {finding.Title} ({finding.FilePath}:{finding.Line})");
        }
    }, CancellationToken.None);
}, pathArgument, platformOption);

var fixCommand = new Command("fix", "Apply fixes for detected issues")
{
    pathArgument,
    new Option<string?>("--issue", "Fix a specific issue ID")
};

fixCommand.SetHandler(async (string path, string? issue) =>
{
    var options = BuildScanOptions(path, "any", null, null, true);
    var scanEngine = BuildScanEngine();
    var scanResult = await scanEngine.ScanAsync(options, CancellationToken.None);

    var plugins = PluginLoader.LoadPlugins(options.PluginsPath);
    var fixEngine = new FixEngineService(plugins);
    var context = new ScanContext
    {
        Options = options,
        RuleEngine = new RuleEngineService(options.RulesPath, plugins),
        SecretScanner = new SecretScannerService(),
        DependencyScanner = new DependencyScannerService(),
        ReverseAnalyzer = new ReverseAnalyzerService(),
        FixEngine = fixEngine,
        Plugins = plugins
    };

    IReadOnlyList<Finding> findings = scanResult.Findings;
    if (!string.IsNullOrWhiteSpace(issue))
    {
        findings = scanResult.Findings.Where(f => string.Equals(f.Id, issue, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    var results = await fixEngine.ApplyFixesAsync(context, findings, CancellationToken.None);
    foreach (var result in results)
    {
        Console.WriteLine($"{result.IssueId}: {(result.Success ? "Fixed" : "Skipped")} - {result.Message}");
    }
}, pathArgument, fixCommand.Options[1] as Option<string?> ?? throw new InvalidOperationException());

var rulesCommand = new Command("rules", "List available rules");

rulesCommand.SetHandler(() =>
{
    var options = BuildScanOptions(Directory.GetCurrentDirectory(), "any", null, null, false);
    var plugins = PluginLoader.LoadPlugins(options.PluginsPath);
    var engine = new RuleEngineService(options.RulesPath, plugins);

    foreach (var rule in engine.GetRules())
    {
        Console.WriteLine($"{rule.Id} [{rule.Severity}] {rule.Title}");
    }
});

var versionCommand = new Command("version", "Print version information");
versionCommand.SetHandler(() =>
{
    var version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0";
    Console.WriteLine($"Mobiscan CLI v{version}");
});

rootCommand.AddCommand(scanCommand);
rootCommand.AddCommand(reportCommand);
rootCommand.AddCommand(auditCommand);
rootCommand.AddCommand(watchCommand);
rootCommand.AddCommand(fixCommand);
rootCommand.AddCommand(rulesCommand);
rootCommand.AddCommand(versionCommand);

return await rootCommand.InvokeAsync(args);

static ScanOptions BuildScanOptions(string path, string platform, string? apk, string? failOn, bool fix)
{
    var platformEnum = platform.ToLowerInvariant() switch
    {
        "android" => Platform.Android,
        "ios" => Platform.iOS,
        _ => Platform.Any
    };

    return new ScanOptions
    {
        TargetPath = path,
        Platform = platformEnum,
        ApkPath = apk,
        FailOnSeverity = SeverityParser.TryParse(failOn),
        EnableAutoFix = fix
    };
}

static ScanEngineService BuildScanEngine()
{
    var analyzers = new IAnalyzer[]
    {
        new AndroidAnalyzer(),
        new IosAnalyzer()
    };

    return new ScanEngineService(
        analyzers,
        new DependencyScannerService(),
        new SecretScannerService(),
        new ReverseAnalyzerService(),
        (options, plugins) => new RuleEngineService(options.RulesPath, plugins)
    );
}

static async Task WriteReportAsync(ScanResult result, string format, string? output)
{
    var reporter = ReportWriter.Resolve(format);
    if (string.IsNullOrWhiteSpace(output))
    {
        await reporter.WriteAsync(result, Console.OpenStandardOutput(), CancellationToken.None);
        return;
    }

    await using var stream = File.Create(output);
    await reporter.WriteAsync(result, stream, CancellationToken.None);
}

static bool ShouldFail(ScanResult result, Severity? threshold)
{
    if (threshold is null)
    {
        return false;
    }

    return result.Findings.Any(f => f.Severity >= threshold.Value);
}
