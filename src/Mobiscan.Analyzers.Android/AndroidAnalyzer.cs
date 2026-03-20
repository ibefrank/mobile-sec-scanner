using System.Text.RegularExpressions;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;
using Mobiscan.Core.Utilities;

namespace Mobiscan.Analyzers.Android;

public sealed class AndroidAnalyzer : IAnalyzer
{
    public string Name => "Android Analyzer";
    public Platform Platform => Platform.Android;

    public async Task<IReadOnlyList<Finding>> AnalyzeAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var root = context.Options.TargetPath;

        var manifestPath = Directory.EnumerateFiles(root, "AndroidManifest.xml", SearchOption.AllDirectories).FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(manifestPath))
        {
            var content = FileUtils.ReadAllTextSafe(manifestPath);
            findings.AddRange(await context.RuleEngine.EvaluateAsync(manifestPath, content, Platform.Android, cancellationToken));
            findings.AddRange(AnalyzeManifest(manifestPath, content));
        }

        var sourceFiles = FileUtils.EnumerateFiles(root, ".java", ".kt", ".gradle", ".xml").ToList();
        foreach (var file in sourceFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var content = FileUtils.ReadAllTextSafe(file);
            findings.AddRange(await context.RuleEngine.EvaluateAsync(file, content, Platform.Android, cancellationToken));
            findings.AddRange(AnalyzeWebViewUsage(file, content));
        }

        return findings;
    }

    private static IEnumerable<Finding> AnalyzeManifest(string manifestPath, string content)
    {
        var findings = new List<Finding>();

        var debuggableMatch = Regex.Match(content, "android:debuggable\\s*=\\s*\"true\"", RegexOptions.IgnoreCase);
        if (debuggableMatch.Success)
        {
            findings.Add(new Finding
            {
                Id = "ANDROID_DEBUG_ENABLED",
                RuleId = "ANDROID_DEBUG_ENABLED",
                Title = "Android debug mode enabled",
                Severity = Severity.Medium,
                FilePath = manifestPath,
                Line = FileUtils.GetLineNumber(content, debuggableMatch.Index),
                Description = "Debug mode should not be enabled in production builds.",
                Recommendation = "Set android:debuggable to false in AndroidManifest.xml.",
                OwaspCategory = "M7: Client Code Quality",
                Source = "AndroidAnalyzer"
            });
        }

        var exportedMatches = Regex.Matches(content, "<activity[^>]*android:exported\\s*=\\s*\"true\"", RegexOptions.IgnoreCase);
        foreach (Match match in exportedMatches)
        {
            findings.Add(new Finding
            {
                Id = "ANDROID_EXPORTED_ACTIVITY",
                RuleId = "ANDROID_EXPORTED_ACTIVITY",
                Title = "Exported activity detected",
                Severity = Severity.Medium,
                FilePath = manifestPath,
                Line = FileUtils.GetLineNumber(content, match.Index),
                Description = "Exported activities can be invoked by other apps if not protected.",
                Recommendation = "Ensure exported activities require permissions or are not exported unless necessary.",
                OwaspCategory = "M3: Insecure Communication",
                Source = "AndroidAnalyzer"
            });
        }

        var cleartextMatch = Regex.Match(content, "android:usesCleartextTraffic\\s*=\\s*\"true\"", RegexOptions.IgnoreCase);
        if (cleartextMatch.Success)
        {
            findings.Add(new Finding
            {
                Id = "ANDROID_CLEARTEXT_TRAFFIC",
                RuleId = "ANDROID_CLEARTEXT_TRAFFIC",
                Title = "Cleartext traffic allowed",
                Severity = Severity.High,
                FilePath = manifestPath,
                Line = FileUtils.GetLineNumber(content, cleartextMatch.Index),
                Description = "Allowing cleartext traffic exposes data to interception.",
                Recommendation = "Disable cleartext traffic and enforce HTTPS.",
                OwaspCategory = "M3: Insecure Communication",
                Source = "AndroidAnalyzer"
            });
        }

        var dangerousPermissions = new[]
        {
            "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
            "RECORD_AUDIO", "READ_PHONE_STATE", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "CAMERA"
        };

        foreach (var permission in dangerousPermissions)
        {
            var permMatch = Regex.Match(content, $"uses-permission[^>]*{permission}", RegexOptions.IgnoreCase);
            if (permMatch.Success)
            {
                findings.Add(new Finding
                {
                    Id = "ANDROID_DANGEROUS_PERMISSION",
                    RuleId = "ANDROID_DANGEROUS_PERMISSION",
                    Title = "Dangerous permission requested",
                    Severity = Severity.Medium,
                    FilePath = manifestPath,
                    Line = FileUtils.GetLineNumber(content, permMatch.Index),
                    Description = $"The app requests the dangerous permission: {permission}.",
                    Recommendation = "Review whether the permission is strictly required and implement runtime checks.",
                    OwaspCategory = "M1: Improper Platform Usage",
                    Source = "AndroidAnalyzer"
                });
            }
        }

        return findings;
    }

    private static IEnumerable<Finding> AnalyzeWebViewUsage(string filePath, string content)
    {
        var findings = new List<Finding>();

        var jsMatch = Regex.Match(content, "setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)", RegexOptions.IgnoreCase);
        if (jsMatch.Success)
        {
            findings.Add(new Finding
            {
                Id = "ANDROID_WEBVIEW_JS",
                RuleId = "ANDROID_WEBVIEW_JS",
                Title = "WebView JavaScript enabled",
                Severity = Severity.Medium,
                FilePath = filePath,
                Line = FileUtils.GetLineNumber(content, jsMatch.Index),
                Description = "Enabling JavaScript in WebView can expose the app to injection risks.",
                Recommendation = "Disable JavaScript unless required and validate loaded content.",
                OwaspCategory = "M7: Client Code Quality",
                Source = "AndroidAnalyzer"
            });
        }

        var fileAccessMatch = Regex.Match(content, "setAllowFileAccess\\s*\\(\\s*true\\s*\\)", RegexOptions.IgnoreCase);
        if (fileAccessMatch.Success)
        {
            findings.Add(new Finding
            {
                Id = "ANDROID_WEBVIEW_FILE_ACCESS",
                RuleId = "ANDROID_WEBVIEW_FILE_ACCESS",
                Title = "WebView file access enabled",
                Severity = Severity.Medium,
                FilePath = filePath,
                Line = FileUtils.GetLineNumber(content, fileAccessMatch.Index),
                Description = "Allowing file access in WebView can expose local files.",
                Recommendation = "Disable file access unless strictly necessary.",
                OwaspCategory = "M7: Client Code Quality",
                Source = "AndroidAnalyzer"
            });
        }

        var universalAccessMatch = Regex.Match(content, "setAllowUniversalAccessFromFileURLs\\s*\\(\\s*true\\s*\\)", RegexOptions.IgnoreCase);
        if (universalAccessMatch.Success)
        {
            findings.Add(new Finding
            {
                Id = "ANDROID_WEBVIEW_UNIVERSAL_ACCESS",
                RuleId = "ANDROID_WEBVIEW_UNIVERSAL_ACCESS",
                Title = "WebView universal access enabled",
                Severity = Severity.High,
                FilePath = filePath,
                Line = FileUtils.GetLineNumber(content, universalAccessMatch.Index),
                Description = "Universal access from file URLs can expose sensitive data.",
                Recommendation = "Disable universal access from file URLs.",
                OwaspCategory = "M7: Client Code Quality",
                Source = "AndroidAnalyzer"
            });
        }

        return findings;
    }
}
