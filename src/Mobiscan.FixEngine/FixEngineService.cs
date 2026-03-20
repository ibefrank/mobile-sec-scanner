using System.Text.RegularExpressions;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;
using Mobiscan.Core.Plugins;
using Mobiscan.Core.Utilities;

namespace Mobiscan.FixEngine;

public sealed class FixEngineService : IFixEngine
{
    private readonly Dictionary<string, Func<string, string>> _fixHandlers = new(StringComparer.OrdinalIgnoreCase);

    public FixEngineService(PluginRegistry plugins)
    {
        RegisterBuiltInFixes();
        LoadPluginFixes(plugins);
    }

    public async Task<IReadOnlyList<FixResult>> ApplyFixesAsync(ScanContext context, IReadOnlyList<Finding> findings, CancellationToken cancellationToken)
    {
        var results = new List<FixResult>();
        var grouped = findings.GroupBy(f => f.FilePath);

        foreach (var group in grouped)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var filePath = group.Key;
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                foreach (var finding in group)
                {
                    results.Add(new FixResult
                    {
                        IssueId = finding.Id,
                        Success = false,
                        Message = "File not found for fix",
                        FilePath = filePath
                    });
                }
                continue;
            }

            var content = FileUtils.ReadAllTextSafe(filePath);
            var original = content;
            foreach (var finding in group)
            {
                if (_fixHandlers.TryGetValue(finding.Id, out var handler))
                {
                    content = handler(content);
                }
            }

            if (!string.Equals(content, original, StringComparison.Ordinal))
            {
                var backupPath = CreateBackup(filePath);
                File.WriteAllText(filePath, content);

                foreach (var finding in group)
                {
                    results.Add(new FixResult
                    {
                        IssueId = finding.Id,
                        Success = true,
                        Message = "Applied fix",
                        FilePath = filePath,
                        BackupPath = backupPath
                    });
                }
            }
            else
            {
                foreach (var finding in group)
                {
                    results.Add(new FixResult
                    {
                        IssueId = finding.Id,
                        Success = false,
                        Message = "No changes applied",
                        FilePath = filePath
                    });
                }
            }
        }

        return results;
    }

    public async Task<IReadOnlyList<FixResult>> ApplyFixAsync(ScanContext context, string issueId, CancellationToken cancellationToken)
    {
        var findings = await FindFindingsAsync(context, issueId, cancellationToken);
        return await ApplyFixesAsync(context, findings, cancellationToken);
    }

    private async Task<IReadOnlyList<Finding>> FindFindingsAsync(ScanContext context, string issueId, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var root = context.Options.TargetPath;
        var files = FileUtils.EnumerateFiles(root, ".xml", ".java", ".kt");

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var content = FileUtils.ReadAllTextSafe(file);
            var fileFindings = await context.RuleEngine.EvaluateAsync(file, content, context.Options.Platform, cancellationToken);
            findings.AddRange(fileFindings.Where(f => string.Equals(f.Id, issueId, StringComparison.OrdinalIgnoreCase)));
        }

        return findings;
    }

    private void RegisterBuiltInFixes()
    {
        _fixHandlers["ANDROID_DEBUG_ENABLED"] = content =>
            Regex.Replace(content, "android:debuggable\\s*=\\s*\"true\"", "android:debuggable=\"false\"", RegexOptions.IgnoreCase);

        _fixHandlers["ANDROID_WEBVIEW_JS"] = content =>
            Regex.Replace(content, "setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)", "setJavaScriptEnabled(false)", RegexOptions.IgnoreCase);

        _fixHandlers["ANDROID_WEBVIEW_FILE_ACCESS"] = content =>
            Regex.Replace(content, "setAllowFileAccess\\s*\\(\\s*true\\s*\\)", "setAllowFileAccess(false)", RegexOptions.IgnoreCase);

        _fixHandlers["ANDROID_WEBVIEW_UNIVERSAL_ACCESS"] = content =>
            Regex.Replace(content, "setAllowUniversalAccessFromFileURLs\\s*\\(\\s*true\\s*\\)", "setAllowUniversalAccessFromFileURLs(false)", RegexOptions.IgnoreCase);
    }

    private void LoadPluginFixes(PluginRegistry plugins)
    {
        foreach (var provider in plugins.FixProviders)
        {
            foreach (var kvp in provider.GetFixHandlers())
            {
                _fixHandlers[kvp.Key] = kvp.Value;
            }
        }
    }

    private static string CreateBackup(string filePath)
    {
        var backupPath = $"{filePath}.bak.{DateTimeOffset.UtcNow:yyyyMMddHHmmss}";
        File.Copy(filePath, backupPath, overwrite: true);
        return backupPath;
    }
}
