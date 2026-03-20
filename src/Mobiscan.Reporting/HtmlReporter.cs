using System.Text;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;

namespace Mobiscan.Reporting;

public sealed class HtmlReporter : IReporter
{
    public string Name => "html";

    public async Task WriteAsync(ScanResult result, Stream output, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        builder.AppendLine("<!doctype html>");
        builder.AppendLine("<html lang=\"en\">");
        builder.AppendLine("<head>");
        builder.AppendLine("<meta charset=\"utf-8\" />");
        builder.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
        builder.AppendLine("<title>Mobiscan Report</title>");
        builder.AppendLine("<style>");
        builder.AppendLine("body{font-family:Arial, sans-serif;background:#f5f7fb;color:#1b1b1f;margin:0;padding:24px;}h1{margin-top:0;}table{width:100%;border-collapse:collapse;background:#fff;}th,td{padding:12px;border-bottom:1px solid #e6e6e6;text-align:left;}th{background:#f0f2f6;}");
        builder.AppendLine(".sev-High{color:#b00020;font-weight:bold;} .sev-Critical{color:#7f0000;font-weight:bold;} .sev-Medium{color:#b26a00;font-weight:bold;} .sev-Low{color:#2b6f2b;font-weight:bold;}");
        builder.AppendLine("</style>");
        builder.AppendLine("</head>");
        builder.AppendLine("<body>");
        builder.AppendLine("<h1>Mobiscan Security Report</h1>");
        builder.AppendLine($"<p>Total findings: {result.Findings.Count}</p>");
        builder.AppendLine("<table>");
        builder.AppendLine("<thead><tr><th>Severity</th><th>Title</th><th>File</th><th>Line</th><th>Description</th><th>Recommendation</th></tr></thead>");
        builder.AppendLine("<tbody>");

        foreach (var finding in result.Findings)
        {
            builder.AppendLine("<tr>");
            builder.AppendLine($"<td class=\"sev-{finding.Severity}\">{finding.Severity}</td>");
            builder.AppendLine($"<td>{Escape(finding.Title)}</td>");
            builder.AppendLine($"<td>{Escape(finding.FilePath)}</td>");
            builder.AppendLine($"<td>{finding.Line}</td>");
            builder.AppendLine($"<td>{Escape(finding.Description)}</td>");
            builder.AppendLine($"<td>{Escape(finding.Recommendation)}</td>");
            builder.AppendLine("</tr>");
        }

        builder.AppendLine("</tbody></table></body></html>");

        var bytes = Encoding.UTF8.GetBytes(builder.ToString());
        await output.WriteAsync(bytes, cancellationToken);
    }

    private static string Escape(string value) =>
        value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
}
