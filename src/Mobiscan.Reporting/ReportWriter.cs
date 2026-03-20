using Mobiscan.Core.Interfaces;

namespace Mobiscan.Reporting;

public static class ReportWriter
{
    public static IReporter Resolve(string format)
    {
        return format.ToLowerInvariant() switch
        {
            "json" => new JsonReporter(),
            "html" => new HtmlReporter(),
            _ => new CliReporter()
        };
    }
}
