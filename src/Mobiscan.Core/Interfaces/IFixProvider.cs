namespace Mobiscan.Core.Interfaces;

public interface IFixProvider
{
    IReadOnlyDictionary<string, Func<string, string>> GetFixHandlers();
}
