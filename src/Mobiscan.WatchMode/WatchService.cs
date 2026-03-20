using Mobiscan.Core.Models;
using Mobiscan.ScanEngine;

namespace Mobiscan.WatchMode;

public sealed class WatchService
{
    private readonly ScanEngineService _scanEngine;

    public WatchService(ScanEngineService scanEngine)
    {
        _scanEngine = scanEngine;
    }

    public async Task StartAsync(ScanOptions options, Action<ScanResult> onResult, CancellationToken cancellationToken)
    {
        var watcher = new FileSystemWatcher(options.TargetPath)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName
        };

        var debounce = new DebounceTimer(TimeSpan.FromSeconds(1));

        FileSystemEventHandler handler = (_, _) => debounce.Trigger(async () =>
        {
            var result = await _scanEngine.ScanAsync(options, cancellationToken);
            onResult(result);
        });

        watcher.Changed += handler;
        watcher.Created += handler;
        watcher.Renamed += (_, _) => debounce.Trigger(async () =>
        {
            var result = await _scanEngine.ScanAsync(options, cancellationToken);
            onResult(result);
        });

        watcher.EnableRaisingEvents = true;

        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(500, cancellationToken);
        }

        watcher.Dispose();
    }
}

internal sealed class DebounceTimer
{
    private readonly TimeSpan _delay;
    private CancellationTokenSource? _cts;

    public DebounceTimer(TimeSpan delay)
    {
        _delay = delay;
    }

    public void Trigger(Func<Task> action)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(_delay, token);
                if (!token.IsCancellationRequested)
                {
                    await action();
                }
            }
            catch (TaskCanceledException)
            {
            }
        }, token);
    }
}
