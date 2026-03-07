using Avalonia;
using DNSHop.App.Services;
using System;

namespace DNSHop.App;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (SystemDnsSwitchService.TryHandleCommandLine(args, out int exitCode))
        {
            return exitCode;
        }

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        return 0;
    }

    // Avalonia and Suki bootstrap.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .With(new Win32PlatformOptions
            {
                // Force classic composition path to avoid glass/transparency artifacts on some Win11 setups.
                CompositionMode = [Win32CompositionMode.RedirectionSurface],
            })
            .WithInterFont()
            .LogToTrace();
}

