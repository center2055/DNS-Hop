using Avalonia;
using System;

namespace DNSHop.App;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
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

