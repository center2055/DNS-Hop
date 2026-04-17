using Avalonia;
using DNSHop.App.Services;
using System;
using System.IO;
using System.Reflection;

namespace DNSHop.App;

internal static class Program
{
    private const string SmokeTestArgument = "--smoke-test";

    [STAThread]
    public static int Main(string[] args)
    {
        if (TryHandleDiagnosticCommand(args, out int diagnosticExitCode))
        {
            return diagnosticExitCode;
        }

        if (SystemDnsSwitchService.TryHandleCommandLine(args, out int exitCode))
        {
            return exitCode;
        }

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        return 0;
    }

    // Avalonia and Suki bootstrap.
    public static AppBuilder BuildAvaloniaApp()
    {
        var builder = AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

        if (OperatingSystem.IsWindows())
        {
            builder = builder.With(new Win32PlatformOptions
            {
                // Force classic composition path to avoid glass/transparency artifacts on some Win11 setups.
                CompositionMode = [Win32CompositionMode.RedirectionSurface],
            });
        }

        return builder;
    }

    private static bool TryHandleDiagnosticCommand(string[] args, out int exitCode)
    {
        exitCode = 0;

        if (args.Length == 0 || !string.Equals(args[0], SmokeTestArgument, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string resolverListPath = Path.Combine(AppContext.BaseDirectory, "New Public DNS Resolvers.ini");
        bool resolverListExists = File.Exists(resolverListPath);
        SelfInvocationCommand? selfInvocation = ProcessCommand.TryCreateSelfInvocation([SmokeTestArgument]);
        string version = Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown";

        Console.WriteLine("DNS Hop smoke test");
        Console.WriteLine($"Version: {version}");
        Console.WriteLine($"Platform: {PlatformEnvironment.DisplayName}");
        Console.WriteLine($"ProcessPath: {Environment.ProcessPath ?? "unknown"}");
        Console.WriteLine($"BaseDirectory: {AppContext.BaseDirectory}");
        Console.WriteLine($"ResolversFile: {(resolverListExists ? resolverListPath : "missing")}");
        Console.WriteLine($"SelfInvocation: {selfInvocation?.FileName ?? "unavailable"}");

        if (!resolverListExists || selfInvocation is null)
        {
            Console.Error.WriteLine("Smoke test failed.");
            exitCode = 1;
        }

        return true;
    }
}

