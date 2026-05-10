using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

internal static class AppDiagnostics
{
    private static readonly object Sync = new();
    private static bool _initialized;

    public static string LogsDirectory => Path.Combine(GetAppDataRoot(), "Logs");

    public static string CurrentLogPath => Path.Combine(
        LogsDirectory,
        $"dns-hop-{DateTime.UtcNow:yyyyMMdd}.log");

    public static void Initialize()
    {
        lock (Sync)
        {
            if (_initialized)
            {
                return;
            }

            _initialized = true;
        }

        AppDomain.CurrentDomain.UnhandledException += static (_, args) =>
        {
            if (args.ExceptionObject is Exception exception)
            {
                WriteError("App", "Unhandled exception reached AppDomain.", exception);
                return;
            }

            WriteWarning("App", $"Unhandled non-exception object reached AppDomain: {args.ExceptionObject}");
        };

        TaskScheduler.UnobservedTaskException += static (_, args) =>
        {
            WriteError("App", "Unobserved task exception.", args.Exception);
        };

        WriteInfo("App", $"Diagnostics initialized. Log path: {CurrentLogPath}");
    }

    public static void WriteInfo(string component, string message)
        => Write("INFO", component, message, exception: null);

    public static void WriteWarning(string component, string message)
        => Write("WARN", component, message, exception: null);

    public static void WriteError(string component, string message, Exception? exception = null)
        => Write("ERROR", component, message, exception);

    private static void Write(string level, string component, string message, Exception? exception)
    {
        try
        {
            Directory.CreateDirectory(LogsDirectory);

            var builder = new StringBuilder(capacity: 512);
            builder.Append(DateTimeOffset.UtcNow.ToString("O"));
            builder.Append(' ');
            builder.Append('[');
            builder.Append(level);
            builder.Append("] ");
            builder.Append('[');
            builder.Append(component);
            builder.Append("] ");
            builder.AppendLine(message);

            if (exception is not null)
            {
                builder.AppendLine(exception.ToString());
            }

            lock (Sync)
            {
                File.AppendAllText(CurrentLogPath, builder.ToString(), Encoding.UTF8);
            }
        }
        catch
        {
            // Diagnostics must never interfere with the main app flow.
        }
    }

    private static string GetAppDataRoot()
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(root))
        {
            root = Path.GetTempPath();
        }

        return Path.Combine(root, "DNS Hop");
    }
}
