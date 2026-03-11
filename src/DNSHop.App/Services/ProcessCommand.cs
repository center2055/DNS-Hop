using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace DNSHop.App.Services;

internal static class ProcessCommand
{
    public static ProcessCommandResult Run(string fileName, params string[] arguments)
        => Run(fileName, (IEnumerable<string>)arguments);

    public static ProcessCommandResult Run(string fileName, IEnumerable<string> arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = new Process { StartInfo = startInfo };
            process.Start();

            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            return new ProcessCommandResult(
                process.ExitCode == 0,
                process.ExitCode,
                stdout,
                stderr);
        }
        catch (Exception ex)
        {
            return new ProcessCommandResult(
                Success: false,
                ExitCode: -1,
                Output: string.Empty,
                Error: ex.Message);
        }
    }

    public static bool Exists(string fileName)
    {
        if (Path.IsPathRooted(fileName))
        {
            return File.Exists(fileName);
        }

        string checker = OperatingSystem.IsWindows() ? "where.exe" : "which";
        ProcessCommandResult result = Run(checker, fileName);
        return result.Success && !string.IsNullOrWhiteSpace(result.Output);
    }

    public static SelfInvocationCommand? TryCreateSelfInvocation(IEnumerable<string> arguments)
    {
        string? processPath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrWhiteSpace(processPath) || !File.Exists(processPath))
        {
            return null;
        }

        var invocationArguments = new List<string>();

        if (IsDotNetHost(processPath))
        {
            string? entryAssemblyName = AppDomain.CurrentDomain.FriendlyName;
            if (string.IsNullOrWhiteSpace(entryAssemblyName))
            {
                return null;
            }

            string assemblyFileName = Path.ChangeExtension(entryAssemblyName, ".dll");
            string? entryAssemblyPath = Path.Combine(AppContext.BaseDirectory, assemblyFileName);
            if (string.IsNullOrWhiteSpace(entryAssemblyPath) || !File.Exists(entryAssemblyPath))
            {
                return null;
            }

            invocationArguments.Add(entryAssemblyPath);
        }

        invocationArguments.AddRange(arguments);
        return new SelfInvocationCommand(processPath, invocationArguments);
    }

    private static bool IsDotNetHost(string processPath)
    {
        string fileName = Path.GetFileName(processPath);
        return string.Equals(fileName, "dotnet", StringComparison.OrdinalIgnoreCase)
            || string.Equals(fileName, "dotnet.exe", StringComparison.OrdinalIgnoreCase);
    }
}

internal readonly record struct ProcessCommandResult(bool Success, int ExitCode, string Output, string Error)
{
    public string CombinedOutput
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Error))
            {
                return NormalizeWhitespace(Output);
            }

            if (string.IsNullOrWhiteSpace(Output))
            {
                return NormalizeWhitespace(Error);
            }

            return NormalizeWhitespace($"{Output}{Environment.NewLine}{Error}");
        }
    }

    private static string NormalizeWhitespace(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return string.Join(
            " ",
            value.Split(
                [Environment.NewLine, "\r", "\n"],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }
}

internal sealed record SelfInvocationCommand(string FileName, IReadOnlyList<string> Arguments);
