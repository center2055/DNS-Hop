using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DNSHop.App.Services;

/// <summary>
/// Drives the process-wide Windows chrome theme via undocumented uxtheme ordinals so
/// the title bar paints in the right colour from the very first frame instead of
/// flashing the OS default light chrome.
/// </summary>
internal static class WindowsAppMode
{
    public enum PreferredAppMode
    {
        Default = 0,
        AllowDark = 1,
        ForceDark = 2,
        ForceLight = 3,
    }

    [SupportedOSPlatform("windows")]
    public static void Apply(string themeName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // AllowDark by itself does NOT force the chrome — it only permits a per-window
        // DwmSetWindowAttribute opt-in. For "System" we resolve the actual OS theme
        // and pick ForceDark / ForceLight so the first WM_NCPAINT is correct.
        bool systemPrefersDark = SystemPrefersDarkMode();
        var mode = themeName switch
        {
            "Light" => PreferredAppMode.ForceLight,
            "Dark" => PreferredAppMode.ForceDark,
            _ => systemPrefersDark ? PreferredAppMode.ForceDark : PreferredAppMode.ForceLight,
        };

        TryApply(mode);
    }

    [SupportedOSPlatform("windows")]
    public static bool SystemPrefersDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            if (key?.GetValue("AppsUseLightTheme") is int v)
            {
                return v == 0;
            }
        }
        catch
        {
        }
        return false;
    }

    private static void TryApply(PreferredAppMode mode)
    {
        try
        {
            var previous = SetPreferredAppMode(mode);
            FlushMenuThemes();
            AppDiagnostics.WriteInfo("WindowsAppMode", $"SetPreferredAppMode({mode}) succeeded (previous={previous}).");
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteWarning("WindowsAppMode", $"SetPreferredAppMode({mode}) failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // Ordinal 135 in uxtheme.dll on Windows 10 1903+ and Windows 11. Returns the
    // previous mode. Undocumented but widely used (Notepad++, Files, ShareX, etc.).
    [DllImport("uxtheme.dll", EntryPoint = "#135", SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern PreferredAppMode SetPreferredAppMode(PreferredAppMode preferredAppMode);

    [DllImport("uxtheme.dll", EntryPoint = "#136", SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern bool FlushMenuThemes();
}
