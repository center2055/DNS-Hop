using DNSHop.App.Localization;
using DNSHop.App.Models;
using System;

namespace DNSHop.App.Services;

/// <summary>
/// Maps a <see cref="LeakTestResult"/> to a user-facing, localized line. Shared so the
/// Home and Network pages describe the same result identically.
/// </summary>
internal static class LeakTestStatusText
{
    public static string Describe(LeakTestResult result, ILocalizationService localization)
    {
        var observed = string.IsNullOrWhiteSpace(result.ObservedResolver) ? "—" : result.ObservedResolver!;
        var expected = string.IsNullOrWhiteSpace(result.ExpectedResolver) ? "—" : result.ExpectedResolver!;

        return result.Outcome switch
        {
            LeakTestOutcome.Clear => SafeFormat(localization["Network.LeakTest.Clear"], observed),
            LeakTestOutcome.Override => SafeFormat(localization["Network.LeakTest.Override"], expected, observed),
            LeakTestOutcome.NotApplicable => SafeFormat(localization["Network.LeakTest.Info"], observed),
            _ => localization["Network.LeakTest.Undetectable"],
        };
    }

    // A mistranslated string with the wrong number of placeholders would otherwise throw
    // FormatException; fall back to the raw template rather than crash the UI thread.
    private static string SafeFormat(string template, params object[] args)
    {
        try
        {
            return string.Format(template, args);
        }
        catch (FormatException)
        {
            return template;
        }
    }
}
