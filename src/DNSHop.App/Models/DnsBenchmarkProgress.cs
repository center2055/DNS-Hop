using System;

namespace DNSHop.App.Models;

public sealed class DnsBenchmarkProgress
{
    public DnsBenchmarkProgress(int totalQueries, int completedQueries, TimeSpan elapsed, string currentServer)
    {
        TotalQueries = Math.Max(0, totalQueries);
        CompletedQueries = Math.Clamp(completedQueries, 0, TotalQueries);
        QueriesRemaining = Math.Max(0, TotalQueries - CompletedQueries);
        Elapsed = elapsed;
        CurrentServer = currentServer;

        PercentCompleted = TotalQueries == 0
            ? 0
            : Math.Round((double)CompletedQueries / TotalQueries * 100.0, 2);
    }

    public int TotalQueries { get; }

    public int CompletedQueries { get; }

    public int QueriesRemaining { get; }

    public double PercentCompleted { get; }

    public TimeSpan Elapsed { get; }

    public string CurrentServer { get; }
}

