using DNSHop.App.Models;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

public interface IDnsBenchmarkService
{
    Task<IReadOnlyList<DnsBenchmarkResult>> BenchmarkAsync(
        IReadOnlyList<DnsServerDefinition> servers,
        DnsBenchmarkOptions options,
        IProgress<DnsBenchmarkProgress>? progress,
        CancellationToken cancellationToken);
}

