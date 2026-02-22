using DnsClient;
using DnsClient.Protocol;
using DNSHop.App.Models;
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

public sealed class DnsBenchmarkService : IDnsBenchmarkService
{
    private const string CachedDomain = "google.com";
    private const string DotComDomain = "com";
    private const string DnssecProbeDomain = "dnssec-failed.org";
    private const int MinRedirectProbeCount = 3;
    private const int ControlResolverCount = 2;

    private const int ResponseCodeNoError = 0;
    private const int ResponseCodeServFail = 2;
    private const int ResponseCodeNxDomain = 3;

    // Static HttpClient avoids socket churn while benchmarking many DoH endpoints.
    private static readonly HttpClient SecureHttpClient = new()
    {
        Timeout = Timeout.InfiniteTimeSpan,
    };

    private static readonly HttpClient InsecureHttpClient = new(new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    })
    {
        Timeout = Timeout.InfiniteTimeSpan,
    };

    private static readonly ConcurrentDictionary<string, HttpClient> ProxiedHttpClients = new(StringComparer.Ordinal);

    private static readonly DnsServerDefinition[] UdpTcpControlResolvers =
    [
        DnsServerDefinition.CreateUdpTcp("1.1.1.1", "Control-Cloudflare"),
        DnsServerDefinition.CreateUdpTcp("9.9.9.9", "Control-Quad9"),
    ];

    private static readonly DnsServerDefinition[] DohControlResolvers =
    [
        DnsServerDefinition.CreateDoh("https://cloudflare-dns.com/dns-query", "Control-Cloudflare"),
        DnsServerDefinition.CreateDoh("https://dns.quad9.net/dns-query", "Control-Quad9"),
    ];

    private static readonly DnsServerDefinition[] DotControlResolvers =
    [
        DnsServerDefinition.CreateDot("1.1.1.1", "cloudflare-dns.com", "Control-Cloudflare"),
        DnsServerDefinition.CreateDot("9.9.9.9", "dns.quad9.net", "Control-Quad9"),
    ];

    public async Task<IReadOnlyList<DnsBenchmarkResult>> BenchmarkAsync(
        IReadOnlyList<DnsServerDefinition> servers,
        DnsBenchmarkOptions options,
        IProgress<DnsBenchmarkProgress>? progress,
        CancellationToken cancellationToken)
    {
        if (servers.Count == 0)
        {
            return [];
        }

        var effectiveOptions = new DnsBenchmarkOptions
        {
            TimeoutMilliseconds = Math.Max(250, options.TimeoutMilliseconds),
            ConcurrencyLimit = Math.Max(1, options.ConcurrencyLimit),
            AttemptsPerProbe = Math.Max(1, options.AttemptsPerProbe),
            AllowInsecureSsl = options.AllowInsecureSsl,
            OutboundProxyType = options.OutboundProxyType,
            OutboundProxyHost = options.OutboundProxyHost?.Trim() ?? string.Empty,
            OutboundProxyPort = Math.Clamp(options.OutboundProxyPort, 1, 65535),
        };

        // Per server:
        // - cached/uncached/dotcom/dnssec probes run with AttemptsPerProbe.
        // - redirect probes run multiple randomized invalid domains.
        // - each redirect probe is cross-checked against two trusted control resolvers.
        int redirectProbeCount = Math.Max(MinRedirectProbeCount, effectiveOptions.AttemptsPerProbe);
        int queriesPerServer = (effectiveOptions.AttemptsPerProbe * 4) + (redirectProbeCount * (1 + ControlResolverCount));
        int totalQueries = servers.Count * queriesPerServer;
        int completedQueries = 0;
        var benchmarkStopwatch = Stopwatch.StartNew();

        using var semaphore = new SemaphoreSlim(effectiveOptions.ConcurrencyLimit);

        var tasks = servers.Select(async server =>
        {
            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                return await BenchmarkSingleServerAsync(
                    server,
                    effectiveOptions,
                    () =>
                    {
                        var completed = Interlocked.Increment(ref completedQueries);
                        progress?.Report(
                            new DnsBenchmarkProgress(
                                totalQueries,
                                completed,
                                benchmarkStopwatch.Elapsed,
                                server.EndpointDisplay));
                    },
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                semaphore.Release();
            }
        });

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);

        return results
            .OrderByDescending(result => result.Server.IsPinned)
            .ThenBy(result => result.AverageMilliseconds ?? double.MaxValue)
            .ToArray();
    }

    private async Task<DnsBenchmarkResult> BenchmarkSingleServerAsync(
        DnsServerDefinition server,
        DnsBenchmarkOptions options,
        Action onAttemptCompleted,
        CancellationToken cancellationToken)
    {
        // For DoT servers, establish a persistent TLS connection once and reuse it
        // across all probes. This avoids paying TLS handshake cost per query, making
        // DoT measurements comparable to DoH (which benefits from HttpClient pooling).
        TcpClient? dotTcpClient = null;
        SslStream? dotSession = null;

        if (server.Protocol == DnsProtocol.Dot)
        {
            try
            {
                (dotTcpClient, dotSession) = await EstablishDotConnectionAsync(
                    server, options, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Connection setup failed; probes will create individual connections.
            }
        }

        try
        {
            var cached = await MeasureProbeAsync(
                server,
                static _ => CachedDomain,
                QueryType.A,
                options,
                onAttemptCompleted,
                cancellationToken,
                dotSession).ConfigureAwait(false);

            var uncached = await MeasureProbeAsync(
                server,
                static _ => $"{Guid.NewGuid():N}.com",
                QueryType.A,
                options,
                onAttemptCompleted,
                cancellationToken,
                dotSession).ConfigureAwait(false);

            var dotCom = await MeasureProbeAsync(
                server,
                static _ => DotComDomain,
                QueryType.NS,
                options,
                onAttemptCompleted,
                cancellationToken,
                dotSession).ConfigureAwait(false);

            var redirectAnalysis = await AnalyzeRedirectBehaviorAsync(
                server,
                options,
                onAttemptCompleted,
                cancellationToken,
                dotSession).ConfigureAwait(false);

            var dnssecProbe = await MeasureProbeAsync(
                server,
                static _ => DnssecProbeDomain,
                QueryType.A,
                options,
                onAttemptCompleted,
                cancellationToken,
                dotSession).ConfigureAwait(false);

            bool dead = cached.AverageMilliseconds is null
                && uncached.AverageMilliseconds is null
                && dotCom.AverageMilliseconds is null;

            bool redirecting = redirectAnalysis.IsRedirecting;

            bool supportsDnssec = dnssecProbe.FirstResponseCode == ResponseCodeServFail;

            DnsServerStatus status = dead
                ? DnsServerStatus.Dead
                : redirecting
                    ? DnsServerStatus.Redirecting
                    : DnsServerStatus.Alive;

            return new DnsBenchmarkResult
            {
                Server = server,
                CachedMilliseconds = cached.AverageMilliseconds,
                UncachedMilliseconds = uncached.AverageMilliseconds,
                DotComMilliseconds = dotCom.AverageMilliseconds,
                Status = status,
                SupportsDnssec = supportsDnssec,
                RedirectsNxDomain = redirecting,
                PoisoningConfidence = redirectAnalysis.Confidence,
                PoisoningEvidence = redirectAnalysis.Evidence,
                SuccessfulQueries = cached.SuccessfulAttempts
                    + uncached.SuccessfulAttempts
                    + dotCom.SuccessfulAttempts
                    + redirectAnalysis.SuccessfulAttempts
                    + dnssecProbe.SuccessfulAttempts,
                FailedQueries = cached.FailedAttempts
                    + uncached.FailedAttempts
                    + dotCom.FailedAttempts
                    + redirectAnalysis.FailedAttempts
                    + dnssecProbe.FailedAttempts,
                LastError = cached.LastError
                    ?? uncached.LastError
                    ?? dotCom.LastError
                    ?? redirectAnalysis.LastError
                    ?? dnssecProbe.LastError,
            };
        }
        finally
        {
            if (dotSession is not null) await dotSession.DisposeAsync().ConfigureAwait(false);
            dotTcpClient?.Dispose();
        }
    }

    private async Task<ProbeAggregate> MeasureProbeAsync(
        DnsServerDefinition server,
        Func<int, string> domainFactory,
        QueryType queryType,
        DnsBenchmarkOptions options,
        Action onAttemptCompleted,
        CancellationToken cancellationToken,
        SslStream? dotSession = null)
    {
        var aggregate = new ProbeAggregate();

        for (int attempt = 0; attempt < options.AttemptsPerProbe; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string domain = domainFactory(attempt);

            QueryAttemptResult attemptResult = await RunSingleQueryAsync(
                server,
                domain,
                queryType,
                options,
                cancellationToken,
                dotSession).ConfigureAwait(false);

            if (attemptResult.ElapsedMilliseconds is double elapsedMs)
            {
                aggregate.SuccessTimings.Add(elapsedMs);
                aggregate.SuccessfulAttempts++;
            }
            else
            {
                aggregate.FailedAttempts++;
            }

            // Preserve the first successful response code so that a later timeout
            // does not overwrite a valid SERVFAIL or NXDOMAIN needed by DNSSEC/redirect checks.
            if (attemptResult.ResponseCode is not null && aggregate.FirstResponseCode is null)
            {
                aggregate.FirstResponseCode = attemptResult.ResponseCode;
                aggregate.FirstHasAnswers = attemptResult.HasAnswers;
            }

            if (!string.IsNullOrWhiteSpace(attemptResult.Error))
            {
                aggregate.LastError = attemptResult.Error;
            }

            onAttemptCompleted();
        }

        return aggregate;
    }

    private async Task<RedirectAnalysis> AnalyzeRedirectBehaviorAsync(
        DnsServerDefinition server,
        DnsBenchmarkOptions options,
        Action onAttemptCompleted,
        CancellationToken cancellationToken,
        SslStream? dotSession)
    {
        var analysis = new RedirectAnalysis();
        int redirectProbeCount = Math.Max(MinRedirectProbeCount, options.AttemptsPerProbe);
        int redirectThreshold = Math.Max(2, (int)Math.Ceiling(redirectProbeCount * 0.5));

        var fingerprintCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        for (int attempt = 0; attempt < redirectProbeCount; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string domain = $"{Guid.NewGuid():N}.invalid";

            Task<QueryAttemptResult> targetTask = RunSingleQueryAsync(
                server,
                domain,
                QueryType.A,
                options,
                cancellationToken,
                dotSession);

            Task<ControlConsensus> consensusTask = ProbeControlConsensusAsync(
                server.Protocol,
                domain,
                options,
                onAttemptCompleted,
                cancellationToken);

            QueryAttemptResult targetResult = await targetTask.ConfigureAwait(false);

            UpdateAttemptStats(analysis, targetResult);
            onAttemptCompleted();

            bool redirectLike = targetResult.ResponseCode is int responseCode
                && responseCode != ResponseCodeNxDomain
                && targetResult.HasAnswers;

            if (redirectLike)
            {
                analysis.RedirectLikeCount++;

                if (!string.IsNullOrWhiteSpace(targetResult.AnswerFingerprint))
                {
                    string key = targetResult.AnswerFingerprint!;
                    fingerprintCounts[key] = fingerprintCounts.TryGetValue(key, out int count)
                        ? count + 1
                        : 1;
                }
            }

            ControlConsensus consensus = await consensusTask.ConfigureAwait(false);

            analysis.ControlComparisons++;
            if (redirectLike && consensus.BothNxDomain)
            {
                analysis.ControlMismatchCount++;
            }

            if (!string.IsNullOrWhiteSpace(consensus.LastError))
            {
                analysis.LastError = consensus.LastError;
            }
        }

        if (fingerprintCounts.Count > 0)
        {
            var topFingerprint = fingerprintCounts
                .OrderByDescending(static kv => kv.Value)
                .ThenBy(static kv => kv.Key, StringComparer.Ordinal)
                .First();

            analysis.TopFingerprint = TrimFingerprint(topFingerprint.Key);
            analysis.TopFingerprintCount = topFingerprint.Value;
            analysis.RepeatedFingerprint = topFingerprint.Value >= 2;
        }

        bool thresholdTriggered = analysis.RedirectLikeCount >= redirectThreshold;
        bool controlMismatchStrong = analysis.ControlMismatchCount >= Math.Max(1, (int)Math.Ceiling(redirectProbeCount * 0.34));

        // Require repeated behavior + corroboration, but keep an all-probes redirect fallback.
        analysis.IsRedirecting =
            thresholdTriggered
            && (analysis.RepeatedFingerprint || controlMismatchStrong || analysis.RedirectLikeCount == redirectProbeCount);

        analysis.Confidence = CalculatePoisoningConfidence(
            analysis,
            redirectProbeCount,
            redirectThreshold,
            thresholdTriggered,
            controlMismatchStrong);

        analysis.Evidence = BuildPoisoningEvidence(
            analysis,
            redirectProbeCount,
            redirectThreshold);

        return analysis;
    }

    private async Task<ControlConsensus> ProbeControlConsensusAsync(
        DnsProtocol protocol,
        string domain,
        DnsBenchmarkOptions options,
        Action onAttemptCompleted,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<DnsServerDefinition> controls = protocol switch
        {
            DnsProtocol.Doh => DohControlResolvers,
            DnsProtocol.Dot => DotControlResolvers,
            _ => UdpTcpControlResolvers,
        };

        int successfulResponses = 0;
        int nxDomainConsensus = 0;
        string? lastError = null;

        var controlTasks = controls
            .Select(control => RunSingleQueryAsync(
                control,
                domain,
                QueryType.A,
                options,
                cancellationToken))
            .ToArray();

        QueryAttemptResult[] controlResults = await Task.WhenAll(controlTasks).ConfigureAwait(false);

        foreach (QueryAttemptResult controlResult in controlResults)
        {
            onAttemptCompleted();

            if (controlResult.ElapsedMilliseconds is not null)
            {
                successfulResponses++;
            }

            if (controlResult.ResponseCode == ResponseCodeNxDomain && !controlResult.HasAnswers)
            {
                nxDomainConsensus++;
            }

            if (!string.IsNullOrWhiteSpace(controlResult.Error))
            {
                lastError = controlResult.Error;
            }
        }

        bool bothNxDomain = successfulResponses == controls.Count && nxDomainConsensus == controls.Count;
        return new ControlConsensus(bothNxDomain, lastError);
    }

    private static void UpdateAttemptStats(RedirectAnalysis analysis, QueryAttemptResult attemptResult)
    {
        if (attemptResult.ElapsedMilliseconds is not null)
        {
            analysis.SuccessfulAttempts++;
        }
        else
        {
            analysis.FailedAttempts++;
        }

        if (!string.IsNullOrWhiteSpace(attemptResult.Error))
        {
            analysis.LastError = attemptResult.Error;
        }
    }

    private static double CalculatePoisoningConfidence(
        RedirectAnalysis analysis,
        int redirectProbeCount,
        int redirectThreshold,
        bool thresholdTriggered,
        bool controlMismatchStrong)
    {
        if (redirectProbeCount <= 0)
        {
            return 0;
        }

        double confidence = 0;

        if (analysis.RedirectLikeCount > 0)
        {
            confidence += 0.30 * (analysis.RedirectLikeCount / (double)redirectProbeCount);
        }

        if (thresholdTriggered)
        {
            confidence += 0.35;
        }

        if (analysis.RepeatedFingerprint)
        {
            confidence += 0.20;
        }

        if (analysis.ControlMismatchCount > 0)
        {
            confidence += controlMismatchStrong ? 0.25 : 0.12;
        }

        if (analysis.RedirectLikeCount >= redirectThreshold && analysis.RedirectLikeCount == redirectProbeCount)
        {
            confidence += 0.10;
        }

        return Math.Clamp(confidence, 0, 1);
    }

    private static string BuildPoisoningEvidence(
        RedirectAnalysis analysis,
        int redirectProbeCount,
        int redirectThreshold)
    {
        if (redirectProbeCount == 0)
        {
            return "No poisoning probes executed.";
        }

        var evidenceParts = new List<string>
        {
            $"invalid-domain answers {analysis.RedirectLikeCount}/{redirectProbeCount} (threshold {redirectThreshold})",
        };

        if (analysis.ControlComparisons > 0)
        {
            evidenceParts.Add($"control mismatches {analysis.ControlMismatchCount}/{analysis.ControlComparisons}");
        }

        if (analysis.RepeatedFingerprint)
        {
            evidenceParts.Add($"repeated answer fingerprint {analysis.TopFingerprintCount}x");
        }

        if (!string.IsNullOrWhiteSpace(analysis.TopFingerprint))
        {
            evidenceParts.Add($"fingerprint {analysis.TopFingerprint}");
        }

        return string.Join("; ", evidenceParts);
    }

    private static string TrimFingerprint(string fingerprint)
    {
        const int maxLength = 72;
        return fingerprint.Length <= maxLength
            ? fingerprint
            : fingerprint[..maxLength] + "...";
    }

    private static async Task<QueryAttemptResult> RunSingleQueryAsync(
        DnsServerDefinition server,
        string domain,
        QueryType queryType,
        DnsBenchmarkOptions options,
        CancellationToken cancellationToken,
        SslStream? dotSession = null)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(options.TimeoutMilliseconds);

        try
        {
            var stopwatch = Stopwatch.StartNew();

            QueryWireResult result = server.Protocol switch
            {
                DnsProtocol.UdpTcp => await QueryClassicDnsAsync(server, domain, queryType, options.TimeoutMilliseconds, timeoutCts.Token).ConfigureAwait(false),
                DnsProtocol.Doh => await QueryDohAsync(server, domain, queryType, options, timeoutCts.Token).ConfigureAwait(false),
                DnsProtocol.Dot when dotSession is not null => await QueryDotOnStreamAsync(dotSession, domain, queryType, timeoutCts.Token).ConfigureAwait(false),
                DnsProtocol.Dot => await QueryDotAsync(server, domain, queryType, options, timeoutCts.Token).ConfigureAwait(false),
                _ => throw new NotSupportedException($"Protocol '{server.Protocol}' is not supported."),
            };

            stopwatch.Stop();

            return new QueryAttemptResult(
                stopwatch.Elapsed.TotalMilliseconds,
                result.ResponseCode,
                result.AnswerCount > 0,
                false,
                null,
                result.AnswerFingerprint);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new QueryAttemptResult(
                null,
                null,
                false,
                true,
                $"Timeout after {options.TimeoutMilliseconds} ms",
                null);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            return new QueryAttemptResult(
                null,
                null,
                false,
                false,
                ex.Message,
                null);
        }
    }

    private static async Task<QueryWireResult> QueryClassicDnsAsync(
        DnsServerDefinition server,
        string domain,
        QueryType queryType,
        int timeoutMilliseconds,
        CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(server.AddressOrHost, out var ipAddress))
        {
            throw new InvalidOperationException($"'{server.AddressOrHost}' is not a valid IP address for UDP/TCP DNS.");
        }

        var lookupOptions = new LookupClientOptions(new NameServer(ipAddress, server.Port))
        {
            Timeout = TimeSpan.FromMilliseconds(timeoutMilliseconds),
            Retries = 0,
            UseCache = false,
            ContinueOnDnsError = true,
            ThrowDnsErrors = false,
            AutoResolveNameServers = false,
            UseRandomNameServer = false,
            UseTcpFallback = true,
        };

        var lookupClient = new LookupClient(lookupOptions);
        IDnsQueryResponse response = await lookupClient.QueryAsync(domain, queryType, cancellationToken: cancellationToken).ConfigureAwait(false);

        string? answerFingerprint = BuildClassicAnswerFingerprint(response);
        return new QueryWireResult((int)response.Header.ResponseCode, response.Answers.Count, answerFingerprint);
    }

    private static HttpClient GetDohHttpClient(DnsBenchmarkOptions options)
    {
        if (options.OutboundProxyType == DnsOutboundProxyType.None)
        {
            return options.AllowInsecureSsl ? InsecureHttpClient : SecureHttpClient;
        }

        (string proxyHost, int proxyPort) = ResolveProxyEndpoint(options);
        string key = $"{(options.AllowInsecureSsl ? "insecure" : "secure")}|{options.OutboundProxyType}|{proxyHost}|{proxyPort}";

        return ProxiedHttpClients.GetOrAdd(key, _ =>
        {
            string proxyScheme = options.OutboundProxyType switch
            {
                DnsOutboundProxyType.Https => "https",
                DnsOutboundProxyType.Socks4 => "socks4",
                DnsOutboundProxyType.Socks5 => "socks5",
                _ => "http",
            };

            var handler = new HttpClientHandler
            {
                UseProxy = true,
                Proxy = new WebProxy(new Uri($"{proxyScheme}://{proxyHost}:{proxyPort}")),
            };

            if (options.AllowInsecureSsl)
            {
                handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }

            return new HttpClient(handler)
            {
                Timeout = Timeout.InfiniteTimeSpan,
            };
        });
    }

    private static async Task<QueryWireResult> QueryDohAsync(
        DnsServerDefinition server,
        string domain,
        QueryType queryType,
        DnsBenchmarkOptions options,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(server.DohEndpoint))
        {
            throw new InvalidOperationException("DoH endpoint URL is missing.");
        }

        byte[] requestPayload = BuildDnsWireQuestion(domain, ToWireType(queryType));

        using var request = new HttpRequestMessage(HttpMethod.Post, server.DohEndpoint)
        {
            Content = new ByteArrayContent(requestPayload),
        };

        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

        var client = GetDohHttpClient(options);

        using HttpResponseMessage response = await client
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        byte[] payload = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        return ParseDnsWireResponse(payload);
    }

    private static async Task<(TcpClient, SslStream)> EstablishDotConnectionAsync(
        DnsServerDefinition server,
        DnsBenchmarkOptions options,
        CancellationToken cancellationToken)
    {
        bool allowInsecureSsl = options.AllowInsecureSsl;
        TcpClient tcpClient;
        Stream transportStream;

        if (options.OutboundProxyType == DnsOutboundProxyType.None)
        {
            tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(server.AddressOrHost, server.Port, cancellationToken).ConfigureAwait(false);
            transportStream = tcpClient.GetStream();
        }
        else
        {
            (tcpClient, transportStream) = await ConnectViaProxyAsync(server, options, cancellationToken).ConfigureAwait(false);
        }

        var tlsStream = new SslStream(
            transportStream,
            leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (sender, cert, chain, errors) =>
            {
                if (allowInsecureSsl) return true;
                return errors == SslPolicyErrors.None;
            });

        string targetHost = server.DotTlsHost ?? server.AddressOrHost;

        var sslOptions = new SslClientAuthenticationOptions
        {
            TargetHost = targetHost,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = allowInsecureSsl ? X509RevocationMode.NoCheck : X509RevocationMode.Online,
        };

        await tlsStream.AuthenticateAsClientAsync(sslOptions, cancellationToken).ConfigureAwait(false);

        return (tcpClient, tlsStream);
    }

    private static async Task<QueryWireResult> QueryDotOnStreamAsync(
        SslStream tlsStream,
        string domain,
        QueryType queryType,
        CancellationToken cancellationToken)
    {
        byte[] requestPayload = BuildDnsWireQuestion(domain, ToWireType(queryType));

        byte[] requestLengthPrefix =
        [
            (byte)(requestPayload.Length >> 8),
            (byte)(requestPayload.Length & 0xFF),
        ];

        await tlsStream.WriteAsync(requestLengthPrefix, cancellationToken).ConfigureAwait(false);
        await tlsStream.WriteAsync(requestPayload, cancellationToken).ConfigureAwait(false);
        await tlsStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        byte[] responseLengthPrefix = new byte[2];
        await ReadExactAsync(tlsStream, responseLengthPrefix, cancellationToken).ConfigureAwait(false);

        int responseLength = (responseLengthPrefix[0] << 8) | responseLengthPrefix[1];
        if (responseLength <= 0 || responseLength > 65535)
        {
            throw new InvalidDataException($"Invalid DoT response size: {responseLength} bytes.");
        }

        byte[] responsePayload = new byte[responseLength];
        await ReadExactAsync(tlsStream, responsePayload, cancellationToken).ConfigureAwait(false);

        return ParseDnsWireResponse(responsePayload);
    }

    private static async Task<QueryWireResult> QueryDotAsync(
        DnsServerDefinition server,
        string domain,
        QueryType queryType,
        DnsBenchmarkOptions options,
        CancellationToken cancellationToken)
    {
        var (tcpClient, tlsStream) = await EstablishDotConnectionAsync(
            server, options, cancellationToken).ConfigureAwait(false);

        try
        {
            return await QueryDotOnStreamAsync(tlsStream, domain, queryType, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await tlsStream.DisposeAsync().ConfigureAwait(false);
            tcpClient.Dispose();
        }
    }

    private static async Task<(TcpClient, Stream)> ConnectViaProxyAsync(
        DnsServerDefinition server,
        DnsBenchmarkOptions options,
        CancellationToken cancellationToken)
    {
        return options.OutboundProxyType switch
        {
            DnsOutboundProxyType.Https => await ConnectViaHttpsProxyAsync(server, options, cancellationToken).ConfigureAwait(false),
            DnsOutboundProxyType.Socks4 => await ConnectViaSocks4ProxyAsync(server, options, cancellationToken).ConfigureAwait(false),
            DnsOutboundProxyType.Socks5 => await ConnectViaSocks5ProxyAsync(server, options, cancellationToken).ConfigureAwait(false),
            _ => throw new InvalidOperationException("Unsupported outbound proxy type."),
        };
    }

    private static async Task<(TcpClient, Stream)> ConnectViaHttpsProxyAsync(
        DnsServerDefinition server,
        DnsBenchmarkOptions options,
        CancellationToken cancellationToken)
    {
        (string proxyHost, int proxyPort) = ResolveProxyEndpoint(options);
        string targetHost = ResolveProxyDestinationHost(server);

        var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(proxyHost, proxyPort, cancellationToken).ConfigureAwait(false);
        Stream stream = tcpClient.GetStream();

        string request =
            $"CONNECT {targetHost}:{server.Port} HTTP/1.1\r\n" +
            $"Host: {targetHost}:{server.Port}\r\n" +
            "Proxy-Connection: Keep-Alive\r\n\r\n";

        byte[] requestBytes = Encoding.ASCII.GetBytes(request);
        await stream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        string headers = await ReadHttpHeadersAsync(stream, cancellationToken).ConfigureAwait(false);
        bool success =
            headers.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase)
            || headers.StartsWith("HTTP/1.0 200", StringComparison.OrdinalIgnoreCase);

        if (!success)
        {
            tcpClient.Dispose();
            string firstLine = headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()
                ?? "unknown response";
            throw new InvalidOperationException($"HTTPS proxy CONNECT failed: {firstLine}");
        }

        return (tcpClient, stream);
    }

    private static async Task<(TcpClient, Stream)> ConnectViaSocks5ProxyAsync(
        DnsServerDefinition server,
        DnsBenchmarkOptions options,
        CancellationToken cancellationToken)
    {
        (string proxyHost, int proxyPort) = ResolveProxyEndpoint(options);
        string targetHost = ResolveProxyDestinationHost(server);

        var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(proxyHost, proxyPort, cancellationToken).ConfigureAwait(false);
        Stream stream = tcpClient.GetStream();

        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        byte[] greetingResponse = new byte[2];
        await ReadExactAsync(stream, greetingResponse, cancellationToken).ConfigureAwait(false);

        if (greetingResponse[0] != 0x05 || greetingResponse[1] == 0xFF)
        {
            tcpClient.Dispose();
            throw new InvalidOperationException("SOCKS5 proxy rejected authentication method.");
        }

        var request = new List<byte>(capacity: 280)
        {
            0x05, // version
            0x01, // CONNECT
            0x00, // reserved
        };

        AppendProxyTargetAddress(request, targetHost, allowSocks4: false);
        request.Add((byte)(server.Port >> 8));
        request.Add((byte)(server.Port & 0xFF));

        await stream.WriteAsync(request.ToArray(), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        byte[] responseHeader = new byte[4];
        await ReadExactAsync(stream, responseHeader, cancellationToken).ConfigureAwait(false);

        if (responseHeader[0] != 0x05 || responseHeader[1] != 0x00)
        {
            tcpClient.Dispose();
            throw new InvalidOperationException($"SOCKS5 CONNECT failed with code 0x{responseHeader[1]:X2}.");
        }

        int atyp = responseHeader[3];
        if (atyp == 0x01)
        {
            await ReadExactAsync(stream, new byte[4], cancellationToken).ConfigureAwait(false);
        }
        else if (atyp == 0x04)
        {
            await ReadExactAsync(stream, new byte[16], cancellationToken).ConfigureAwait(false);
        }
        else if (atyp == 0x03)
        {
            byte[] hostLength = new byte[1];
            await ReadExactAsync(stream, hostLength, cancellationToken).ConfigureAwait(false);
            await ReadExactAsync(stream, new byte[hostLength[0]], cancellationToken).ConfigureAwait(false);
        }
        else
        {
            tcpClient.Dispose();
            throw new InvalidOperationException("SOCKS5 proxy returned unsupported address type.");
        }

        await ReadExactAsync(stream, new byte[2], cancellationToken).ConfigureAwait(false);
        return (tcpClient, stream);
    }

    private static async Task<(TcpClient, Stream)> ConnectViaSocks4ProxyAsync(
        DnsServerDefinition server,
        DnsBenchmarkOptions options,
        CancellationToken cancellationToken)
    {
        (string proxyHost, int proxyPort) = ResolveProxyEndpoint(options);
        string targetHost = ResolveProxyDestinationHost(server);

        var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(proxyHost, proxyPort, cancellationToken).ConfigureAwait(false);
        Stream stream = tcpClient.GetStream();

        var request = new List<byte>(capacity: 280)
        {
            0x04, // version
            0x01, // CONNECT
            (byte)(server.Port >> 8),
            (byte)(server.Port & 0xFF),
        };

        bool socks4a = AppendProxyTargetAddress(request, targetHost, allowSocks4: true);
        request.Add(0x00); // user id terminator

        if (socks4a)
        {
            byte[] hostBytes = Encoding.ASCII.GetBytes(targetHost);
            if (hostBytes.Length == 0 || hostBytes.Length > 255)
            {
                tcpClient.Dispose();
                throw new InvalidOperationException("SOCKS4A target host is invalid.");
            }

            request.AddRange(hostBytes);
            request.Add(0x00);
        }

        await stream.WriteAsync(request.ToArray(), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        byte[] response = new byte[8];
        await ReadExactAsync(stream, response, cancellationToken).ConfigureAwait(false);

        if (response[1] != 0x5A)
        {
            tcpClient.Dispose();
            throw new InvalidOperationException($"SOCKS4 CONNECT failed with code 0x{response[1]:X2}.");
        }

        return (tcpClient, stream);
    }

    private static bool AppendProxyTargetAddress(List<byte> buffer, string targetHost, bool allowSocks4)
    {
        if (IPAddress.TryParse(targetHost, out IPAddress? ipAddress))
        {
            byte[] addressBytes = ipAddress.GetAddressBytes();

            if (allowSocks4)
            {
                if (ipAddress.AddressFamily != AddressFamily.InterNetwork)
                {
                    // SOCKS4 cannot transport IPv6 literals directly.
                    buffer.AddRange(new byte[] { 0, 0, 0, 1 });
                    return true;
                }

                buffer.AddRange(addressBytes);
                return false;
            }

            if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                buffer.Add(0x01);
                buffer.AddRange(addressBytes);
                return false;
            }

            buffer.Add(0x04);
            buffer.AddRange(addressBytes);
            return false;
        }

        if (allowSocks4)
        {
            buffer.AddRange(new byte[] { 0, 0, 0, 1 });
            return true;
        }

        byte[] hostBytes = Encoding.ASCII.GetBytes(targetHost);
        if (hostBytes.Length == 0 || hostBytes.Length > 255)
        {
            throw new InvalidOperationException("Proxy target host is invalid.");
        }

        buffer.Add(0x03);
        buffer.Add((byte)hostBytes.Length);
        buffer.AddRange(hostBytes);
        return false;
    }

    private static string ResolveProxyDestinationHost(DnsServerDefinition server)
    {
        string target = server.DotTlsHost ?? server.AddressOrHost;
        if (string.IsNullOrWhiteSpace(target))
        {
            throw new InvalidOperationException("Proxy destination host is missing.");
        }

        return target.Trim();
    }

    private static (string Host, int Port) ResolveProxyEndpoint(DnsBenchmarkOptions options)
    {
        string rawHost = options.OutboundProxyHost?.Trim() ?? string.Empty;
        int fallbackPort = Math.Clamp(options.OutboundProxyPort, 1, 65535);

        if (string.IsNullOrWhiteSpace(rawHost))
        {
            throw new InvalidOperationException("Outbound proxy host is missing.");
        }

        if (Uri.TryCreate(rawHost, UriKind.Absolute, out Uri? proxyUri))
        {
            int uriPort = proxyUri.IsDefaultPort ? fallbackPort : proxyUri.Port;
            return (proxyUri.Host, Math.Clamp(uriPort, 1, 65535));
        }

        if (Uri.TryCreate($"tcp://{rawHost}", UriKind.Absolute, out Uri? tcpLikeUri))
        {
            int uriPort = tcpLikeUri.IsDefaultPort ? fallbackPort : tcpLikeUri.Port;
            return (tcpLikeUri.Host, Math.Clamp(uriPort, 1, 65535));
        }

        return (rawHost, fallbackPort);
    }

    private static async Task<string> ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
    {
        const int maxHeaderBytes = 16384;
        var bytes = new List<byte>(capacity: 512);
        var readBuffer = new byte[1];

        while (bytes.Count < maxHeaderBytes)
        {
            int read = await stream.ReadAsync(readBuffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            bytes.Add(readBuffer[0]);
            int count = bytes.Count;
            if (count >= 4
                && bytes[count - 4] == (byte)'\r'
                && bytes[count - 3] == (byte)'\n'
                && bytes[count - 2] == (byte)'\r'
                && bytes[count - 1] == (byte)'\n')
            {
                break;
            }
        }

        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int offset = 0;

        while (offset < buffer.Length)
        {
            int bytesRead = await stream
                .ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken)
                .ConfigureAwait(false);

            if (bytesRead == 0)
            {
                throw new EndOfStreamException("Unexpected end of DNS stream.");
            }

            offset += bytesRead;
        }
    }

    private static byte[] BuildDnsWireQuestion(string domain, ushort queryType)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentException("Domain must be supplied.", nameof(domain));
        }

        Span<byte> header = stackalloc byte[12];
        ushort id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1);

        BinaryPrimitives.WriteUInt16BigEndian(header[..2], id);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], 0x0100); // RD = true
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1);      // QDCOUNT = 1

        List<byte> payload = new(capacity: 96);
        payload.AddRange(header.ToArray());

        var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (string label in labels)
        {
            if (label.Length is 0 or > 63)
            {
                throw new InvalidDataException($"Invalid DNS label length in '{domain}'.");
            }

            payload.Add((byte)label.Length);
            payload.AddRange(Encoding.ASCII.GetBytes(label));
        }

        payload.Add(0x00); // End of QNAME

        payload.Add((byte)(queryType >> 8));
        payload.Add((byte)(queryType & 0xFF));
        payload.Add(0x00);
        payload.Add(0x01); // QCLASS = IN

        return payload.ToArray();
    }

    private static string? BuildClassicAnswerFingerprint(IDnsQueryResponse response)
    {
        if (response.Answers.Count == 0)
        {
            return null;
        }

        var components = response.Answers
            .Select(static record => record switch
            {
                ARecord a => $"A:{a.Address}",
                AaaaRecord aaaa => $"AAAA:{aaaa.Address}",
                _ => $"{record.RecordType}:{record.InitialTimeToLive}:{record.GetType().Name}",
            })
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static value => value, StringComparer.Ordinal)
            .Take(6)
            .ToArray();

        return components.Length == 0
            ? null
            : string.Join("|", components);
    }

    private static QueryWireResult ParseDnsWireResponse(byte[] responsePayload)
    {
        if (responsePayload.Length < 12)
        {
            throw new InvalidDataException("DNS response payload is too small.");
        }

        int flags = (responsePayload[2] << 8) | responsePayload[3];
        int responseCode = flags & 0x000F;
        int answerCount = (responsePayload[6] << 8) | responsePayload[7];
        string? answerFingerprint = ExtractWireAnswerFingerprint(responsePayload);

        return new QueryWireResult(responseCode, answerCount, answerFingerprint);
    }

    private static string? ExtractWireAnswerFingerprint(byte[] payload)
    {
        try
        {
            int questionCount = (payload[4] << 8) | payload[5];
            int answerCount = (payload[6] << 8) | payload[7];
            int offset = 12;

            for (int questionIndex = 0; questionIndex < questionCount; questionIndex++)
            {
                if (!TryReadDnsName(payload, ref offset, out _))
                {
                    return null;
                }

                if (offset + 4 > payload.Length)
                {
                    return null;
                }

                offset += 4; // QTYPE + QCLASS
            }

            var components = new List<string>(capacity: Math.Min(answerCount, 8));

            for (int answerIndex = 0; answerIndex < answerCount; answerIndex++)
            {
                if (!TryReadDnsName(payload, ref offset, out _))
                {
                    return null;
                }

                if (offset + 10 > payload.Length)
                {
                    return null;
                }

                ushort type = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset, 2));
                offset += 2;
                offset += 2; // CLASS
                offset += 4; // TTL

                ushort rdLength = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset, 2));
                offset += 2;

                if (offset + rdLength > payload.Length)
                {
                    return null;
                }

                string component = BuildWireAnswerComponent(payload, type, offset, rdLength);
                if (!string.IsNullOrWhiteSpace(component))
                {
                    components.Add(component);
                }

                offset += rdLength;
            }

            if (components.Count == 0)
            {
                return null;
            }

            return string.Join("|", components
                .Distinct(StringComparer.Ordinal)
                .OrderBy(static c => c, StringComparer.Ordinal));
        }
        catch
        {
            return null;
        }
    }

    private static string BuildWireAnswerComponent(byte[] payload, ushort type, int rdataOffset, int rdLength)
    {
        return type switch
        {
            1 when rdLength == 4 => $"A:{new IPAddress(payload.AsSpan(rdataOffset, 4).ToArray())}",
            28 when rdLength == 16 => $"AAAA:{new IPAddress(payload.AsSpan(rdataOffset, 16).ToArray())}",
            5 => TryReadNameAt(payload, rdataOffset, out string cname) ? $"CNAME:{cname}" : "CNAME",
            2 => TryReadNameAt(payload, rdataOffset, out string ns) ? $"NS:{ns}" : "NS",
            12 => TryReadNameAt(payload, rdataOffset, out string ptr) ? $"PTR:{ptr}" : "PTR",
            15 when rdLength > 2 => TryReadNameAt(payload, rdataOffset + 2, out string mx)
                ? $"MX:{mx}"
                : "MX",
            _ => $"T{type}/L{rdLength}",
        };
    }

    private static bool TryReadNameAt(byte[] payload, int offset, out string name)
    {
        return TryReadDnsName(payload, ref offset, out name);
    }

    private static bool TryReadDnsName(byte[] payload, ref int offset, out string name)
    {
        var labels = new List<string>();
        int cursor = offset;
        int postPointerOffset = -1;
        int hops = 0;

        while (true)
        {
            if (cursor >= payload.Length)
            {
                name = string.Empty;
                return false;
            }

            byte length = payload[cursor];

            if (length == 0)
            {
                cursor++;
                break;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= payload.Length)
                {
                    name = string.Empty;
                    return false;
                }

                int pointer = ((length & 0x3F) << 8) | payload[cursor + 1];

                if (pointer >= payload.Length || hops++ > 16)
                {
                    name = string.Empty;
                    return false;
                }

                if (postPointerOffset < 0)
                {
                    postPointerOffset = cursor + 2;
                }

                cursor = pointer;
                continue;
            }

            if ((length & 0xC0) != 0)
            {
                name = string.Empty;
                return false;
            }

            cursor++;

            if (cursor + length > payload.Length)
            {
                name = string.Empty;
                return false;
            }

            string label = Encoding.ASCII.GetString(payload, cursor, length);
            labels.Add(label);
            cursor += length;
        }

        offset = postPointerOffset >= 0
            ? postPointerOffset
            : cursor;

        name = string.Join('.', labels);
        return true;
    }

    private static ushort ToWireType(QueryType queryType)
    {
        return queryType switch
        {
            QueryType.A => 1,
            QueryType.NS => 2,
            QueryType.AAAA => 28,
            _ => (ushort)queryType,
        };
    }

    private readonly record struct QueryAttemptResult(
        double? ElapsedMilliseconds,
        int? ResponseCode,
        bool HasAnswers,
        bool IsTimeout,
        string? Error,
        string? AnswerFingerprint);

    private readonly record struct QueryWireResult(
        int ResponseCode,
        int AnswerCount,
        string? AnswerFingerprint);

    private readonly record struct ControlConsensus(bool BothNxDomain, string? LastError);

    private sealed class ProbeAggregate
    {
        public List<double> SuccessTimings { get; } = [];

        public int SuccessfulAttempts { get; set; }

        public int FailedAttempts { get; set; }

        // First successful response code is preserved so that a later timeout
        // cannot overwrite a valid SERVFAIL / NXDOMAIN needed by DNSSEC and redirect checks.
        public int? FirstResponseCode { get; set; }

        public bool FirstHasAnswers { get; set; }

        public string? LastError { get; set; }

        public double? AverageMilliseconds => SuccessTimings.Count == 0
            ? null
            : SuccessTimings.Average();
    }

    private sealed class RedirectAnalysis
    {
        public int RedirectLikeCount { get; set; }

        public int ControlComparisons { get; set; }

        public int ControlMismatchCount { get; set; }

        public bool RepeatedFingerprint { get; set; }

        public string? TopFingerprint { get; set; }

        public int TopFingerprintCount { get; set; }

        public bool IsRedirecting { get; set; }

        public double Confidence { get; set; }

        public string Evidence { get; set; } = string.Empty;

        public int SuccessfulAttempts { get; set; }

        public int FailedAttempts { get; set; }

        public string? LastError { get; set; }
    }
}
