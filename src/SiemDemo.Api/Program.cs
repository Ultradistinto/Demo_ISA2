using System.Diagnostics;
using Elastic.Channels;
using Elastic.Ingest.Elasticsearch;
using Elastic.Ingest.Elasticsearch.DataStreams;
using Elastic.Serilog.Sinks;
using Serilog;
using Serilog.Context;

var builder = WebApplication.CreateBuilder(args);

// URL de Elasticsearch desde env var (para correr en Docker apuntando al
// service `elasticsearch`) con fallback a localhost para correr fuera de Docker.
var esUrl = Environment.GetEnvironmentVariable("ELASTICSEARCH_URL")
            ?? "http://localhost:9200";

builder.Host.UseSerilog((ctx, services, lc) => lc
    .ReadFrom.Configuration(ctx.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithProperty("service.name", "siem-demo-api")
    .WriteTo.Console()
    .WriteTo.Elasticsearch(new[] { new Uri(esUrl) }, opts =>
    {
        opts.DataStream = new DataStreamName("logs", "api", "siem");
        opts.BootstrapMethod = BootstrapMethod.Failure;
    }, transport => { }));

var app = builder.Build();

// Forwarded headers so k6's X-Forwarded-For lands in HttpContext.Connection.RemoteIpAddress
app.UseForwardedHeaders(new Microsoft.AspNetCore.Builder.ForwardedHeadersOptions
{
    ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor,
    KnownNetworks = { },
    KnownProxies = { }
});

// Per-request structured log: client.ip, http.*, event.duration
app.Use(async (ctx, next) =>
{
    var sw = Stopwatch.StartNew();
    var clientIp =
        ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',').FirstOrDefault()?.Trim()
        ?? ctx.Connection.RemoteIpAddress?.ToString()
        ?? "unknown";

    await next();
    sw.Stop();

    using (LogContext.PushProperty("client.ip", clientIp))
    using (LogContext.PushProperty("http.request.method", ctx.Request.Method))
    using (LogContext.PushProperty("url.path", ctx.Request.Path.Value))
    using (LogContext.PushProperty("url.query", ctx.Request.QueryString.Value))
    using (LogContext.PushProperty("http.response.status_code", ctx.Response.StatusCode))
    using (LogContext.PushProperty("http.response.bytes", ctx.Response.ContentLength ?? 0))
    using (LogContext.PushProperty("user_agent.original", ctx.Request.Headers.UserAgent.ToString()))
    using (LogContext.PushProperty("event.duration_ms", sw.Elapsed.TotalMilliseconds))
    {
        Log.Information("HTTP {Method} {Path} -> {Status} in {Duration:F1}ms from {ClientIp}",
            ctx.Request.Method, ctx.Request.Path, ctx.Response.StatusCode, sw.Elapsed.TotalMilliseconds, clientIp);
    }
});

// Fake user store (intentionally small — brute force should hit it)
var users = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
{
    ["alice"]   = "password123",
    ["bob"]     = "qwerty",
    ["charlie"] = "letmein",
    ["dave"]    = "hunter2",
};

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/login", (LoginRequest req) =>
{
    if (req is null || string.IsNullOrWhiteSpace(req.Username))
        return Results.BadRequest(new { error = "missing_credentials" });

    if (users.TryGetValue(req.Username, out var expected) && expected == req.Password)
    {
        Log.Information("auth.success {User}", req.Username);
        return Results.Ok(new { token = $"fake-token-{Guid.NewGuid():N}" });
    }

    Log.Warning("auth.failure {User}", req.Username);
    return Results.Json(new { error = "invalid_credentials" }, statusCode: 401);
});

app.MapGet("/search", (string? q) =>
{
    var results = string.IsNullOrWhiteSpace(q)
        ? Array.Empty<object>()
        : new object[] { new { id = 1, title = $"Result for {q}" } };
    return Results.Ok(new { query = q, results });
});

app.MapGet("/profile/{id:int}", (int id) =>
    id is > 0 and < 1000
        ? Results.Ok(new { id, name = $"user{id}", joined = "2024-01-01" })
        : Results.NotFound(new { error = "not_found" }));

app.Run();

record LoginRequest(string Username, string Password);
