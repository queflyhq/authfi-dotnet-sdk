using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthFI;

/// <summary>
/// AuthFI .NET SDK
///
/// Usage (ASP.NET Core):
///   var auth = new AuthFIClient("acme", "sk_live_...");
///
///   app.MapGet("/api/users", (HttpContext ctx) => {
///       var user = auth.Authenticate(ctx);
///       auth.RequirePermissions(user, "read:users");
///       return Results.Ok(users);
///   });
///
///   await auth.SyncAsync();
/// </summary>
public class AuthFIClient
{
    private readonly string _tenant;
    private readonly string _apiKey;
    private readonly string _apiUrl;
    private readonly string? _applicationId;
    private readonly string _issuer;
    private readonly string _jwksUrl;
    private readonly HttpClient _http = new();
    private readonly Dictionary<string, string?> _permissions = new();
    private readonly JsonWebTokenHandler _tokenHandler = new();
    private readonly JwksCache _jwks;

    public AuthFIClient(string tenant, string apiKey, string apiUrl = "https://api.authfi.io", string? applicationId = null)
    {
        _tenant = tenant;
        _apiKey = apiKey;
        _apiUrl = apiUrl.TrimEnd('/');
        _applicationId = applicationId;

        // AuthFI issues tokens under https://<tenant>.authfi.io and publishes its
        // signing keys at <apiUrl>/v1/<tenant>/.well-known/jwks.json (see other SDKs).
        _issuer = $"https://{tenant}.authfi.io";
        _jwksUrl = $"{_apiUrl}/v1/{tenant}/.well-known/jwks.json";
        _jwks = new JwksCache(_http, _jwksUrl);
    }

    /// <summary>Authenticate request and return decoded claims.</summary>
    public AuthFIClaims Authenticate(HttpContext context)
    {
        var auth = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(auth) || !auth.StartsWith("Bearer "))
            throw new AuthFIException("Missing authorization", 401);

        return VerifyToken(auth[7..]);
    }

    /// <summary>
    /// Verify a JWT and return its claims.
    ///
    /// Performs full RS256 signature verification against the tenant's JWKS,
    /// and validates issuer and lifetime (exp/nbf). The JWKS is cached in-memory
    /// with a short TTL and refetched automatically when an unknown <c>kid</c> is
    /// seen (key rotation). Any failure — bad signature, unknown key, expired,
    /// wrong issuer, or JWKS fetch failure — throws <see cref="AuthFIException"/>.
    /// </summary>
    public AuthFIClaims VerifyToken(string token)
    {
        if (string.IsNullOrEmpty(token) || token.Split('.').Length != 3)
            throw new AuthFIException("Invalid token", 401);

        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            // Resolve keys dynamically so we can refetch the JWKS on an unknown kid.
            IssuerSigningKeyResolver = (_, _, kid, _) => _jwks.GetSigningKeys(kid),
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }, // RS256 only

            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(60),

            ValidateIssuer = true,
            ValidIssuer = _issuer,

            // The SDK does not bind a specific audience.
            ValidateAudience = false,
        };

        TokenValidationResult result;
        try
        {
            result = _tokenHandler.ValidateToken(token, parameters);
        }
        catch (AuthFIException)
        {
            // Propagate JWKS fetch failures raised inside the key resolver.
            throw;
        }
        catch (Exception ex)
        {
            throw new AuthFIException($"Invalid token: {ex.Message}", 401);
        }

        if (!result.IsValid)
        {
            var reason = result.Exception?.Message ?? "signature or claim validation failed";
            throw new AuthFIException($"Invalid token: {reason}", 401);
        }

        // Reconstruct the public claims shape from the verified token payload.
        var jwt = (JsonWebToken)result.SecurityToken;
        var claims = JsonSerializer.Deserialize<AuthFIClaims>(jwt.EncodedPayload.DecodeBase64Url())
            ?? throw new AuthFIException("Invalid payload", 401);

        return claims;
    }

    /// <summary>Check ALL permissions present.</summary>
    public void RequirePermissions(AuthFIClaims user, params string[] permissions)
    {
        var userPerms = new HashSet<string>(user.Permissions ?? Array.Empty<string>());
        var missing = permissions.Where(p => !userPerms.Contains(p)).ToList();

        foreach (var p in permissions) RegisterPermission(p);

        if (missing.Count > 0)
            throw new AuthFIException($"Missing permissions: {string.Join(", ", missing)}", 403);
    }

    /// <summary>Check ANY role matches.</summary>
    public void RequireRole(AuthFIClaims user, params string[] roles)
    {
        var userRoles = new HashSet<string>(user.Roles ?? Array.Empty<string>());
        if (!roles.Any(r => userRoles.Contains(r)))
            throw new AuthFIException("Insufficient role", 403);
    }

    public void RegisterPermission(string name, string? description = null)
    {
        _permissions.TryAdd(name, description);
    }

    /// <summary>Sync permissions to AuthFI.</summary>
    public async Task SyncAsync()
    {
        if (_permissions.Count == 0) return;

        var body = new
        {
            permissions = _permissions.Select(p => new { name = p.Key, description = p.Value }).ToArray(),
            application_id = _applicationId
        };

        var req = new HttpRequestMessage(HttpMethod.Put, $"{_apiUrl}/manage/v1/{_tenant}/permissions/sync")
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
        req.Headers.Add("X-API-Key", _apiKey);

        var res = await _http.SendAsync(req);
        var responseBody = await res.Content.ReadAsStringAsync();

        if (res.IsSuccessStatusCode)
            Console.WriteLine($"[authfi] Permissions synced: {responseBody}");
        else
            Console.Error.WriteLine($"[authfi] Sync failed: {responseBody}");
    }
}

/// <summary>
/// In-memory JWKS cache. Keys are fetched from the tenant's well-known endpoint
/// and cached for a short TTL. An unknown <c>kid</c> triggers an immediate refetch
/// (to support signing-key rotation) before giving up.
/// </summary>
internal sealed class JwksCache
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private readonly HttpClient _http;
    private readonly string _jwksUrl;
    private readonly object _lock = new();

    private JsonWebKeySet? _keySet;
    private ConcurrentDictionary<string, SecurityKey>? _byKid;
    private DateTimeOffset _fetchedAt = DateTimeOffset.MinValue;

    public JwksCache(HttpClient http, string jwksUrl)
    {
        _http = http;
        _jwksUrl = jwksUrl;
    }

    /// <summary>
    /// Returns the signing key(s) matching <paramref name="kid"/>. Uses the cached
    /// JWKS when fresh and the kid is known; otherwise refetches. Throws
    /// <see cref="AuthFIException"/> if the JWKS cannot be fetched or the kid is
    /// still unknown after a refetch.
    /// </summary>
    public IEnumerable<SecurityKey> GetSigningKeys(string? kid)
    {
        var fresh = DateTimeOffset.UtcNow - _fetchedAt < Ttl;

        if (!fresh || _byKid == null || (kid != null && !_byKid.ContainsKey(kid)))
            Refresh();

        if (kid != null && _byKid != null && _byKid.TryGetValue(kid, out var key))
            return new[] { key };

        // No kid in header (rare) or kid not found after refresh — hand over all
        // keys so the handler can try each, but fail loudly if the set is empty.
        var all = _keySet?.GetSigningKeys();
        if (all == null || !all.Any())
            throw new AuthFIException(
                kid != null ? $"Unknown signing key: {kid}" : "No signing keys available", 401);
        return all;
    }

    private void Refresh()
    {
        lock (_lock)
        {
            // Another thread may have refreshed while we waited on the lock.
            if (DateTimeOffset.UtcNow - _fetchedAt < Ttl && _byKid != null)
                return;

            string json;
            try
            {
                json = _http.GetStringAsync(_jwksUrl).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                throw new AuthFIException($"JWKS fetch failed: {ex.Message}", 401);
            }

            JsonWebKeySet keySet;
            try
            {
                keySet = new JsonWebKeySet(json);
            }
            catch (Exception ex)
            {
                throw new AuthFIException($"Invalid JWKS: {ex.Message}", 401);
            }

            var byKid = new ConcurrentDictionary<string, SecurityKey>();
            foreach (var key in keySet.GetSigningKeys())
            {
                if (!string.IsNullOrEmpty(key.KeyId))
                    byKid[key.KeyId] = key;
            }

            _keySet = keySet;
            _byKid = byKid;
            _fetchedAt = DateTimeOffset.UtcNow;
        }
    }
}

internal static class Base64UrlExtensions
{
    public static string DecodeBase64Url(this string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Encoding.UTF8.GetString(Convert.FromBase64String(s));
    }
}

public class AuthFIClaims
{
    [JsonPropertyName("sub")]
    public string Sub { get; set; } = "";

    [JsonPropertyName("email")]
    public string Email { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("roles")]
    public string[] Roles { get; set; } = Array.Empty<string>();

    [JsonPropertyName("permissions")]
    public string[] Permissions { get; set; } = Array.Empty<string>();

    [JsonPropertyName("tenant_id")]
    public string TenantId { get; set; } = "";

    [JsonPropertyName("org_id")]
    public string OrgId { get; set; } = "";

    [JsonPropertyName("exp")]
    public long Exp { get; set; }

    [JsonPropertyName("iat")]
    public long Iat { get; set; }
}

public class AuthFIException : Exception
{
    public int Status { get; }
    public AuthFIException(string message, int status) : base(message) { Status = status; }
}
