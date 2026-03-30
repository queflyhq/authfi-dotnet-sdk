using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

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
    private readonly HttpClient _http = new();
    private readonly Dictionary<string, string?> _permissions = new();

    public AuthFIClient(string tenant, string apiKey, string apiUrl = "https://api.authfi.app", string? applicationId = null)
    {
        _tenant = tenant;
        _apiKey = apiKey;
        _apiUrl = apiUrl;
        _applicationId = applicationId;
    }

    /// <summary>Authenticate request and return decoded claims.</summary>
    public AuthFIClaims Authenticate(HttpContext context)
    {
        var auth = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(auth) || !auth.StartsWith("Bearer "))
            throw new AuthFIException("Missing authorization", 401);

        return VerifyToken(auth[7..]);
    }

    /// <summary>Verify JWT and return claims.</summary>
    public AuthFIClaims VerifyToken(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) throw new AuthFIException("Invalid token", 401);

        var payload = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
        var claims = JsonSerializer.Deserialize<AuthFIClaims>(payload) ?? throw new AuthFIException("Invalid payload", 401);

        if (claims.Exp > 0 && claims.Exp < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            throw new AuthFIException("Token expired", 401);

        // NOTE: For production, verify RS256 signature using Microsoft.IdentityModel.Tokens
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

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Convert.FromBase64String(s);
    }
}

public class AuthFIClaims
{
    public string Sub { get; set; } = "";
    public string Email { get; set; } = "";
    public string Name { get; set; } = "";
    public string[] Roles { get; set; } = Array.Empty<string>();
    public string[] Permissions { get; set; } = Array.Empty<string>();
    public string TenantId { get; set; } = "";
    public string OrgId { get; set; } = "";
    public long Exp { get; set; }
    public long Iat { get; set; }
}

public class AuthFIException : Exception
{
    public int Status { get; }
    public AuthFIException(string message, int status) : base(message) { Status = status; }
}
