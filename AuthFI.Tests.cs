// AuthFI .NET SDK Tests
// Run: dotnet test (after setting up test project)
//
// NOTE: These tests require the .NET SDK (dotnet) which is NOT installed in the
// authoring environment, so they have not been executed here — they are written
// to compile and pass under `dotnet test` / the bundled runner below.
//
// The signature-verification tests spin up a tiny in-process HTTP server
// (HttpListener) that serves a JWKS document at the AuthFI well-known path
// (<apiUrl>/v1/<tenant>/.well-known/jwks.json) and point the SDK at it via the
// apiUrl constructor argument. Tokens are minted with JsonWebTokenHandler so the
// "valid" case carries a real RS256 signature over the published key.

#if false // Uncomment when running as xunit test project
using Xunit;
#endif

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthFI.Tests;

/// <summary>
/// Unit tests for AuthFI .NET SDK.
/// These can be run with xunit, nunit, or mstest.
/// For quick validation, compile and check assertions.
/// </summary>
public class AuthFIClientTests
{
    private const string Tenant = "acme";
    private const string Issuer = "https://acme.authfi.app";
    private const string Kid = "test-key-1";

    /// <summary>
    /// A self-contained signing harness: an RSA key, a JWKS endpoint that publishes
    /// it, and a helper to mint RS256-signed tokens. Disposing it stops the server.
    /// </summary>
    private sealed class TestIssuer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly RsaSecurityKey _signingKey;
        public string ApiUrl { get; }

        public TestIssuer(RSA? publishKey = null, RSA? signKey = null, string kid = Kid)
        {
            var rsaSign = signKey ?? RSA.Create(2048);
            // By default the same key is published and used for signing. Tests that
            // want a forged signature pass a *different* publishKey.
            var rsaPublish = publishKey ?? rsaSign;

            _signingKey = new RsaSecurityKey(rsaSign) { KeyId = kid };

            var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(
                new RsaSecurityKey(rsaPublish) { KeyId = kid });
            jwk.Use = "sig";
            jwk.Alg = SecurityAlgorithms.RsaSha256;
            var jwksJson = JsonSerializer.Serialize(new { keys = new[] { jwk } });

            // Bind to an ephemeral port. The SDK requests
            //   {ApiUrl}/v1/{tenant}/.well-known/jwks.json
            var port = GetFreePort();
            ApiUrl = $"http://localhost:{port}";
            _listener = new HttpListener();
            _listener.Prefixes.Add($"{ApiUrl}/");
            _listener.Start();
            _ = ServeAsync(jwksJson);
        }

        private async Task ServeAsync(string jwksJson)
        {
            var bytes = Encoding.UTF8.GetBytes(jwksJson);
            while (_listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); }
                catch { break; } // listener stopped
                ctx.Response.ContentType = "application/json";
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.Close();
            }
        }

        public string MintToken(object claims)
        {
            var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = Issuer,
                Claims = ToClaimMap(claims),
                SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256),
            };
            return handler.CreateToken(descriptor);
        }

        private static Dictionary<string, object> ToClaimMap(object claims)
        {
            var json = JsonSerializer.Serialize(claims);
            return JsonSerializer.Deserialize<Dictionary<string, object>>(json)!;
        }

        private static int GetFreePort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { }
            try { _listener.Close(); } catch { }
        }
    }

    private static object ValidClaims(long? exp = null) => new
    {
        sub = "usr_123",
        email = "jane@acme.com",
        name = "Jane Smith",
        roles = new[] { "admin", "editor" },
        permissions = new[] { "read:users", "write:users" },
        tenant_id = "tnt_456",
        exp = exp ?? DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
        iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    };

    // --- Initialization ---

    public static void TestCreatesInstance()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        Assert(auth != null, "should create instance");
    }

    // --- Token verification ---

    public static void TestRejectsInvalidFormat()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        AssertThrows<AuthFIException>(() => auth.VerifyToken("not-a-jwt"), 401);
    }

    public static void TestDecodesValidPayload()
    {
        using var issuer = new TestIssuer();
        var auth = new AuthFIClient(Tenant, "sk_test", issuer.ApiUrl);

        var token = issuer.MintToken(ValidClaims());
        var claims = auth.VerifyToken(token);

        Assert(claims.Sub == "usr_123", "sub should be usr_123");
        Assert(claims.Email == "jane@acme.com", "email should match");
        Assert(claims.Roles.Length == 2, "should have 2 roles");
        Assert(claims.Permissions.Length == 2, "should have 2 permissions");
        Assert(claims.TenantId == "tnt_456", "tenant_id should match");
    }

    public static void TestRejectsTamperedToken()
    {
        using var issuer = new TestIssuer();
        var auth = new AuthFIClient(Tenant, "sk_test", issuer.ApiUrl);

        var token = issuer.MintToken(ValidClaims());

        // Tamper with the payload: flip "usr_123" -> "usr_999" without re-signing.
        var parts = token.Split('.');
        var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]))
            .Replace("usr_123", "usr_999");
        parts[1] = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var tampered = string.Join('.', parts);

        AssertThrows<AuthFIException>(() => auth.VerifyToken(tampered), 401);
    }

    public static void TestRejectsForgedSignature()
    {
        // Token is signed with a key that is NOT the one published in the JWKS.
        using var issuer = new TestIssuer(publishKey: RSA.Create(2048), signKey: RSA.Create(2048));
        var auth = new AuthFIClient(Tenant, "sk_test", issuer.ApiUrl);

        var token = issuer.MintToken(ValidClaims());

        AssertThrows<AuthFIException>(() => auth.VerifyToken(token), 401);
    }

    public static void TestRejectsExpiredToken()
    {
        using var issuer = new TestIssuer();
        var auth = new AuthFIClient(Tenant, "sk_test", issuer.ApiUrl);

        // Expired well beyond the 60s clock-skew allowance.
        var token = issuer.MintToken(ValidClaims(exp: DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds()));

        AssertThrows<AuthFIException>(() => auth.VerifyToken(token), 401);
    }

    public static void TestRejectsWrongIssuer()
    {
        using var issuer = new TestIssuer();
        // SDK configured for a different tenant -> expected issuer differs.
        var auth = new AuthFIClient("other-tenant", "sk_test", issuer.ApiUrl);

        var token = issuer.MintToken(ValidClaims());

        AssertThrows<AuthFIException>(() => auth.VerifyToken(token), 401);
    }

    // --- Permission checks ---

    public static void TestPassesWithMatchingPermissions()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        var claims = new AuthFIClaims { Permissions = new[] { "read:users", "write:users" } };
        auth.RequirePermissions(claims, "read:users"); // should not throw
    }

    public static void TestRaisesOnMissingPermission()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        var claims = new AuthFIClaims { Permissions = new[] { "read:users" } };
        AssertThrows<AuthFIException>(() => auth.RequirePermissions(claims, "delete:users"), 403);
    }

    public static void TestHandlesEmptyPermissions()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        var claims = new AuthFIClaims();
        AssertThrows<AuthFIException>(() => auth.RequirePermissions(claims, "read:users"), 403);
    }

    // --- Role checks ---

    public static void TestPassesWithMatchingRole()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        var claims = new AuthFIClaims { Roles = new[] { "editor" } };
        auth.RequireRole(claims, "admin", "editor"); // should not throw
    }

    public static void TestRaisesOnMissingRole()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        var claims = new AuthFIClaims { Roles = new[] { "viewer" } };
        AssertThrows<AuthFIException>(() => auth.RequireRole(claims, "admin"), 403);
    }

    // --- Permission registration ---

    public static void TestRegistersPermissions()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        auth.RegisterPermission("read:users", "Read user data");
        auth.RegisterPermission("write:users");
        // Should not throw
    }

    // --- Sync ---

    public static void TestSyncEmptyIsNoop()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        var task = auth.SyncAsync();
        task.Wait();
        // Empty sync should complete without error
    }

    // --- Exception ---

    public static void TestExceptionStatus()
    {
        var ex = new AuthFIException("test", 403);
        Assert(ex.Status == 403, "status should be 403");
        Assert(ex.Message == "test", "message should be test");
    }

    // --- Runner ---

    public static void Main(string[] args)
    {
        Console.WriteLine("\nAuthFI .NET SDK Tests");
        Console.WriteLine(new string('=', 40));

        int passed = 0, failed = 0;
        var tests = new (string name, Action fn)[]
        {
            ("creates instance", TestCreatesInstance),
            ("rejects invalid format", TestRejectsInvalidFormat),
            ("decodes valid (signed) payload", TestDecodesValidPayload),
            ("rejects tampered token", TestRejectsTamperedToken),
            ("rejects forged signature", TestRejectsForgedSignature),
            ("rejects expired token", TestRejectsExpiredToken),
            ("rejects wrong issuer", TestRejectsWrongIssuer),
            ("passes with matching permissions", TestPassesWithMatchingPermissions),
            ("raises on missing permission", TestRaisesOnMissingPermission),
            ("handles empty permissions", TestHandlesEmptyPermissions),
            ("passes with matching role", TestPassesWithMatchingRole),
            ("raises on missing role", TestRaisesOnMissingRole),
            ("registers permissions", TestRegistersPermissions),
            ("sync empty is noop", TestSyncEmptyIsNoop),
            ("exception status", TestExceptionStatus),
        };

        foreach (var (name, fn) in tests)
        {
            try { fn(); Console.WriteLine($"  PASS {name}"); passed++; }
            catch (Exception ex) { Console.WriteLine($"  FAIL {name} - {ex.Message}"); failed++; }
        }

        Console.WriteLine($"\n{new string('=', 40)}");
        Console.WriteLine($"Results: {passed} passed, {failed} failed");
        Environment.Exit(failed > 0 ? 1 : 0);
    }

    // --- Helpers ---

    private static void Assert(bool condition, string msg)
    {
        if (!condition) throw new Exception($"Assertion failed: {msg}");
    }

    private static void AssertThrows<T>(Action fn, int? expectedStatus = null) where T : Exception
    {
        try
        {
            fn();
            throw new Exception($"Expected {typeof(T).Name} to be thrown");
        }
        catch (T ex)
        {
            if (expectedStatus.HasValue && ex is AuthFIException ae && ae.Status != expectedStatus.Value)
                throw new Exception($"Expected status {expectedStatus}, got {ae.Status}");
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Convert.FromBase64String(s);
    }

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
