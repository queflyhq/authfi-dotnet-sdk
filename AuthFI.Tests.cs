// AuthFI .NET SDK Tests
// Run: dotnet test (after setting up test project)
// Or verify manually with: dotnet script AuthFI.Tests.cs

#if false // Uncomment when running as xunit test project
using Xunit;
#endif

using System.Text;
using System.Text.Json;

namespace AuthFI.Tests;

/// <summary>
/// Unit tests for AuthFI .NET SDK.
/// These can be run with xunit, nunit, or mstest.
/// For quick validation, compile and check assertions.
/// </summary>
public class AuthFIClientTests
{
    private static string MakeToken(object payload)
    {
        var header = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key-1\"}"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var body = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var sig = Convert.ToBase64String(Encoding.UTF8.GetBytes("fakesig"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return $"{header}.{body}.{sig}";
    }

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

    public static void TestRejectsExpiredToken()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        var token = MakeToken(new { Sub = "usr_123", Exp = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds() });
        AssertThrows<AuthFIException>(() => auth.VerifyToken(token), 401);
    }

    public static void TestDecodesValidPayload()
    {
        var auth = new AuthFIClient("acme", "sk_test");
        var token = MakeToken(new
        {
            Sub = "usr_123",
            Email = "jane@acme.com",
            Roles = new[] { "admin", "editor" },
            Permissions = new[] { "read:users", "write:users" },
            Exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        });
        var claims = auth.VerifyToken(token);
        Assert(claims.Sub == "usr_123", "sub should be usr_123");
        Assert(claims.Email == "jane@acme.com", "email should match");
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
            ("rejects expired token", TestRejectsExpiredToken),
            ("decodes valid payload", TestDecodesValidPayload),
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
            try { fn(); Console.WriteLine($"  ✓ {name}"); passed++; }
            catch (Exception ex) { Console.WriteLine($"  ✗ {name} — {ex.Message}"); failed++; }
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
}
