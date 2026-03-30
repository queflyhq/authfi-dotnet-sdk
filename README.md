# AuthFI .NET SDK

Official .NET SDK for [AuthFI](https://authfi.app) — the identity control plane.

## Install

```bash
dotnet add package AuthFI
```

## Quick Start

```csharp
var auth = new AuthFIClient("acme", "sk_live_...");

// ASP.NET Core minimal API
app.MapGet("/api/users", (HttpContext ctx) => {
    var user = auth.Authenticate(ctx);
    auth.RequirePermissions(user, "read:users");
    return Results.Ok(users);
});

// Sync permissions on startup
await auth.SyncAsync();
```

## Features

- JWT verification (RS256 via JWKS)
- Permission checks — `RequirePermissions(user, "read:users")`
- Role checks — `RequireRole(user, "admin")`
- Permission auto-sync to AuthFI console
- Works with ASP.NET Core 8+

## Token Verification

```csharp
var claims = auth.VerifyToken(token);
// claims.Sub, claims.Email, claims.Roles, claims.Permissions
```

## Permission Registration

```csharp
auth.RegisterPermission("read:users", "Read user list");
auth.RegisterPermission("write:users", "Create/update users");
await auth.SyncAsync(); // push to AuthFI console
```

## License

MIT
