using Microsoft.Extensions.Caching.Memory;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

const string cookieName = "token";

var tokens = new Dictionary<string, DateTime>();

var cache = new MemoryCache(new MemoryCacheOptions());

var builder = WebApplication.CreateBuilder(args);

var realms = builder.Configuration.GetSection("Realms").Get<Dictionary<string, string>>() ?? [];

var app = builder.Build();

app.MapGet("/auth/webauthn.js", () =>
{
    var path = Path.Combine(Environment.CurrentDirectory, "webauthn.js");
    return Results.File(path, MediaTypeNames.Text.JavaScript);
});

app.MapGet("/auth/check", (HttpContext ctx) =>
{
    var token = ctx.Request.Cookies[cookieName];
    if (!string.IsNullOrEmpty(token) && IsTokenValid(token))
    {
        Results.Ok();
    }
    else
    {
        ctx.Response.StatusCode = 401;
    }
});

app.MapGet("/auth/login", () => {
    string html = "<body><script src=\"webauthn.js\"></script><div id=\"command\"/></body>";
    return Results.Content(html, MediaTypeNames.Text.Html);
});

app.MapGet("/auth/logout", (HttpContext ctx) =>
{
    if (ctx.Request.Cookies.ContainsKey(cookieName))
    {
        var token = ctx.Request.Cookies[cookieName];
        tokens.Remove(token);
        ctx.Response.Cookies.Delete(cookieName);
    }
    ctx.Response.Redirect("/");
});

app.MapPost("/auth/get_challenge_for_new_key", (HttpContext ctx) =>
{
    var origin = new Uri(ctx.Request.Headers.Origin);

    var challenge = GenerateChallenge();

    var rp = new
    {
        id = origin.Host,
        name = "NGINX Auth Server"
    };

    var user = new
    {
        id = "default",
        name = "Default user",
        displayName = "Default user"
    };

    var pubKeyCredParams = new[] {
        new {
            type = "public-key",
            alg = -7
        }
    };

    //https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create#creating_a_public_key_credential
    var publicKey = new { publicKey = new { challenge, rp, user, pubKeyCredParams } };

    return Results.Json(publicKey);
});

app.MapPost("/auth/get_challenge_for_existing_key", (HttpContext ctx) =>
{
    var origin = new Uri(ctx.Request.Headers.Origin);

    if (!realms.ContainsKey(origin.Host))
    {
        return Results.Json(new { error = "not_configured" });
    }

    var key = (string)ctx.Request.Headers["X-Forwarded-For"] ?? ctx.Connection.RemoteIpAddress.ToString();
    var challenge = cache.Set<string>(key, GenerateChallenge());

    var rpId = origin.Host;

    var allowCredentials = new[] {
        new {
            type = "public-key",
            id = realms[origin.Host].Split(' ')[0]
        }
    };

    var userVerification = "preferred";

    //https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#retrieving_a_public_key_credential
    var publicKey = new { publicKey = new { allowCredentials, challenge, rpId, userVerification } };

    return Results.Json(publicKey);
});

app.MapPost("/auth/complete_challenge_for_existing_key", (JsonElement data, HttpContext ctx) =>
{
    var origin = new Uri(ctx.Request.Headers.Origin);

    var key = (string)ctx.Request.Headers["X-Forwarded-For"] ?? ctx.Connection.RemoteIpAddress.ToString();
    string challenge = cache.Get<string>(key);

    string authenticatorData = data.GetProperty("authenticatorData").GetString();
    string clientDataJSON = data.GetProperty("clientDataJSON").GetString();
    var dataToVerify = GenerateComparison(authenticatorData, clientDataJSON);

    realms.TryGetValue(origin.Host, out var realm);
    var split = realm.Split(' ');

    if (split[0] == data.GetProperty("id").GetString() && 
        IsDataValid(clientDataJSON, challenge.TrimEnd('='), origin.AbsoluteUri.TrimEnd('/')) &&
        IsSignatureValid(split[1], data.GetProperty("signature").GetString(), dataToVerify))
    {
        ctx.Response.Cookies.Append(cookieName, GenerateToken(), new CookieOptions { HttpOnly = true, Secure = true });
    }

    return Results.Ok();
});

app.Run("http://*:8080");

string GenerateChallenge()
{
    var randomString = RandomNumberGenerator.GetString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 16);
    var bytes = ASCIIEncoding.ASCII.GetBytes(randomString);
    return Convert.ToBase64String(bytes);
}

bool IsDataValid(string encodedData, string challenge, string origin)
{
    var bytes = Convert.FromBase64String(encodedData);
    var data = ASCIIEncoding.ASCII.GetString(bytes);
    var clientData = JsonSerializer.Deserialize<JsonElement>(data);

    var typeValid = clientData.GetProperty("type").GetString().Equals("webauthn.get");
    var challengeValid = clientData.GetProperty("challenge").GetString().Equals(challenge);
    var originValid = clientData.GetProperty("origin").GetString().Equals(origin);

    return typeValid && challengeValid && originValid;
}

byte[] GenerateComparison(string authenticatorData, string clientDataJSON)
{
    var auth = Convert.FromBase64String(authenticatorData);
    using var sha256 = SHA256.Create();
    var hash = sha256.ComputeHash(Convert.FromBase64String(clientDataJSON));

    var data = new byte[auth.Length + hash.Length];
    auth.CopyTo(data, 0);
    hash.CopyTo(data, auth.Length);

    return data;
}

bool IsSignatureValid(string publicKey, string signature, byte[] comparison)
{
    var key = Convert.FromBase64String(publicKey);
    var sig = Convert.FromBase64String(signature);

    using var ecdsa = ECDsa.Create();
    ecdsa.ImportSubjectPublicKeyInfo(key, out _);

    return ecdsa.VerifyData(comparison, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
}

string GenerateToken()
{
    var token = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
    tokens[token] = DateTime.UtcNow;
    return token;
}

bool IsTokenValid(string token)
{
    bool result = false;

    if (tokens.TryGetValue(token, out var timestamp))
    {
        if (DateTime.UtcNow - timestamp < TimeSpan.FromDays(1))
        {
            result = true;
        }
        else
        {
            tokens.Remove(token);
        }
    }

    return result;
}