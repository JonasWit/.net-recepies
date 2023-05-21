using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace CookiesAndTokens;

public static class AppExtensions
{
    public static async Task<WebApplication> BuildAndSetup(this WebApplicationBuilder builder)
    {
        var app = builder.Build();
        using var scope = app.Services.CreateScope();

        var um = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = new IdentityUser() { UserName = "test@test.com", Email = "test@test.com" };
        _ = await um.CreateAsync(user, password: "password");
        _ = await um.AddClaimAsync(user, new Claim("role", "janitor"));

        return app;

    }
}
