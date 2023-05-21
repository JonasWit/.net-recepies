using CookiesAndTokens;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var keyManager = new KeyManager();
builder.Services.AddSingleton(keyManager);
builder.Services.AddDbContext<IdentityDbContext>(c => c.UseInMemoryDatabase(Guid.NewGuid().ToString()));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(o =>
    {
        o.User.RequireUniqueEmail = false;

        o.Password.RequireDigit = false;
        o.Password.RequiredLength = 4;
        o.Password.RequireLowercase = false;
        o.Password.RequireNonAlphanumeric = false;
        o.Password.RequireUppercase = false;
    })
    .AddEntityFrameworkStores<IdentityDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication()
    .AddJwtBearer("jwy", o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateAudience = false,
            ValidateIssuer = false,
        };

        o.Configuration = new OpenIdConnectConfiguration()
        {
            SigningKeys =
            {
                new RsaSecurityKey(keyManager.RsaKey)
            }
        };
        o.MapInboundClaims = false;

    });

var app = builder.Build();

app.Run();

