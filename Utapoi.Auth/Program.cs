using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Utapoi.Auth.Entities;
using Utapoi.Auth.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddDbContext<UtapoiAuthDbContext>(c =>
    {
        c.UseMongoDB(builder.Configuration.GetConnectionString("UtapoiAuthDb")!, "UtapoiAuthDb");
    });

builder.Services
    .AddIdentity<UtapoiUser, IdentityRole<Guid>>(c =>
    {
        c.SignIn.RequireConfirmedAccount = false;
        c.SignIn.RequireConfirmedEmail = false;
    })
    .AddEntityFrameworkStores<UtapoiAuthDbContext>()
    .AddDefaultTokenProviders()
    .AddSignInManager();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(c =>
    {
        c.Cookie.Name = "UtapoiAuth";
        c.Cookie.Domain = ".utapoi.com";
        c.Cookie.HttpOnly = true;
        c.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        c.Cookie.SameSite = SameSiteMode.Strict;

        c.LoginPath = "/Identity/Account/Login";
        c.AccessDeniedPath = "/Identity/Account/AccessDenied";
        c.ExpireTimeSpan = TimeSpan.FromHours(2);
        c.SlidingExpiration = true;
    });

builder.Services.AddAuthorization();

builder.Services.AddControllers();
builder.Services.AddRazorPages();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();
app.MapControllers();

app.Run();
