using Utapoi.Auth.Application;
using Utapoi.Auth.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(c =>
{
    c.AddDefaultPolicy(p =>
    {
        if (builder.Environment.IsDevelopment())
        {
            p.AllowAnyHeader()
             .AllowAnyMethod()
             .AllowCredentials()
             .WithOrigins("http://localhost:3001", "https://localhost:7027");
        }
        else if (builder.Environment.IsStaging())
        {
            p.AllowAnyHeader()
             .AllowAnyMethod()
             .AllowCredentials()
             .WithOrigins("https://mq-dev.utapoi.com", "https://mq-api-dev.utapoi.com");
        }
        else if (builder.Environment.IsProduction())
        {
            p.AllowAnyHeader()
             .AllowAnyMethod()
             .AllowCredentials()
             .WithOrigins("https://mq.utapoi.com", "https://mq-api.utapoi.com");
        }
    });
});

builder
    .Services
    .AddApplication()
    .AddInfrastructure(builder.Configuration);

builder.Services.AddControllers().AddJsonOptions(x => x.JsonSerializerOptions.PropertyNamingPolicy = null); ;
builder.Services.AddRazorPages();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => { c.CustomSchemaIds(type => type?.FullName?.Replace("+", ".")); });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();
app.MapControllers();

app.Run();
