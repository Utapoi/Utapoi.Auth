using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Utapoi.Auth.Core.Entities;

namespace Utapoi.Auth.Infrastructure.Persistence;

public sealed class UtapoiAuthDbContext : IdentityDbContext<UtapoiUser, IdentityRole<Guid>, Guid>
{
    public UtapoiAuthDbContext(DbContextOptions<UtapoiAuthDbContext> options) : base(options)
    {
        ChangeTracker.LazyLoadingEnabled = false;
    }

    public DbSet<Token> Tokens => Set<Token>();

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetAssembly(typeof(UtapoiAuthDbContext)) ??
                                                     Assembly.GetExecutingAssembly());

        base.OnModelCreating(modelBuilder);
    }
}