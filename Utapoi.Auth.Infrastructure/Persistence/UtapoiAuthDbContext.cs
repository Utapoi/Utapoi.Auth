using System.Reflection;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Utapoi.Auth.Core.Entities;
using Utapoi.Auth.Core.Entities.Identity;

namespace Utapoi.Auth.Infrastructure.Persistence;

public sealed class UtapoiDbContext : UtapoiDbContext<UtapoiUser, UtapoiRole, Guid>
{
    public UtapoiDbContext(DbContextOptions options) : base(options)
    {
        ChangeTracker.LazyLoadingEnabled = false;
    }

    public UtapoiDbContext(DbContextOptions<UtapoiDbContext<UtapoiUser, UtapoiRole, Guid>> options) : base(options)
    {
        ChangeTracker.LazyLoadingEnabled = false;
    }
}

public class UtapoiDbContext<TUser, TRole, TKey> : IdentityDbContext<TUser, TRole, TKey>
    where TUser : UtapoiUser<TKey>
    where TRole : UtapoiRole<TKey>
    where TKey : IEquatable<TKey>
{
    public UtapoiDbContext(DbContextOptions options) : base(options)
    {
    }

    public UtapoiDbContext(DbContextOptions<UtapoiDbContext<TUser, TRole, TKey>> options) : base(options)
    {
    }

    public DbSet<Token> Tokens => Set<Token>();

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetAssembly(typeof(UtapoiDbContext)) ??
                                                     Assembly.GetExecutingAssembly());

        base.OnModelCreating(modelBuilder);
    }
}