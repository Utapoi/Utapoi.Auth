using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Reflection;
using Utapoi.Auth.Entities;

namespace Utapoi.Auth.Persistence;

public sealed class UtapoiAuthDbContext : IdentityDbContext<UtapoiUser, IdentityRole<Guid>, Guid>
{
    public UtapoiAuthDbContext(DbContextOptions<UtapoiAuthDbContext> options) : base(options)
    {
        ChangeTracker.LazyLoadingEnabled = false;
    }

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetAssembly(typeof(UtapoiAuthDbContext)) ??
                                                     Assembly.GetExecutingAssembly());

        base.OnModelCreating(modelBuilder);
    }
}