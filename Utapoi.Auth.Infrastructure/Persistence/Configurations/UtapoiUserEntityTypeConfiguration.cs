using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Utapoi.Auth.Core.Entities.Identity;
using Utapoi.Auth.Core.Entities.Relations;

namespace Utapoi.Auth.Infrastructure.Persistence.Configurations;

internal sealed class UtapoiUserEntityTypeConfiguration : IEntityTypeConfiguration<UtapoiUser>
{
    public void Configure(EntityTypeBuilder<UtapoiUser> builder)
    {
        builder.HasMany(u => u.Tokens)
            .WithOne(t => t.User)
            .HasForeignKey(t => t.UserId);

        builder.HasMany(u => u.RefreshTokens)
            .WithOne(t => t.User)
            .HasForeignKey(t => t.UserId);

        builder.HasMany(u => u.Roles)
            .WithMany();

        builder.HasMany(u => u.Claims)
            .WithMany();

        builder.HasMany(u => u.Logins)
            .WithMany()
            .UsingEntity<UtapoiUserUserLogin>();
    }
}