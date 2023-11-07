using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Utapoi.Auth.Core.Entities;

namespace Utapoi.Auth.Infrastructure.Persistence.Configurations;

public sealed class RefreshTokenEntityTypeConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.HasOne(r => r.AccessToken)
            .WithOne(r => r.RefreshToken)
            .HasForeignKey<RefreshToken>(r => r.TokenId);
    }
}