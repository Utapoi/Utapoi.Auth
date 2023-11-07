using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Utapoi.Auth.Core.Entities;

namespace Utapoi.Auth.Infrastructure.Persistence.Configurations;

public class TokenEntityTypeConfiguration : IEntityTypeConfiguration<Token>
{
    public void Configure(EntityTypeBuilder<Token> builder)
    {
        builder.HasOne(t => t.RefreshToken)
            .WithOne(t => t.AccessToken)
            .HasForeignKey<Token>(t => t.RefreshTokenId);
    }
}