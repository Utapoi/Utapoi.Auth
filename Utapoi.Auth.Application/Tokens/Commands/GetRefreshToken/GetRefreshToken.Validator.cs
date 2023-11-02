using FluentValidation;
using JetBrains.Annotations;

namespace Utapoi.Auth.Application.Tokens.Commands.GetRefreshToken;

public static partial class GetRefreshToken
{
    [UsedImplicitly]
    internal sealed class Validator : AbstractValidator<Command>
    {
        public Validator()
        {
            RuleFor(x => x.Token).NotEmpty();
            RuleFor(x => x.RefreshToken).NotEmpty();
            RuleFor(x => x.IpAddress).NotEmpty();
        }
    }
}