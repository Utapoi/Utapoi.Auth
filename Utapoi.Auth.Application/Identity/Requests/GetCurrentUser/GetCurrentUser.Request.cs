using FluentResults;
using MediatR;

namespace Utapoi.Auth.Application.Identity.Requests.GetCurrentUser;

public static partial class GetCurrentUser
{
    public sealed class Request : IRequest<Result<Response>>
    {
        public Guid UserId { get; set; }
    }
}