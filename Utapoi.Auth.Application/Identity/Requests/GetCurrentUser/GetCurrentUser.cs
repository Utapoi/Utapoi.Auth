using FluentResults;
using MediatR;
using Utapoi.Auth.Application.Common.Errors;

namespace Utapoi.Auth.Application.Identity.Requests.GetCurrentUser;

public static partial class GetCurrentUser
{
    internal sealed class Handler : IRequestHandler<Request, Result<Response>>
    {
        private readonly IUsersService _usersService;

        public Handler(IUsersService usersService)
        {
            _usersService = usersService;
        }

        public async Task<Result<Response>> Handle(Request request, CancellationToken cancellationToken)
        {
            var result = await _usersService.GetAsync(request.UserId, cancellationToken);

            if (result is null)
            {
                return Result.Fail(new EntityNotFoundError());
            }

            return Result.Ok(new Response
            {
                Id = result.Id,
                Username = result.UserName ?? result.Email ?? string.Empty,
                Roles = result.Roles.Select(x => x.Name!).ToList()
            });
        }
    }
}