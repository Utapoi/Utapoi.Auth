using Utapoi.Auth.Core.Entities.Identity;

namespace Utapoi.Auth.Application.Identity;

public interface IUsersService
{
    Task<UtapoiUser?> GetAsync(
        Guid userId,
        CancellationToken cancellationToken = default
    );
}