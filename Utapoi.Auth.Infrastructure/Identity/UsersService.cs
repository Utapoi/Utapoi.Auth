using Microsoft.EntityFrameworkCore;
using Utapoi.Auth.Application.Identity;
using Utapoi.Auth.Core.Entities.Identity;
using Utapoi.Auth.Infrastructure.Persistence;

namespace Utapoi.Auth.Infrastructure.Identity;

internal sealed class UsersService : IUsersService
{
    private readonly UtapoiDbContext _context;

    public UsersService(UtapoiDbContext context)
    {
        _context = context;
    }

    public Task<UtapoiUser?> GetAsync(
        Guid userId,
        CancellationToken cancellationToken = default
    )
    {
        return _context
            .Users
            .FirstOrDefaultAsync(x => x.Id == userId, cancellationToken);
    }
}