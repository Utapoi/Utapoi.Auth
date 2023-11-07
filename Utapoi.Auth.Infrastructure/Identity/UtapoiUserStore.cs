using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MongoDB.Driver.Core.Misc;
using Utapoi.Auth.Core.Entities.Identity;

namespace Utapoi.Auth.Infrastructure.Identity;

public class UtapoiUserStore<TUser, TRole, TContext, TKey> :
    IUserLoginStore<TUser>,
    IUserRoleStore<TUser>,
    IUserClaimStore<TUser>,
    IUserPasswordStore<TUser>,
    IUserSecurityStampStore<TUser>,
    IUserTwoFactorStore<TUser>,
    IUserEmailStore<TUser>,
    IUserLockoutStore<TUser>,
    IUserPhoneNumberStore<TUser>,
    IQueryableUserStore<TUser>,
    IUserAuthenticatorKeyStore<TUser>,
    IUserTwoFactorRecoveryCodeStore<TUser>
    where TUser : UtapoiUser<TKey>, new()
    where TRole : UtapoiRole<TKey>, new()
    where TContext : IdentityDbContext<TUser, TRole, TKey>
    where TKey : IEquatable<TKey>
{
    private TContext Context { get; init; }

    public IQueryable<TUser> Users { get; }

    public UtapoiUserStore(TContext context)
    {
        Context = context;
        Users = context.Set<TUser>();
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        Context.Dispose();
    }

    public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.Id.ToString())!;
    }

    public Task<string?> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.UserName);
    }

    public Task SetUserNameAsync(TUser user, string? userName, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetUserName(userName);

        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.NormalizedUserName);
    }

    public Task SetNormalizedUserNameAsync(TUser user, string? normalizedName, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetNormalizedUserName(normalizedName);

        return Task.CompletedTask;
    }

    public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        Context.Users.Add(user);
        await Context.SaveChangesAsync(cancellationToken);

        return IdentityResult.Success;
    }

    public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        Context.Users.Update(user);
        await Context.SaveChangesAsync(cancellationToken);

        return IdentityResult.Success;
    }

    public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        Context.Users.Remove(user);
        await Context.SaveChangesAsync(cancellationToken);

        return IdentityResult.Success;
    }

    public Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNullOrEmpty(userId, nameof(userId));

        cancellationToken.ThrowIfCancellationRequested();

        return Users.FirstOrDefaultAsync(u => u.Id.ToString() == userId, cancellationToken);
    }

    public Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNullOrEmpty(normalizedUserName, nameof(normalizedUserName));

        cancellationToken.ThrowIfCancellationRequested();

        return Users.FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedUserName, cancellationToken);
    }

    public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));
        Ensure.IsNotNull(login, nameof(login));

        cancellationToken.ThrowIfCancellationRequested();

        if (user.Logins.Any(x => x.Equals(login)))
        {
            throw new InvalidOperationException("Login already exists.");
        }

        user.AddLogin(login);

        return Task.CompletedTask;
    }

    public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));
        Ensure.IsNotNullOrEmpty(loginProvider, nameof(loginProvider));
        Ensure.IsNotNullOrEmpty(providerKey, nameof(providerKey));

        cancellationToken.ThrowIfCancellationRequested();

        user.RemoveLogin(new UtapoiUserLogin(loginProvider, providerKey));

        return Task.CompletedTask;
    }

    public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult<IList<UserLoginInfo>>(
           user.Logins
              .Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName))
              .ToList()
        );
    }

    public Task<TUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNullOrEmpty(loginProvider, nameof(loginProvider));
        Ensure.IsNotNullOrEmpty(providerKey, nameof(providerKey));

        cancellationToken.ThrowIfCancellationRequested();

        return Users.FirstOrDefaultAsync(u => u.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey), cancellationToken);
    }

    public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult<IList<Claim>>(
            user.Claims
                .Select(c => new Claim(c.Type, c.Value, c.Issuer))
                .ToList()
        );
    }

    public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));
        Ensure.IsNotNull(claims, nameof(claims));

        cancellationToken.ThrowIfCancellationRequested();

        foreach (var claim in claims)
        {
            user.AddClaim(claim);
        }

        return Task.CompletedTask;
    }

    public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));
        Ensure.IsNotNull(claim, nameof(claim));
        Ensure.IsNotNull(newClaim, nameof(newClaim));

        cancellationToken.ThrowIfCancellationRequested();

        user.RemoveClaim(new UtapoiClaim(claim));
        user.AddClaim(newClaim);

        return Task.CompletedTask;
    }

    public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));
        Ensure.IsNotNull(claims, nameof(claims));

        cancellationToken.ThrowIfCancellationRequested();

        foreach (var claim in claims)
        {
            user.RemoveClaim(new UtapoiClaim(claim));
        }

        return Task.CompletedTask;
    }

    public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(claim, nameof(claim));

        cancellationToken.ThrowIfCancellationRequested();

        return await Users
            .Where(u => u.Claims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
            .ToListAsync(cancellationToken);
    }

    public Task SetPasswordHashAsync(TUser user, string? passwordHash, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetPasswordHash(passwordHash);

        return Task.CompletedTask;
    }

    public Task<string?> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.PasswordHash);
    }

    public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(!string.IsNullOrWhiteSpace(user.PasswordHash));
    }

    public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));
        Ensure.IsNotNullOrEmpty(stamp, nameof(stamp));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetSecurityStamp(stamp);

        return Task.CompletedTask;
    }

    public Task<string?> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.SecurityStamp);
    }

    public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetTwoFactorEnabled(enabled);

        return Task.CompletedTask;
    }

    public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.TwoFactorEnabled);
    }

    public Task SetEmailAsync(TUser user, string? email, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetEmail(email);

        return Task.CompletedTask;
    }

    public Task<string?> GetEmailAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.Email);
    }

    public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.EmailConfirmed);
    }

    public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetEmailConfirmed(confirmed);

        return Task.CompletedTask;
    }

    public Task<TUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNullOrEmpty(normalizedEmail, nameof(normalizedEmail));

        cancellationToken.ThrowIfCancellationRequested();

        return Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, cancellationToken);
    }

    public Task<string?> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.NormalizedEmail);
    }

    public Task SetNormalizedEmailAsync(TUser user, string? normalizedEmail, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetNormalizedEmail(normalizedEmail);

        return Task.CompletedTask;
    }

    public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.LockoutEnd);
    }

    public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetLockoutEnd(lockoutEnd);

        return Task.CompletedTask;
    }

    public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.AccessFailedCount += 1;

        return Task.FromResult(user.AccessFailedCount);
    }

    public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.AccessFailedCount = 0;

        return Task.CompletedTask;
    }

    public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.AccessFailedCount);
    }

    public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.LockoutEnabled);
    }

    public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        user.SetLockoutEnabled(enabled);

        return Task.CompletedTask;
    }

    public Task SetPhoneNumberAsync(TUser user, string? phoneNumber, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public Task<string?> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.PhoneNumber);
    }

    public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.PhoneNumberConfirmed);
    }

    public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public Task<string?> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));
        Ensure.IsNotNullOrEmpty(roleName, nameof(roleName));

        cancellationToken.ThrowIfCancellationRequested();

        user.AddRole(new UtapoiRole(roleName));

        return Task.CompletedTask;
    }

    public Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));
        Ensure.IsNotNullOrEmpty(roleName, nameof(roleName));

        cancellationToken.ThrowIfCancellationRequested();

        user.RemoveRole(new UtapoiRole(roleName));

        return Task.CompletedTask;
    }

    public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult<IList<string>>(
           user.Roles
               .Select(r => r.Name ?? string.Empty)
               .Where(r => !string.IsNullOrWhiteSpace(r))
               .ToList()
        );
    }

    public Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNull(user, nameof(user));
        Ensure.IsNotNullOrEmpty(roleName, nameof(roleName));

        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(user.Roles.Any(r => r.Name == roleName));
    }

    public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default)
    {
        Ensure.IsNotNullOrEmpty(roleName, nameof(roleName));

        cancellationToken.ThrowIfCancellationRequested();

        return await Users
            .Where(u => u.Roles.Any(r => r.Name == roleName))
            .ToListAsync(cancellationToken);
    }
}