using Microsoft.AspNetCore.Identity;
using Utapoi.Auth.Core.Entities.Common;
using Utapoi.Auth.Core.Entities.Relations;

namespace Utapoi.Auth.Core.Entities.Identity;

public class UtapoiUserLogin : Entity, IEquatable<UtapoiUserLogin>, IEquatable<UserLoginInfo>
{
    public UtapoiUserLogin()
    {
    }

    public UtapoiUserLogin(string loginProvider, string providerKey)
    {
        LoginProvider = loginProvider;
        ProviderKey = providerKey;
    }

    public UtapoiUserLogin(UserLoginInfo info)
    {
        LoginProvider = info.LoginProvider;
        ProviderKey = info.ProviderKey;
        ProviderDisplayName = info.ProviderDisplayName;
    }

    public string LoginProvider { get; set; } = string.Empty;

    public string ProviderKey { get; set; } = string.Empty;
    
    public string? ProviderDisplayName { get; set; } = string.Empty;

    public IEnumerable<UtapoiUserUserLogin> Users { get; set; } = new List<UtapoiUserUserLogin>();

    public bool Equals(UtapoiUserLogin? other)
    {
        if (ReferenceEquals(other, null))
            return false;

        if (ReferenceEquals(other, this))
            return true;

        return other.LoginProvider.Equals(LoginProvider)
               && other.ProviderKey.Equals(ProviderKey);
    }

    public bool Equals(UserLoginInfo? other)
    {
        if (ReferenceEquals(other, null))
            return false;

        return other.LoginProvider.Equals(LoginProvider)
               && other.ProviderKey.Equals(ProviderKey);
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(obj, null))
            return false;

        if (ReferenceEquals(obj, this))
            return true;

        if (obj.GetType() != GetType())
            return false;

        return Equals(obj as UtapoiUserLogin);
    }

    public override int GetHashCode()
    {
        unchecked
        {
            var hash = GetType().GetHashCode();
            hash = (hash * 397) ^ LoginProvider.GetHashCode();
            hash = (hash * 397) ^ ProviderKey.GetHashCode();

            return hash;
        }
    }
}