using Microsoft.AspNetCore.Identity;

namespace Utapoi.Auth.Core.Entities.Identity;

public class UtapoiRole : UtapoiRole<Guid>
{
    public UtapoiRole()
    {
    }

    public UtapoiRole(string role) : base(role)
    {
    }
}

public class UtapoiRole<TKey> : IdentityRole<TKey> where TKey : IEquatable<TKey>
{
    public UtapoiRole()
    {
    }

    public UtapoiRole(string role) : base(role)
    {
    }
}