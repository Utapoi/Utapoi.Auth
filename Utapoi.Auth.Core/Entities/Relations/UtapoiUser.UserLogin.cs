using System.ComponentModel.DataAnnotations.Schema;
using Utapoi.Auth.Core.Entities.Identity;

namespace Utapoi.Auth.Core.Entities.Relations;

public class UtapoiUserUserLogin
{
    public UtapoiUser? User { get; set; }

    [ForeignKey(nameof(User))]
    public Guid UserId { get; set; }

    public UtapoiUserLogin? UserLogin { get; set; }

    [ForeignKey(nameof(UserLogin))]
    public Guid UserLoginId { get; set; }
}