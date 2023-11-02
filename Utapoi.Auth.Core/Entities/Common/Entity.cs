using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Utapoi.Auth.Core.Entities.Common;

public abstract class Entity
{
    /// <summary>
    ///     Gets or sets the identifier.
    /// </summary>
    [Key, Column("_id")]
    public Guid Id { get; set; } = Guid.NewGuid();
}