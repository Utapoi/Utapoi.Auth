namespace Utapoi.Auth.Core.Entities.Common;

/// <summary>
///     Represents an entity that can be audited.
/// </summary>
public class AuditableEntity : Entity
{
    /// <summary>
    ///     Gets or sets the date and time when the entity was created.
    /// </summary>
    public DateTime Created { get; set; }

    /// <summary>
    ///     Gets or sets the identifier of the user who created the entity.
    /// </summary>
    public Guid CreatedBy { get; set; } = Guid.Empty;

    /// <summary>
    ///     Gets or sets the date and time when the entity was last modified.
    /// </summary>
    public DateTime? LastModified { get; set; }

    /// <summary>
    ///     Gets or sets the identifier of the user who last modified the entity.
    /// </summary>
    public Guid LastModifiedBy { get; set; } = Guid.Empty;
}