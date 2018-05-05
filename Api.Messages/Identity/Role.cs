using System.Collections.Generic;

namespace Api.Messages.Identity
{
    public class Role
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string ConcurrencyStamp { get; set; }
        public virtual ICollection<UserRole> UserRoles { get; set; }
    }
}
