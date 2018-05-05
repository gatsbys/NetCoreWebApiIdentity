using System.Threading;
using System.Threading.Tasks;

namespace Api.Identity
{
    public interface ILastLoggedIn
    {
        Task UpdateUserLastActivityDateAsync(string userId, CancellationToken cancellationToken);
    }
}
