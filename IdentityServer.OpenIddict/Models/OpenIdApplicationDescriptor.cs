using OpenIddict.Abstractions;

namespace IdentityServer.OpenIddict.Models;

public class OpenIdApplicationDescriptor : OpenIddictApplicationDescriptor
{
    /// <summary>
    /// 获取与应用程序关联的角色。
    /// </summary>
    public ISet<string> Roles { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}