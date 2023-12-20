using System.ComponentModel.DataAnnotations;

namespace IdentityServer.OpenIddict.ViewModels.Application;

public class CreateViewModel
{
    /// <summary>
    /// 客户端id
    /// </summary>
    [Required(ErrorMessage = "客户端Id不能为空")]
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// 显示名称
    /// </summary>
    [Required(ErrorMessage = "显示名称不能为空")]
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// 重定向url
    /// </summary>
    [Url(ErrorMessage = "{0} 格式不正确")]
    public string? RedirectUris { get; set; }
    
    /// <summary>
    /// 注销重定向url
    /// </summary>
    [Url(ErrorMessage = "{0} 格式不正确")]
    public string PostLogoutRedirectUris { get; set; }

    /// <summary>
    /// 应用程序(客户端)类型
    /// </summary>
    public string? Type { get; set; }

    /// <summary>
    /// 同意类型
    /// </summary>
    public string? ConsentType { get; set; }

    /// <summary>
    /// 客户端密钥
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// scope 列表
    /// </summary>
    public List<ScopeEntry> ScopeEntries { get; } = new();

    /// <summary>
    /// 角色 列表
    /// </summary>
    public List<RoleEntry> RoleEntries { get; } = new();

    /// <summary>
    /// 允许密码流程
    /// </summary>
    public bool AllowPasswordFlow { get; set; }

    /// <summary>
    /// 允许客户端凭据流程
    /// </summary>
    public bool AllowClientCredentialsFlow { get; set; }

    /// <summary>
    /// 允许授权码流程
    /// </summary>
    public bool AllowAuthorizationCodeFlow { get; set; }

    /// <summary>
    /// 允许刷新token流程
    /// </summary>
    public bool AllowRefreshTokenFlow { get; set; }

    /// <summary>
    /// 允许混合流程
    /// </summary>
    public bool AllowHybridFlow { get; set; }

    /// <summary>
    /// 允许隐式流程
    /// </summary>
    public bool AllowImplicitFlow { get; set; }

    /// <summary>
    /// 允许登出端点
    /// </summary>
    public bool AllowLogoutEndpoint { get; set; }

    /// <summary>
    /// 允许内省端点
    /// </summary>
    public bool AllowIntrospectionEndpoint { get; set; }

    /// <summary>
    /// 允许撤销端点
    /// </summary>
    public bool AllowRevocationEndpoint { get; set; }

    /// <summary>
    /// 需要PKCE
    /// </summary>
    public bool RequireProofKeyForCodeExchange { get; set; }

    /// <summary>
    /// scope 条目
    /// </summary>
    public class ScopeEntry
    {
        public string Name { get; set; }
        public bool Selected { get; set; }
    }

    /// <summary>
    /// 角色 条目
    /// </summary>
    public class RoleEntry
    {
        public string Name { get; set; }
        public bool Selected { get; set; }
    }
}