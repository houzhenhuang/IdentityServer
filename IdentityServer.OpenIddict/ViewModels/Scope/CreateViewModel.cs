using System.ComponentModel.DataAnnotations;

namespace IdentityServer.OpenIddict.ViewModels.Scope;

public class CreateViewModel
{
    /// <summary>
    /// 名称
    /// </summary>
    [Required(ErrorMessage = "名称不能为空")]
    public string Name { get; set; } = string.Empty;
    
    /// <summary>
    /// 显示名称
    /// </summary>
    [Required(ErrorMessage = "显示名称不能为空")]
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// 描述
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// 资源
    /// </summary>
    public string? Resources { get; set; }
}