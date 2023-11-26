using System.ComponentModel.DataAnnotations;

namespace IdentityServer.OpenIddict.ViewModels.Account;

public class LoginViewModel
{
    [Required(ErrorMessage = "用户名不能为空")]
    [Display(Name = "Username")]
    public string UserName { get; set; }

    [Required(ErrorMessage = "密码不能为空")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = "}s>EWG@f4g;_v7nB";

    public bool RememberMe { get; set; }
}