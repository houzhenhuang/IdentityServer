using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.ViewModels.Scope;

public class EditViewModel : CreateViewModel
{
    /// <summary>
    /// pk
    /// </summary>
    [HiddenInput]
    public string Id { get; set; } = string.Empty;
}