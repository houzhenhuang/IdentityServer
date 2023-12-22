using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.ViewModels.Application;

public class EditViewModel : CreateViewModel
{
    /// <summary>
    /// pk
    /// </summary>
    [HiddenInput]
    public string Id { get; set; } = string.Empty;
}