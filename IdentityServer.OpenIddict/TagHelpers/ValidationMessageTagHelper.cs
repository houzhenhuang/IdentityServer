using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;

namespace IdentityServer.OpenIddict.TagHelpers;

/// <summary>
/// 请参阅 <see cref="ITagHelper"/> 实现，该实现针对任何具有 <c>asp-validation-for</c> 属性的HTML元素验证。
/// </summary>
[HtmlTargetElement("*", Attributes = ValidationForAttributeName)]
public class ValidationMessageTagHelper : TagHelper
{
    private const string ValidationForAttributeName = "asp-validation-class-for";
    private const string HasValidationErrorClassName = "has-validation-error";
    private readonly IHtmlHelper _htmlHelper;

    public ValidationMessageTagHelper(IHtmlHelper htmlHelper)
    {
        _htmlHelper = htmlHelper;
    }

    /// <inheritdoc />
    public override int Order => -1000;

    [HtmlAttributeNotBound] [ViewContext] public ViewContext ViewContext { get; set; }

    /// <summary>
    /// 要在当前模型上验证的名称。
    /// </summary>
    [HtmlAttributeName(ValidationForAttributeName)]
    public ModelExpression For { get; set; }

    /// <inheritdoc />
    /// <remarks>Does nothing if <see cref="For"/> is <c>null</c>.</remarks>
    public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
    {
        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        if (output == null)
        {
            throw new ArgumentNullException(nameof(output));
        }

        if (For != null)
        {
            //contextualize IHtmlHelper
            var viewContextAware = _htmlHelper as IViewContextAware;
            viewContextAware?.Contextualize(ViewContext);

            var fullName = _htmlHelper.Name(For.Name);

            if (ViewContext.ViewData.ModelState.TryGetValue(fullName, out var entry) && entry.Errors.Count > 0)
            {
                TagHelperAttribute classAttribute;

                if (output.Attributes.TryGetAttribute("class", out classAttribute))
                {
                    output.Attributes.SetAttribute("class", classAttribute.Value + " " + HasValidationErrorClassName);
                }
                else
                {
                    output.Attributes.Add("class", HasValidationErrorClassName);
                }
            }

            // 我们检查空白以检测以下场景：
            // <span validation-for="Name">
            // </span>
            if (!output.IsContentModified)
            {
                var childContent = await output.GetChildContentAsync();
                output.Content.SetHtmlContent(childContent);
            }
        }
    }
}