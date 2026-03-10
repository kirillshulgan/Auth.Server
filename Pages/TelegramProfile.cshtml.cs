using Auth.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Auth.Server.Pages;

[Authorize]
public class TelegramProfileModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;

    public ApplicationUser? AppUser { get; set; }

    public TelegramProfileModel(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task OnGetAsync()
    {
        AppUser = await _userManager.GetUserAsync(User);
    }
}

