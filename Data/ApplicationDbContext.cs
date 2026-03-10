using Auth.Server.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth.Server.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Дополнительные индексы для наших полей
        builder.Entity<ApplicationUser>()
            .HasIndex(u => u.TelegramId)
            .IsUnique()
            .HasFilter("\"TelegramId\" IS NOT NULL");

        builder.Entity<ApplicationUser>()
            .HasIndex(u => u.GoogleId)
            .IsUnique()
            .HasFilter("\"GoogleId\" IS NOT NULL");
    }
}
