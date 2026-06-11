using AuthApp.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthApp.Data;

public static class DbSeeder
{
    public static async Task SeedAsync(AppDbContext db)
    {
        await db.Database.MigrateAsync();

        if (await db.Users.AnyAsync(u => u.Role == "Admin"))
            return;

        var admin = new User
        {
            Username     = "admin",
            Email        = "admin@authapp.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin123!"),
            Role         = "Admin",
            CreatedAt    = DateTime.UtcNow,
            Message      = "Default admin account."
        };

        db.Users.Add(admin);
        await db.SaveChangesAsync();
    }
}
