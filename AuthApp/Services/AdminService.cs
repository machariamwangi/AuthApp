using AuthApp.Data;
using AuthApp.DTOs;
using Microsoft.EntityFrameworkCore;

namespace AuthApp.Services;

public interface IAdminService
{
    Task<List<AdminUserResponse>> GetAllUsersAsync();
    Task<(AdminUserResponse? result, string? error)> UpdateUserRoleAsync(int userId, string role, int adminUserId);
    Task<(bool success, string? error)> DeleteUserAsync(int userId, int adminUserId);
}

public class AdminService : IAdminService
{
    private readonly AppDbContext _db;

    public AdminService(AppDbContext db)
    {
        _db = db;
    }

    public async Task<List<AdminUserResponse>> GetAllUsersAsync()
    {
        return await _db.Users
            .OrderBy(u => u.Id)
            .Select(u => new AdminUserResponse
            {
                Id        = u.Id,
                Username  = u.Username,
                Email     = u.Email,
                Role      = u.Role,
                CreatedAt = u.CreatedAt
            })
            .ToListAsync();
    }

    public async Task<(AdminUserResponse? result, string? error)> UpdateUserRoleAsync(
        int userId, string role, int adminUserId)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null)
            return (null, "User not found.");

        if (user.Id == adminUserId && role != "Admin")
            return (null, "You cannot remove your own admin role.");

        user.Role = role;
        await _db.SaveChangesAsync();

        return (new AdminUserResponse
        {
            Id        = user.Id,
            Username  = user.Username,
            Email     = user.Email,
            Role      = user.Role,
            CreatedAt = user.CreatedAt
        }, null);
    }

    public async Task<(bool success, string? error)> DeleteUserAsync(int userId, int adminUserId)
    {
        if (userId == adminUserId)
            return (false, "You cannot delete your own account.");

        var user = await _db.Users.FindAsync(userId);
        if (user is null)
            return (false, "User not found.");

        _db.Users.Remove(user);
        await _db.SaveChangesAsync();

        return (true, null);
    }
}
