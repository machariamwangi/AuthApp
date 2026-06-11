using AuthApp.Data;
using AuthApp.DTOs;
using AuthApp.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthApp.Services;

public interface IAuthService
{
    Task<(RegisterResponse? result, string? error)> RegisterAsync(RegisterRequest request);
    Task<(LoginResponse? result, string? error)>   LoginAsync(LoginRequest request, string? ipAddress);
    Task<ProfileResponse?>                          GetProfileAsync(int userId);
    Task<(bool success, string? error)>             ChangePasswordAsync(int userId, ChangePasswordRequest request);
    Task<(bool success, string? error)>             LogoutAsync(string token);
}

public class AuthService : IAuthService
{
    private readonly AppDbContext _db;
    private readonly IJwtService  _jwt;
    private readonly ITokenBlacklistService _blacklist;
    private readonly IConfiguration _config;

    public AuthService(
        AppDbContext db,
        IJwtService jwt,
        ITokenBlacklistService blacklist,
        IConfiguration config)
    {
        _db         = db;
        _jwt        = jwt;
        _blacklist  = blacklist;
        _config     = config;
    }

    public async Task<(RegisterResponse? result, string? error)> RegisterAsync(RegisterRequest request)
    {
        if (await _db.Users.AnyAsync(u => u.Email == request.Email.ToLower()))
            return (null, "An account with this email already exists.");

        if (await _db.Users.AnyAsync(u => u.Username.ToLower() == request.Username.ToLower()))
            return (null, "This username is already taken.");

        var user = new User
        {
            Username     = request.Username.Trim(),
            Email        = request.Email.ToLower().Trim(),
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            Role         = "User",
            CreatedAt    = DateTime.UtcNow,
            Message      = $"Welcome to the platform, {request.Username.Trim()}! Your account has been created successfully."
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        return (new RegisterResponse
        {
            Id        = user.Id,
            Username  = user.Username,
            Email     = user.Email,
            Role      = user.Role,
            CreatedAt = user.CreatedAt,
            Message   = user.Message
        }, null);
    }

    public async Task<(LoginResponse? result, string? error)> LoginAsync(LoginRequest request, string? ipAddress)
    {
        var maxAttempts   = int.Parse(_config["LoginLockout:MaxFailedAttempts"] ?? "5");
        var lockoutMinutes = int.Parse(_config["LoginLockout:LockoutMinutes"] ?? "15");
        var email = request.Email.ToLower().Trim();

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);

        if (user is not null && user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
            return (null, "Too many failed login attempts. Please try again later.");

        if (user is null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            if (user is not null)
            {
                user.FailedLoginAttempts++;

                if (user.FailedLoginAttempts >= maxAttempts)
                {
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(lockoutMinutes);
                    user.FailedLoginAttempts = 0;
                }

                await _db.SaveChangesAsync();
            }

            return (null, "Invalid email or password.");
        }

        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        await _db.SaveChangesAsync();

        var expiryMinutes = int.Parse(_config["JwtSettings:ExpiryMinutes"] ?? "60");
        var expiresAt     = DateTime.UtcNow.AddMinutes(expiryMinutes);
        var token         = _jwt.GenerateToken(user);

        return (new LoginResponse
        {
            Token     = token,
            TokenType = "Bearer",
            ExpiresAt = expiresAt,
            Username  = user.Username,
            Role      = user.Role,
            Message   = $"Welcome back, {user.Username}! You have logged in successfully."
        }, null);
    }

    public async Task<ProfileResponse?> GetProfileAsync(int userId)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null) return null;

        return new ProfileResponse
        {
            Id        = user.Id,
            Username  = user.Username,
            Email     = user.Email,
            Role      = user.Role,
            CreatedAt = user.CreatedAt,
            Message   = $"Hello, {user.Username}! This is your secure profile. Your account was created on {user.CreatedAt:MMMM dd, yyyy}."
        };
    }

    public async Task<(bool success, string? error)> ChangePasswordAsync(int userId, ChangePasswordRequest request)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null)
            return (false, "User not found.");

        if (!BCrypt.Net.BCrypt.Verify(request.CurrentPassword, user.PasswordHash))
            return (false, "Current password is incorrect.");

        if (BCrypt.Net.BCrypt.Verify(request.NewPassword, user.PasswordHash))
            return (false, "New password must be different from your current password.");

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
        await _db.SaveChangesAsync();

        return (true, null);
    }

    public async Task<(bool success, string? error)> LogoutAsync(string token)
    {
        var (jti, expiresAt) = _jwt.GetTokenInfo(token);

        if (jti is null || expiresAt is null)
            return (false, "Invalid token.");

        await _blacklist.RevokeAsync(jti, expiresAt.Value);
        return (true, null);
    }
}
