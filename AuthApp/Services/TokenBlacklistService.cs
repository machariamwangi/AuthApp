using AuthApp.Data;
using AuthApp.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthApp.Services;

public interface ITokenBlacklistService
{
    Task<bool> IsRevokedAsync(string jti);
    Task RevokeAsync(string jti, DateTime expiresAt);
}

public class TokenBlacklistService : ITokenBlacklistService
{
    private readonly AppDbContext _db;

    public TokenBlacklistService(AppDbContext db)
    {
        _db = db;
    }

    public async Task<bool> IsRevokedAsync(string jti)
    {
        return await _db.RevokedTokens.AnyAsync(t => t.Jti == jti);
    }

    public async Task RevokeAsync(string jti, DateTime expiresAt)
    {
        if (await _db.RevokedTokens.AnyAsync(t => t.Jti == jti))
            return;

        _db.RevokedTokens.Add(new RevokedToken
        {
            Jti       = jti,
            ExpiresAt = expiresAt,
            RevokedAt = DateTime.UtcNow
        });

        await _db.SaveChangesAsync();
    }
}
