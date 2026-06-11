using System.Security.Claims;
using AuthApp.DTOs;
using AuthApp.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApp.Controllers;

[ApiController]
[Route("api")]
[Produces("application/json")]
public class ProfileController : ControllerBase
{
    private readonly IAuthService _authService;

    public ProfileController(IAuthService authService)
    {
        _authService = authService;
    }

    /// <summary>Get the currently authenticated user's profile.</summary>
    [HttpGet("profile")]
    [Authorize]
    [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetProfile()
    {
        var userId = GetCurrentUserId();
        if (userId is null)
            return Unauthorized(new ApiErrorResponse { Error = "Invalid or missing token claims." });

        var profile = await _authService.GetProfileAsync(userId.Value);

        if (profile is null)
            return NotFound(new ApiErrorResponse { Error = "User not found." });

        return Ok(profile);
    }

    /// <summary>Change the currently authenticated user's password.</summary>
    [HttpPut("change-password")]
    [Authorize]
    [ProducesResponseType(typeof(MessageResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState.Values
                .SelectMany(v => v.Errors)
                .Select(e => e.ErrorMessage)
                .ToList();

            return BadRequest(new ApiErrorResponse
            {
                Error   = "Validation failed.",
                Details = errors
            });
        }

        var userId = GetCurrentUserId();
        if (userId is null)
            return Unauthorized(new ApiErrorResponse { Error = "Invalid or missing token claims." });

        var (success, error) = await _authService.ChangePasswordAsync(userId.Value, request);

        if (!success)
            return BadRequest(new ApiErrorResponse { Error = error! });

        return Ok(new MessageResponse { Message = "Password changed successfully." });
    }

    /// <summary>Logout and invalidate the current JWT token.</summary>
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(typeof(MessageResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Logout()
    {
        var token = ExtractBearerToken();
        if (token is null)
            return Unauthorized(new ApiErrorResponse { Error = "Bearer token is required." });

        var (success, error) = await _authService.LogoutAsync(token);

        if (!success)
            return BadRequest(new ApiErrorResponse { Error = error! });

        return Ok(new MessageResponse { Message = "You have been logged out successfully. Your token is no longer valid." });
    }

    private int? GetCurrentUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? User.FindFirst("sub")?.Value;

        return userIdClaim is not null && int.TryParse(userIdClaim, out int userId)
            ? userId
            : null;
    }

    private string? ExtractBearerToken()
    {
        var authHeader = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;

        return authHeader["Bearer ".Length..].Trim();
    }
}
