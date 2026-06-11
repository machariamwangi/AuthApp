using System.Security.Claims;
using AuthApp.DTOs;
using AuthApp.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApp.Controllers;

[ApiController]
[Route("api/admin")]
[Authorize(Roles = "Admin")]
[Produces("application/json")]
public class AdminController : ControllerBase
{
    private readonly IAdminService _adminService;

    public AdminController(IAdminService adminService)
    {
        _adminService = adminService;
    }

    /// <summary>List all registered users (admin only).</summary>
    [HttpGet("users")]
    [ProducesResponseType(typeof(List<AdminUserResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _adminService.GetAllUsersAsync();
        return Ok(users);
    }

    /// <summary>Update a user's role (admin only).</summary>
    [HttpPut("users/{id:int}/role")]
    [ProducesResponseType(typeof(AdminUserResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateUserRole(int id, [FromBody] UpdateUserRoleRequest request)
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

        var adminId = GetCurrentUserId();
        if (adminId is null)
            return Unauthorized(new ApiErrorResponse { Error = "Invalid or missing token claims." });

        var (result, error) = await _adminService.UpdateUserRoleAsync(id, request.Role, adminId.Value);

        if (error is not null)
            return error == "User not found."
                ? NotFound(new ApiErrorResponse { Error = error })
                : BadRequest(new ApiErrorResponse { Error = error });

        return Ok(result);
    }

    /// <summary>Delete a user account (admin only).</summary>
    [HttpDelete("users/{id:int}")]
    [ProducesResponseType(typeof(MessageResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var adminId = GetCurrentUserId();
        if (adminId is null)
            return Unauthorized(new ApiErrorResponse { Error = "Invalid or missing token claims." });

        var (success, error) = await _adminService.DeleteUserAsync(id, adminId.Value);

        if (!success)
            return error == "User not found."
                ? NotFound(new ApiErrorResponse { Error = error! })
                : BadRequest(new ApiErrorResponse { Error = error! });

        return Ok(new MessageResponse { Message = "User account deleted successfully." });
    }

    private int? GetCurrentUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? User.FindFirst("sub")?.Value;

        return userIdClaim is not null && int.TryParse(userIdClaim, out int userId)
            ? userId
            : null;
    }
}
