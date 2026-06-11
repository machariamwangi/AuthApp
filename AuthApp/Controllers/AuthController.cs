using AuthApp.DTOs;
using AuthApp.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthApp.Controllers;

[ApiController]
[Route("auth")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    /// <summary>Register a new user account.</summary>
    [HttpPost("register")]
    [ProducesResponseType(typeof(RegisterResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
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

        var (result, error) = await _authService.RegisterAsync(request);

        if (error is not null)
            return Conflict(new ApiErrorResponse { Error = error });

        return CreatedAtAction(nameof(Register), result);
    }

    /// <summary>Login with existing credentials.</summary>
    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
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

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var (result, error) = await _authService.LoginAsync(request, ipAddress);

        if (error is not null)
            return Unauthorized(new ApiErrorResponse { Error = error });

        return Ok(result);
    }
}
