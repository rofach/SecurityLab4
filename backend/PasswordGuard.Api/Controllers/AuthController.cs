using Microsoft.AspNetCore.Mvc;
using PasswordGuard.Api.Models;
using PasswordGuard.Api.Services;

namespace PasswordGuard.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AuthController(IPasswordProtectionService protectionService) : ControllerBase
{
    [HttpPost("register")]
    public ActionResult<AuthOperationResponse> Register([FromBody] RegisterRequest request)
    {
        AuthOperationResponse response = protectionService.Register(request);
        return StatusCode(response.StatusCode, response);
    }

    [HttpPost("login")]
    public ActionResult<AuthOperationResponse> Login([FromBody] LoginRequest request)
    {
        AuthOperationResponse response = protectionService.Login(request);
        return StatusCode(response.StatusCode, response);
    }

    [HttpPost("change-password")]
    public ActionResult<AuthOperationResponse> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        AuthOperationResponse response = protectionService.ChangePassword(request);
        return StatusCode(response.StatusCode, response);
    }

    [HttpPost("reset")]
    public ActionResult<AuthOperationResponse> Reset([FromBody] ResetRequest request)
    {
        AuthOperationResponse response = protectionService.Reset(request);
        return StatusCode(response.StatusCode, response);
    }

    [HttpGet("status/{username}")]
    public ActionResult<AccountStatusResponse> GetStatus(string username)
    {
        AccountStatusResponse? status = protectionService.GetStatus(username);
        if (status is null)
        {
            return NotFound();
        }

        return Ok(status);
    }
}
