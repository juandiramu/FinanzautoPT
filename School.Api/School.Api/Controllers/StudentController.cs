using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using School.Application.Dtos;
using School.Application.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
namespace School.Api.Controllers;

[Route("api/[controller]")]
[ApiController]
public class StudentController(IStudentServices teacherService, IConfiguration config) : ControllerBase
{
	private readonly IStudentServices _teacherService = teacherService;
	private readonly IConfiguration _config = config;


	[HttpGet]
	[Route("GetAll")]
	public async Task<IActionResult> GetAllStudents([FromQuery] int page, [FromQuery] int size)
	{
		var response = await _teacherService.GetAllStudents(page,size);
		return Ok(response);
	}

	[HttpGet]
	[Route("GetByFilter")]
	public async Task<IActionResult> GetByfilterStudents([FromQuery] Guid? id, [FromQuery] string? DNI, [FromQuery] string? name, [FromQuery] string? email)
	{
		var response = await _teacherService.GetByFilter(id,DNI, name, email);
		return Ok(response);
	}

	[HttpPost]
	[Route("Create")]
	public async Task<IActionResult> CreateStudent(CreateStudentDto createTeacherDto)
	{
		var response = await _teacherService.CreateStudent(createTeacherDto);
		return Ok(response);
	}

	[HttpPut]
	[Route("Edit")]
	public async Task<IActionResult> EditStudent(EditStudentDto createTeacherDto)
	{
		var response = await _teacherService.EditStudent(createTeacherDto);
		return Ok(response);
	}

	[HttpDelete]
	[Route("Delete")]
	public async Task<IActionResult> DeleteStudent(Guid id)
	{
		var response = await _teacherService.DeleteStudent(id);
		return Ok(response);
	}


	[HttpPost("login")]
	public IActionResult Login(LoginDTo login)
	{
		if (login.Email== "admin@yourapi.com" && login.Password == "Login1234")
		{
			var jwtSettings = _config.GetSection("JwtSettings");
			var secretKey = Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]);

			var claims = new List<Claim>
	{
		new(ClaimTypes.Email, login.Email),
	};

			var credentials = new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256);
			var token = new JwtSecurityToken(
				issuer: jwtSettings["Issuer"],
				audience: jwtSettings["Audience"],
				claims: claims,
				expires: DateTime.UtcNow.AddMinutes(Convert.ToInt32(jwtSettings["ExpirationInMinutes"])),
				signingCredentials: credentials
			);

			return Ok (new JwtSecurityTokenHandler().WriteToken(token));
		}

		return Unauthorized("Invalid credentials");
	}
}
