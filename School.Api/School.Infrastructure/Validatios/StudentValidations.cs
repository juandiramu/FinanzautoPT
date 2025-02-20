using FluentValidation;
using School.Application.Validations;

namespace School.Infrastructure.Validations;

public class StudentValidations : IStudentValidations
{
	private readonly IValidator<StudentValidationRequest> _validator;

	public StudentValidations()
	{
		_validator = new StudentValidator(); 
	}

	public async Task ValidAsync(string? dni, string? name, string? lastname, string? email, string? phone, int semester)
	{
		var student = new StudentValidationRequest
		{
			DNI = dni,
			Name = name,
			LastName = lastname,
			Email = email,
			Phone = phone,
			Semester = semester
		};

		var validationResult = await _validator.ValidateAsync(student); 

		if (!validationResult.IsValid)
		{
			throw new ValidationException(validationResult.Errors);
		}
	}
}

public class StudentValidator : AbstractValidator<StudentValidationRequest>
{
	public StudentValidator()
	{
		RuleFor(student => student.DNI)
			.NotEmpty().WithMessage("El DNI es obligatorio.")
			.Matches(@"^\d{7,10}$").WithMessage("El DNI debe tener entre 7 y 10 dígitos numéricos.");

		RuleFor(student => student.Name)
			.NotEmpty().WithMessage("El nombre es obligatorio.")
			.MaximumLength(50).WithMessage("El nombre no puede tener más de 50 caracteres.");

		RuleFor(student => student.LastName)
			.NotEmpty().WithMessage("El apellido es obligatorio.")
			.MaximumLength(50).WithMessage("El apellido no puede tener más de 50 caracteres.");

		RuleFor(student => student.Email)
			.NotEmpty().WithMessage("El email es obligatorio.")
			.EmailAddress().WithMessage("El email no tiene un formato válido.");

		RuleFor(student => student.Phone)
			.NotEmpty().WithMessage("El teléfono es obligatorio.")
			.Matches(@"^\d{10}$").WithMessage("El teléfono debe tener exactamente 10 dígitos.");

		RuleFor(student => student.Semester)
			.GreaterThan(0).WithMessage("El semestre debe ser mayor a 0.")
			.LessThanOrEqualTo(10).WithMessage("El semestre no puede ser mayor a 10.");
	}
}

// 🔹 DTO de Validación dentro del mismo archivo
public class StudentValidationRequest
{
	public string? DNI { get; set; }
	public string? Name { get; set; }
	public string? LastName { get; set; }
	public string? Email { get; set; }
	public string? Phone { get; set; }
	public int Semester { get; set; }
}
