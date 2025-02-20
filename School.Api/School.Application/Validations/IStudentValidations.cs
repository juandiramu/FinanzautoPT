namespace School.Application.Validations
{
	public interface IStudentValidations
	{
		Task ValidAsync(string? dni, string? name, string? lastname, string? email, string? phone, int semester);
	}
}
