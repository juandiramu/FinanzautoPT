using School.Application.Dtos;
using School.Domain.Entities;

namespace School.Application.Services
{
	public interface IStudentServices
	{
		Task<List<Student>> GetAllStudents (int page, int size);
		Task<Student> CreateStudent(CreateStudentDto teacherDto);
		Task<Student> EditStudent(EditStudentDto teacherDto);
		Task<Student> DeleteStudent(Guid id);
		Task<List<Student>> GetByFilter(Guid? id,string? DNI, string? name, string? email);
	}
}
