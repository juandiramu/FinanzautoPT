using School.Application.Dtos;
using School.Application.Validations;
using School.Domain.Entities;
using School.Domain.Repository;

namespace School.Application.Services.Impl
{
    public class StudentServices(IRepository<Student> repository, IStudentValidations studentValidations) : IStudentServices
    {
        private readonly IRepository<Student> _repository = repository;
		private readonly IStudentValidations _studentValidations = studentValidations;

        public async Task<List<Student>> GetAllStudents(int page, int size)
        {
			List<Student> students = await _repository.GetAllAsync();
			if(page > 0 && size > 0)
				return students.Skip((page - 1) * size).Take(size).ToList();
			return students;
        }
        public async Task<Student> CreateStudent(CreateStudentDto studentDto)
        {
			await _studentValidations.ValidAsync(studentDto.DNI, studentDto.Name, studentDto.LastName, studentDto.Email,
				studentDto.Phone, studentDto.Semester);
			Student newStudent = new(studentDto.DNI, studentDto.Name, studentDto.LastName, studentDto.Email,
                studentDto.Phone, studentDto.Semester, studentDto.State );
            return await _repository.CreateAsync(newStudent);
        }

		public async Task<Student> EditStudent(EditStudentDto studentDto)
		{
			Student editstudentStudent = await _repository.GetByIdAsync(studentDto.Id) ?? throw new Exception("No se encontró el estudiante");

			await _studentValidations.ValidAsync(studentDto.DNI, studentDto.Name, studentDto.LastName, studentDto.Email,
				studentDto.Phone, studentDto.Semester);

			editstudentStudent.EditStudent(studentDto.DNI, studentDto.Name, studentDto.LastName, studentDto.Email,
				studentDto.Phone, studentDto.Semester, studentDto.State);

			return await _repository.UpdateAsync(editstudentStudent);
		}

		public async Task<Student> DeleteStudent(Guid id)
		{
			Student teacher = await _repository.GetByIdAsync(id);
            return await _repository.DeleteAsync(teacher);
		}

		public async Task<List<Student>> GetByFilter(Guid? id,string? DNI, string? name, string? email)
		{
			return await _repository.GetByFilter(it => it.Id == id || it.Name == name || it.Email == email || it.DNI == DNI);
		}

		
	}
}
