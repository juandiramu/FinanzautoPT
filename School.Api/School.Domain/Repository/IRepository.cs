using School.Domain.Entities;
using System.Linq.Expressions;

namespace School.Domain.Repository
{
	public interface IRepository<T> where T : Entity
	{
		Task<T> CreateAsync(T entity);
		Task<List<T>> GetAllAsync();
		Task<T> GetByIdAsync(Guid id);
		Task<List<T>> GetByFilter(Expression<Func<T, bool>> filter);
		Task<T> UpdateAsync(T entity);
		Task<T> DeleteAsync(T entity);
	}
}
