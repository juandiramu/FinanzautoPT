using Microsoft.EntityFrameworkCore;
using School.Domain.Repository;
using System.Linq.Expressions;
using System;
using School.Infrastructure.DataAcces;
using School.Domain.Entities;

namespace School.Infrastructure.Repository
{
	public class Repository<T> : IRepository<T> where T : Entity
	{
		private readonly SchoolDbContext _appDbContext;
		private readonly DbSet<T> _dbSet;

		public Repository(SchoolDbContext appDbContext)
		{
			_appDbContext = appDbContext;
			_dbSet = _appDbContext.Set<T>();
		}

		public async Task<T> CreateAsync(T entity)
		{
			entity.Id = Guid.NewGuid();
			entity.CreatedDate = DateTime.Now;
			entity.CreatedBy = "system";
			await _dbSet.AddAsync(entity);
			await _appDbContext.SaveChangesAsync();
			return entity;
		}

		public async Task<T> DeleteAsync(T entity)
		{
			var result = await GetByIdAsync(entity.Id) ?? throw new Exception($"{nameof(T)} Not Found");
			_dbSet.Remove(result);
			await _appDbContext.SaveChangesAsync();
			return result;
		}

		public async Task<T> GetByIdAsync(Guid id)
		{
			return await _dbSet.FindAsync(id) ?? throw new Exception($"{nameof(T)} Not Found");
		}

		public async Task<List<T>> GetByFilter(Expression<Func<T, bool>> filter)
		{
			var entity = await _dbSet.Where(filter).ToListAsync();
			return entity;
		}

		

		public async Task<List<T>> GetAllAsync()
		{
			return await _dbSet.ToListAsync() ?? throw new Exception($"{nameof(T)} List Not Found");
		}

		public async Task<T> UpdateAsync(T entity)
		{
			entity.LastModifiedDate = DateTime.Now;
			entity.LastModifiedBy = "system";
			_dbSet.Update(entity); 
			await _appDbContext.SaveChangesAsync();
			return entity;
		}
	}
}
