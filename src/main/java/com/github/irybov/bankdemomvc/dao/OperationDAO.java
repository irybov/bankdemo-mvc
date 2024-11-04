package com.github.irybov.bankdemomvc.dao;

import java.time.OffsetDateTime;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import com.github.irybov.bankdemomvc.entity.Operation;
import com.github.irybov.bankdemomvc.entity.Operation_;

@Repository
public class OperationDAO {
	
	@Autowired
	private EntityManager entityManager;
	
	public void save(Operation operation) {
		entityManager.persist(operation);
	}
	
	public Operation getById(long id) {
		return entityManager.find(Operation.class, id);
	}
	
	public List<Operation> getAll(int id) {
		return entityManager.createQuery
				("SELECT o FROM Operation o WHERE o.sender=:id OR o.recipient=:id ORDER BY id DESC",
				Operation.class)
				.setParameter("id", id)					
				.getResultList();
	}
	
/*	public Page<Operation> getPage(int id, Pageable pageable){
		
		long count = (long) entityManager.createQuery("SELECT COUNT(o.id) FROM Operation o "
				+ "WHERE o.sender=:id OR o.recipient=:id")
				.setParameter("id", id)
				.getSingleResult();
		
		List<Operation> operations = entityManager.createQuery
				("SELECT o FROM Operation o WHERE o.sender=:id OR o.recipient=:id ORDER BY id DESC",
				Operation.class)
				.setParameter("id", id)
				.setFirstResult(pageable.getPageNumber() * pageable.getPageSize())
				.setMaxResults(pageable.getPageSize())
				.getResultList();
		
		return new PageImpl<>(operations, pageable, count);
	}*/
	
	public Page<Operation> getPage(int id, String action, double minval, double maxval, 
			OffsetDateTime mindate, OffsetDateTime maxdate, Pageable pageable) {
		
		CriteriaBuilder builder = entityManager.getCriteriaBuilder();
		CriteriaQuery<Operation> result = builder.createQuery(Operation.class);
		Root<Operation> root = result.from(Operation.class);
		
		Predicate hasAction = builder.like(root.get(Operation_.ACTION), "%"+action+"%");
		Predicate hasOwner = builder.or(builder.equal(root.get(Operation_.SENDER), id),
							 			builder.equal(root.get(Operation_.RECIPIENT), id));
		Predicate amountBetween = builder.between(root.get(Operation_.AMOUNT), minval, maxval);
		Predicate dateBetween = builder.between(root.get(Operation_.CREATED_AT), mindate, maxdate);
		Predicate query = builder.and(hasAction, hasOwner, amountBetween, dateBetween);
		
		result.where(query);
		result.orderBy(builder.desc(root.get(Operation_.ID)));		
		result.select(root);
		List<Operation> operations = entityManager.createQuery(result).getResultList();
		
//		TypedQuery<Operation> typed = entityManager.createQuery(result);
//		List<Operation> operations = typed.getResultList();
//        typed.setFirstResult(pageable.getPageNumber() * pageable.getPageSize());
//        typed.setMaxResults(pageable.getPageSize());
		
/*		long count = (long) entityManager.createQuery("SELECT COUNT(o.id) FROM Operation o "
				+ "WHERE o.action LIKE :action AND (o.sender=:id OR o.recipient=:id)")
				.setParameter("action", "%"+action+"%")
				.setParameter("id", id)
				.getSingleResult();*/
		
		CriteriaQuery<Long> howMuch = builder.createQuery(Long.class);
		Root<Operation> quantity = howMuch.from(Operation.class);
		howMuch.where(query);
		howMuch.select(builder.count(quantity));
		long count = entityManager.createQuery(howMuch).getSingleResult();
		
/*		List<Operation> operations = entityManager.createQuery
				("SELECT o FROM Operation o WHERE o.action LIKE :action AND "
				+ "(o.sender=:id OR o.recipient=:id) ORDER BY id DESC",
				Operation.class)
				.setParameter("action", "%"+action+"%")
				.setParameter("id", id)
				.setFirstResult(pageable.getPageNumber() * pageable.getPageSize())
				.setMaxResults(pageable.getPageSize())
				.getResultList();*/
		
		return new PageImpl<>(operations, pageable, count);
	}
	
}
