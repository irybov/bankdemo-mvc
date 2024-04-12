package com.github.irybov.bankdemomvc.dao;

import java.time.OffsetDateTime;
import java.util.List;

import javax.persistence.EntityManager;

import org.hibernate.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.github.irybov.bankdemomvc.entity.Login;
import com.github.irybov.bankdemomvc.entity.LoginFailure;
import com.github.irybov.bankdemomvc.entity.LoginSuccess;

@Repository
public class LoginDAO {
	
	@Autowired
	private EntityManager entityManager;
	
	public Login saveLogin(Login login) {
		Long id = (Long) entityManager.unwrap(Session.class).save(login);
		if(login instanceof LoginSuccess) return null;
		return entityManager.find(LoginFailure.class, id);
	}

	public List<Login> getByTime(int id, OffsetDateTime createdAt) {
		return entityManager.createQuery
	("SELECT l FROM Login l WHERE l.account.id=:id AND l.createdAt>:createdAt AND l.event='failure'",
						Login.class)
				.setParameter("id", id)
				.setParameter("createdAt", createdAt)
				.getResultList();
	}
	
}
