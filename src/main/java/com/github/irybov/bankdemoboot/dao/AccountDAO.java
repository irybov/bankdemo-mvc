package com.github.irybov.bankdemoboot.dao;

import javax.persistence.EntityManager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.github.irybov.bankdemoboot.entity.Account;

@Repository
public class AccountDAO {

	@Autowired
	private EntityManager entityManager;

	public void saveAccount(Account account) {
		entityManager.persist(account);
	}
	
	public void updateAccount(Account account) {
		entityManager.merge(account);
	}

	public Account getAccount(String phone) {		
		return entityManager.createQuery("SELECT a FROM Account a WHERE a.phone=:phone",
				Account.class)
				.setParameter("phone", phone)
				.getSingleResult();
	}
	
	public String checkPhone(String check) {
		return (String) entityManager.createNativeQuery
				("SELECT phone FROM accounts WHERE phone=:check")
				.setParameter("check", check)
				.getSingleResult();
	}
	
}
