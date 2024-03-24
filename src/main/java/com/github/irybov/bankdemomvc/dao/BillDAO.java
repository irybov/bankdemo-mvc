package com.github.irybov.bankdemomvc.dao;

import java.util.List;

import javax.persistence.EntityManager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.github.irybov.bankdemomvc.entity.Bill;

@Repository
public class BillDAO {

	@Autowired
	private EntityManager entityManager;
	
	public void saveBill(Bill bill) {		
		entityManager.persist(bill);
	}
	
	public void updateBill(Bill bill) {		
		if(entityManager.contains(bill)) entityManager.merge(bill);
		else saveBill(bill);
	}
	
	public void deleteBill(int id) {	
		Bill bill = getBill(id);
		entityManager.remove(bill);
	}
	
	public Bill getBill(int id) {
		return entityManager.find(Bill.class, id);
	}

/*	public String getPhone(int billId) {
		return (String) entityManager.createNativeQuery
		("SELECT phone FROM {h-schema}accounts WHERE id = "
				+ "(SELECT account_id FROM {h-schema}bills WHERE id=:billId)")
				.setParameter("billId", billId)				
				.getSingleResult();
	}
	
	public String getPhone(int billId) {
		return getBill(billId).getOwner().getPhone();
	}
	
	public List<Integer> getAll(String billCurrency){
		return entityManager.createQuery("SELECT id FROM Bill WHERE currency=:billCurrency",
				Integer.class)
				.setParameter("billCurrency", billCurrency)
				.getResultList();
	}*/
	
	public List<Bill> getAll(){
		return entityManager.createQuery("SELECT b FROM Bill b", Bill.class).getResultList();
	}
	
	public List<Bill> getByOwner(int id){
		return entityManager.createQuery("SELECT b FROM Bill b WHERE b.owner.id=:id", Bill.class)
							.setParameter("id", id)
							.getResultList();
	}
	
}
