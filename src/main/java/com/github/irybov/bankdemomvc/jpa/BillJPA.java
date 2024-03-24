package com.github.irybov.bankdemomvc.jpa;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.jpa.repository.Query;
//import org.springframework.data.repository.CrudRepository;

import com.github.irybov.bankdemomvc.entity.Bill;

public interface BillJPA extends JpaRepository<Bill, Integer> {

//	@Query("SELECT b FROM Bill b WHERE b.owner.id=:id")
//	List<Bill> getAll(int id);
	
	List<Bill> findByOwnerId(int id);
}
