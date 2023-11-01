package com.github.irybov.bankdemossr.repository;

import java.util.List;

//import org.springframework.data.domain.Page;
//import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
//import org.springframework.data.jpa.repository.Query;

import com.github.irybov.bankdemossr.entity.Operation;

public interface OperationRepository extends JpaRepository<Operation, Long>,
	JpaSpecificationExecutor<Operation> {

	List<Operation> findBySenderOrRecipientOrderByIdDesc(int sender, int recipient);
//	Page<Operation> findBySenderOrRecipient(int sender, int recipient, Pageable pageable);
	
/*	@Query("FROM Operation o WHERE o.action LIKE %:action% AND "
			+ "(o.sender=:id OR o.recipient=:id)")
	Page<Operation> findByActionLikeAndSenderOrRecipient
	(String action, int id, Pageable pageable);*/
	
}
