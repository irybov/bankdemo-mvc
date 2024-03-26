package com.github.irybov.bankdemomvc.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import com.github.irybov.bankdemomvc.service.OperationService;

@Component
public class OperationListener {
	
	@Autowired
	@Qualifier("operationServiceAlias")
	private OperationService operationService;
	
	@TransactionalEventListener(phase = TransactionPhase.BEFORE_COMMIT)
	public void handle(OperationEvent event) {
		operationService.save(event.getOperation());
	}

}
