package com.github.irybov.bankdemomvc.util;

import org.springframework.context.ApplicationEvent;

import com.github.irybov.bankdemomvc.entity.Operation;

public class OperationEvent extends ApplicationEvent {
	
	private Operation operation;

	public OperationEvent(Object source, Operation operation) {
		super(source);
		this.operation = operation;
	}
	public Operation getOperation() {return operation;}

}
