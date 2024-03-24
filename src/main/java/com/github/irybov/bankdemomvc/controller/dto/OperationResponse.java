package com.github.irybov.bankdemomvc.controller.dto;

import java.time.OffsetDateTime;

//import com.github.irybov.bankdemoboot.entity.Operation;

import io.swagger.annotations.ApiModel;
import lombok.Getter;
import lombok.Setter;

@ApiModel
@Getter
@Setter
public class OperationResponse {

//	private Long id;
	private OffsetDateTime createdAt;
	private Double amount;
	private String action;
	private String currency;	
	private Integer sender;		
	private Integer recipient;
	private String bank;
	
/*	public OperationResponse(Operation operation) {
		
//		this.id = operation.getId();
		this.createdAt = operation.getCreatedAt();
		this.amount = operation.getAmount();
		this.action = operation.getAction();
		this.currency = operation.getCurrency();
		this.sender = operation.getSender();
		this.recipient = operation.getRecipient();
		this.bank = operation.getBank();
	}*/
	
}
