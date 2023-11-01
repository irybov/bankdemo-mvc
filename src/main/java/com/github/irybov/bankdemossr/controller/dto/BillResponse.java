package com.github.irybov.bankdemossr.controller.dto;

import java.math.BigDecimal;
import java.time.OffsetDateTime;

import com.fasterxml.jackson.annotation.JsonBackReference;
//import com.github.irybov.bankdemoboot.entity.Bill;

import io.swagger.annotations.ApiModel;
import lombok.Getter;
import lombok.Setter;

@ApiModel
@Getter
@Setter
public class BillResponse {

	private Integer id;
	private OffsetDateTime createdAt;
	private OffsetDateTime updatedAt;
	private boolean active;
	private BigDecimal balance;
	private String currency;
	@JsonBackReference
	private AccountResponse owner;
	
/*	public BillResponse(Bill bill) {
		
		this.id = bill.getId();
		this.createdAt = bill.getCreatedAt();
		this.updatedAt = bill.getUpdatedAt();		
		this.active = bill.isActive();
		this.balance = bill.getBalance();
		this.currency = bill.getCurrency();
		this.owner = new AccountResponse(bill.getOwner());
	}*/
		
}
