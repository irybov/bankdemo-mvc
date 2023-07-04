package com.github.irybov.bankdemoboot.service;

import java.time.OffsetDateTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.github.irybov.bankdemoboot.controller.dto.OperationResponse;
import com.github.irybov.bankdemoboot.entity.Operation;
//import com.github.irybov.bankdemoboot.model.OperationPage;

public interface OperationService {

	public default Operation transfer(double amount, String action, String currency, int sender, 
			int recipient, String bank) {
		return Operation.builder()
				.amount(amount)
				.action(action)
				.currency(currency)
				.sender(sender)
				.recipient(recipient)
				.createdAt(OffsetDateTime.now())
				.bank(bank)
				.build();
	};
	public default Operation deposit(double amount, String action, String currency, int recipient, 
			String bank) {
		return Operation.builder()
				.amount(amount)
				.action(action)
				.currency(currency)
				.recipient(recipient)
				.createdAt(OffsetDateTime.now())
				.bank(bank)
				.build();
	};
	public default Operation withdraw(double amount, String action, String currency, int sender, 
			String bank) {
		return Operation.builder()
				.amount(amount)
				.action(action)
				.currency(currency)
				.sender(sender)
				.createdAt(OffsetDateTime.now())
				.bank(bank)
				.build();
	};
	public Operation getOne(long id);
	public List<OperationResponse> getAll(int id);
//	public Page<OperationResponseDTO> getPage(int id, OperationPage page);
	public Page<OperationResponse> getPage(int id, String action, double minval, double maxval,
			OffsetDateTime mindate, OffsetDateTime maxdate, Pageable pageable);
}
