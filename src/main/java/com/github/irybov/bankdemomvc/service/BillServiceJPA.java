package com.github.irybov.bankdemomvc.service;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

import javax.persistence.EntityNotFoundException;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.github.irybov.bankdemomvc.controller.dto.BillResponse;
import com.github.irybov.bankdemomvc.entity.Bill;
import com.github.irybov.bankdemomvc.entity.Operation;
import com.github.irybov.bankdemomvc.exception.PaymentException;
import com.github.irybov.bankdemomvc.jpa.BillJPA;
import com.github.irybov.bankdemomvc.jpa.OperationJPA;
import com.github.irybov.bankdemomvc.util.OperationEvent;

@Service
@Transactional
public class BillServiceJPA implements BillService {

	@Autowired
	private ModelMapper modelMapper;
//	@Autowired
//	BillServiceJPA billService;
	@Autowired
	private BillJPA billJPA;
//	@Autowired
//	private OperationJPA operationJPA;
    @Autowired
    private ApplicationEventPublisher publisher;
	
	@Transactional(propagation = Propagation.MANDATORY)
	public void saveBill(Bill bill) {
		billJPA.saveAndFlush(bill);
	}
	
	@Transactional(propagation = Propagation.MANDATORY)
	void updateBill(Bill bill) {
		billJPA.save(bill);
	}
	
	public void deleteBill(int id) {
		billJPA.deleteById(id);
	}
	
	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	public BillResponse getBillDTO(int id) throws EntityNotFoundException {
		return modelMapper.map(getBill(id), BillResponse.class);
	}
//	@Transactional(propagation = Propagation.MANDATORY, readOnly = true, noRollbackFor = Exception.class)
	Bill getBill(int id) throws EntityNotFoundException {
		return billJPA.findById(id).orElseThrow
				(()-> new EntityNotFoundException("Target bill with id: " + id + " not found"));
	}
	
	public void deposit(Operation operation) throws PaymentException {
		
		double amount = operation.getAmount();
		if(amount < 0.01) throw new PaymentException("Amount of money should be higher than zero");

		int id = operation.getRecipient();
		Bill bill = getBill(id);
		bill.setBalance(bill.getBalance().add(BigDecimal.valueOf(amount)));
		updateBill(bill);
//		operationJPA.saveAndFlush(operation);
		publisher.publishEvent(new OperationEvent(this, operation));
	}
	
	public void withdraw(Operation operation) throws PaymentException {
		
		double amount = operation.getAmount();
		if(amount < 0.01) throw new PaymentException("Amount of money should be higher than zero");

		int id = operation.getSender();
		Bill bill = getBill(id);
		if(bill.getBalance().compareTo(BigDecimal.valueOf(amount)) == -1) {
			throw new PaymentException("Not enough money to complete operation");
		}
		bill.setBalance(bill.getBalance().subtract(BigDecimal.valueOf(amount)));
		updateBill(bill);
//		operationJPA.saveAndFlush(operation);
		publisher.publishEvent(new OperationEvent(this, operation));
	}
	
	public void transfer(Operation operation) throws PaymentException {

		double amount = operation.getAmount();
		if(amount < 0.01) throw new PaymentException("Amount of money should be higher than zero");
		
		int from = operation.getSender();
		int to = operation.getRecipient();
		if(from == to) throw new PaymentException("Source and target bills should not be the same");
		Bill target = getBill(to);
/*		if(target == null) {
			throw new PaymentException("Target bill with id: " + to + " not found");
		}*/
		
		Bill sender = getBill(from);
		if(!sender.getCurrency().equals(target.getCurrency())){
			throw new PaymentException("Wrong currency type of the target bill");
		}
		if(sender.getBalance().compareTo(BigDecimal.valueOf(amount)) == -1) {
			throw new PaymentException("Not enough money to complete operation");
		}
		
		target.setBalance(target.getBalance().add(BigDecimal.valueOf(amount)));
		sender.setBalance(sender.getBalance().subtract(BigDecimal.valueOf(amount)));
		updateBill(target);
		updateBill(sender);
//		operationJPA.saveAndFlush(operation);
		publisher.publishEvent(new OperationEvent(this, operation));
	}
	
	public void external(Operation operation) throws PaymentException {
		
		double amount = operation.getAmount();
		if(amount < 0.01) throw new PaymentException("Amount of money should be higher than zero");
		
		int from = operation.getSender();
		int to = operation.getRecipient();
		if(from == to) throw new PaymentException("Source and target bills should not be the same");
		
		Bill target = getBill(to);
		if(!operation.getCurrency().equals(target.getCurrency())){
			throw new PaymentException("Wrong currency type of the target bill");
		}
		target.setBalance(target.getBalance().add(BigDecimal.valueOf(amount)));
		updateBill(target);
//		operationJPA.saveAndFlush(operation);
		publisher.publishEvent(new OperationEvent(this, operation));
	}
	
	public void outward(Operation operation) throws PaymentException {
		
		double amount = operation.getAmount();
		if(amount < 0.01) throw new PaymentException("Amount of money should be higher than zero");
		
		int from = operation.getSender();
		int to = operation.getRecipient();
		if(from == to) throw new PaymentException("Source and target bills should not be the same");
		
		Bill sender = getBill(from);
		if(sender.getBalance().compareTo(BigDecimal.valueOf(amount)) == -1) {
			throw new PaymentException("Not enough money to complete operation");
		}
		sender.setBalance(sender.getBalance().subtract(BigDecimal.valueOf(amount)));
		updateBill(sender);
//		operationJPA.saveAndFlush(operation);
		publisher.publishEvent(new OperationEvent(this, operation));
	}
	
	public boolean changeStatus(int id) {
		
		Bill bill = getBill(id);
		if(bill.isActive()) {
			bill.setActive(false);
		}
		else {
			bill.setActive(true);
		}
		updateBill(bill);
		return bill.isActive();
	}
	
	@Transactional(propagation = Propagation.MANDATORY, readOnly = true, noRollbackFor = Exception.class)
	public List<BillResponse> getAll(int id) {		
//		List<Bill> bills = billRepository.getAll(id);
		List<Bill> bills = billJPA.findByOwnerId(id);
		return bills.stream().map(source -> modelMapper.map(source, BillResponse.class))
					.collect(Collectors.toList());		
	}
	
}
