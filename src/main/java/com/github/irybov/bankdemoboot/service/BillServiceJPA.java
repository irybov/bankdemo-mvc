package com.github.irybov.bankdemoboot.service;

import java.math.BigDecimal;

import javax.persistence.EntityNotFoundException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.github.irybov.bankdemoboot.controller.dto.BillResponseDTO;
import com.github.irybov.bankdemoboot.entity.Bill;
import com.github.irybov.bankdemoboot.exception.PaymentException;
import com.github.irybov.bankdemoboot.repository.BillRepository;

@Service
@Transactional
public class BillServiceJPA implements BillService {
	
	@Autowired
	BillServiceJPA billService;
	@Autowired
	private BillRepository billRepository;
	
	@Transactional(propagation = Propagation.MANDATORY)
	public void saveBill(Bill bill) {
		billRepository.save(bill);
	}
	
	public void updateBill(Bill bill) {
		billRepository.save(bill);
	}
	
	public void deleteBill(int id) {
		billRepository.deleteById(id);
	}
	
	@Transactional(propagation = Propagation.MANDATORY)
	Bill getBill(int id) throws EntityNotFoundException {
		return billRepository.findById(id).orElseThrow
				(()-> new EntityNotFoundException("Target bill with id: " + id + " not found"));
	}
	@Transactional(readOnly = true)
	public BillResponseDTO getBillDTO(int id) throws EntityNotFoundException {
		return new BillResponseDTO(getBill(id));
	}
	
	public String deposit(int id, double amount) throws Exception {
		
		if(amount < 0.01) {
			throw new PaymentException("Amount of money should be higher than zero");
		}		
		
		Bill bill = billService.getBill(id);
		bill.setBalance(bill.getBalance().add(BigDecimal.valueOf(amount)));
		billService.updateBill(bill);
		return bill.getCurrency();
	}
	
	public String withdraw(int id, double amount) throws Exception {
		
		if(amount < 0.01) {
			throw new PaymentException("Amount of money should be higher than zero");
		}
		
		Bill bill = billService.getBill(id);
		if(bill.getBalance().compareTo(BigDecimal.valueOf(amount)) == -1) {
			throw new PaymentException("Not enough money to complete operation");
		}
		bill.setBalance(bill.getBalance().subtract(BigDecimal.valueOf(amount)));
		billService.updateBill(bill);
		return bill.getCurrency();
	}
	
	public String transfer(int from, double amount, int to) throws Exception {

		if(amount < 0.01) {
			throw new PaymentException("Amount of money should be higher than zero");
		}
		
		if(from == to) {
			throw new PaymentException("Source and target bills should not be the same");
		}		
		Bill target = billService.getBill(to);
/*		if(target == null) {
			throw new PaymentException("Target bill with id: " + to + " not found");
		}*/
		
		Bill bill = billService.getBill(from);
		if(!bill.getCurrency().equals(target.getCurrency())){
			throw new PaymentException("Wrong currency type of the target bill");
		}		
		if(bill.getBalance().compareTo(BigDecimal.valueOf(amount)) == -1) {
			throw new PaymentException("Not enough money to complete the operation");
		}
		
		billService.withdraw(from, amount);
		billService.deposit(to, amount);
		return bill.getCurrency();
	}
	
	public boolean changeStatus(int id) throws EntityNotFoundException {
		
		Bill bill = billService.getBill(id);
		if(bill.isActive()) {
			bill.setActive(false);
		}
		else {
			bill.setActive(true);
		}
		billService.updateBill(bill);
		return bill.isActive();
	}
	
}
