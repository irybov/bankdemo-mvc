package com.github.irybov.bankdemomvc.service;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.persistence.NoResultException;
import javax.persistence.PersistenceException;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.github.irybov.bankdemomvc.controller.dto.AccountRequest;
import com.github.irybov.bankdemomvc.controller.dto.AccountResponse;
import com.github.irybov.bankdemomvc.controller.dto.BillResponse;
import com.github.irybov.bankdemomvc.dao.AccountDAO;
import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.entity.Bill;
import com.github.irybov.bankdemomvc.exception.RegistrationException;
import com.github.irybov.bankdemomvc.security.Role;

@Service
@Transactional
public class AccountServiceDAO implements AccountService {

	@Autowired
	private ModelMapper modelMapper;
//	@Autowired
//	AccountServiceDAO accountService;
	@Autowired
	private AccountDAO accountDAO;
	
	@Autowired
	@Qualifier("billServiceAlias")
	private BillService billService;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	public void saveAccount(AccountRequest accountRequest) throws RuntimeException {
		
//		LocalDate birthday = LocalDate.parse(accountRequestDTO.getBirthday());
		if (accountRequest.getBirthday().until(LocalDate.now(), ChronoUnit.YEARS) < 18) {
			throw new RegistrationException("You must be 18+ to register");
		}
		
		Account account = modelMapper.map(accountRequest, Account.class);
		bCryptPasswordEncoder.encode(accountRequest.getPassword());
		account.addRole(Role.CLIENT);
		
		try {
			accountDAO.saveAccount(account);
		}
		catch (RuntimeException exc) {
			throw new PersistenceException(exc.getMessage());
		}
	}
	
	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	public AccountResponse getFullDTO(String phone) throws NoResultException {
		Account account = accountDAO.getWithBills(phone);
		if(account == null) {
			throw new NoResultException("Account with phone " + phone + " not found");
		}
		AccountResponse dto = modelMapper.map(account, AccountResponse.class);
/*		dto.setBills(account.getBills().stream()
				.map(source -> modelMapper.map(source, BillResponse.class))
				.collect(Collectors.toList()));*/
		return dto;
	}
	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	public AccountResponse getAccountDTO(String phone) throws NoResultException {
		return modelMapper.map(getAccount(phone), AccountResponse.class);
	}
//	@Transactional(propagation = Propagation.MANDATORY, readOnly = true)
	Account getAccount(String phone) throws NoResultException {
		Account account = accountDAO.getAccount(phone);
		if(account == null) {
			throw new NoResultException("Account with phone " + phone + " not found");
		}
		return account;
	}
/*	@Transactional(readOnly = true)
	public AccountResponseDTO getById(int id) {
		return new AccountResponseDTO(accountDAO.getById(id));
	}*/
	@Transactional(propagation = Propagation.MANDATORY)
	void updateAccount(Account account) {
		accountDAO.updateAccount(account);
	}
	
	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	public boolean verifyAccount(String phone, String current) throws NoResultException{
		if(getAccount(phone).getPhone() == null || !phone.equals(current)) {
			return false;
		}
		return true;
	}
	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	public Optional<String> getPhone(String phone){
		return accountDAO.getPhone(phone);
	}
/*	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	public List<BillResponse> getBills(int id) {
//		List<Bill> bills = accountDAO.getById(id).getBills();
//		return bills.stream().map(BillResponseDTO::new).collect(Collectors.toList());
		return billService.getAll(id);
	}*/
	
	public BillResponse addBill(String phone, String currency) throws RuntimeException {
		Account account = getAccount(phone);
		Bill bill = new Bill(currency, true, account);
		billService.saveBill(bill);
		account.addBill(bill);
		updateAccount(account);
		return modelMapper.map(bill, BillResponse.class);
	}
	
/*	public void changeStatus(String phone) throws Exception {
		
		Account account = accountService.getAccount(phone);
		if(account.isActive()) {
			account.setActive(false);
		}
		else {
			account.setActive(true);
		}
		accountService.updateAccount(account);
	}*/
	
	public void changePassword(String phone, String password) throws NoResultException {
		Account account = getAccount(phone);
		account.setPassword(bCryptPasswordEncoder.encode(password));
		updateAccount(account);
	}
	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	public boolean comparePassword(String oldPassword, String phone) throws NoResultException {
		Account account = getAccount(phone);
		return bCryptPasswordEncoder.matches(oldPassword, account.getPassword());
	}

	public Boolean changeStatus(int id) {
		
		Account account = accountDAO.getById(id);
		if(account.isActive()) {
			account.setActive(false);
		}
		else {
			account.setActive(true);
		}
		updateAccount(account);
		return account.isActive();
	}

	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	public List<AccountResponse> getAll() {
		return accountDAO.getAll()
				.stream()
//				.sorted((a1, a2) -> a1.getId() - a2.getId())
				.map(source -> modelMapper.map(source, AccountResponse.class))
				.collect(Collectors.toList());
	}
	
}
