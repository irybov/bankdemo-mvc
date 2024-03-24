package com.github.irybov.bankdemomvc.service;

import java.util.List;
import java.util.Optional;

import javax.persistence.EntityNotFoundException;
import javax.persistence.PersistenceException;

import com.github.irybov.bankdemomvc.controller.dto.AccountRequest;
import com.github.irybov.bankdemomvc.controller.dto.AccountResponse;
import com.github.irybov.bankdemomvc.controller.dto.BillResponse;

public interface AccountService {

	public void saveAccount(AccountRequest accountRequestDTO) throws PersistenceException;
	public AccountResponse getAccountDTO(String phone) throws PersistenceException;
//	public void updateAccount(Account account);
	public boolean verifyAccount(String phone, String current) throws PersistenceException;
	public BillResponse addBill(String phone, String currency) throws PersistenceException;
//	public void changeStatus(String phone) throws Exception;
	public void changePassword(String phone, String password) throws PersistenceException;
	public boolean comparePassword(String oldPassword, String phone) throws PersistenceException;
//	public AccountResponseDTO getById(int id);
	public Boolean changeStatus(int id);
	public Optional<String> getPhone(String phone);
//	public List<BillResponse> getBills(int id);
	public List<AccountResponse> getAll();
	public AccountResponse getFullDTO(String phone) throws PersistenceException;
}
