package com.github.irybov.bankdemossr.security;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.github.irybov.bankdemossr.dao.AccountDAO;
import com.github.irybov.bankdemossr.entity.Account;
import com.github.irybov.bankdemossr.repository.AccountRepository;
import com.github.irybov.bankdemossr.service.AccountService;
import com.github.irybov.bankdemossr.service.AccountServiceDAO;
import com.github.irybov.bankdemossr.service.AccountServiceJPA;

@Service
public class AccountDetailsService implements UserDetailsService {
	
	@Autowired
	private AccountRepository repository;
	@Autowired
	private AccountDAO dao;
/*	@Autowired
	@Qualifier("accountServiceAlias")
	private AccountService accountService;*/
	
//	@Value("${bean.service-impl}")
	private String impl;
/*	public AccountDetailsService(@Value("accountService"+"${bean.service-impl}") String impl) {
		this.impl = impl;
	}*/
	@Autowired
	public void setImpl(@Value("${bean.service-impl}") String impl) {
		this.impl = impl;
	}
		
	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	@Override
	public UserDetails loadUserByUsername(String phone) throws UsernameNotFoundException {
		
//		accountService = (AccountService) context.getBean("accountServiceAlias");
		Account account = null;
		if(impl.equals("JPA")) {
//		if(accountService instanceof AccountServiceJPA) {
			Optional<Account> optional = repository.findByPhone(phone);
			account = optional.orElseThrow(() -> 
					new UsernameNotFoundException("User " + phone + " not found"));			
		}
		else if(impl.equals("DAO")) {
//		else if(accountService instanceof AccountServiceDAO) {
			account = dao.getWithRoles(phone);
			if(account == null) throw new UsernameNotFoundException("User " + phone + " not found");
		}	
		return new AccountDetails(account);
	}
	
}
