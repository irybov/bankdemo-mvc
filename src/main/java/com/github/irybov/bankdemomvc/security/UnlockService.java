package com.github.irybov.bankdemomvc.security;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.github.irybov.bankdemomvc.dao.AccountDAO;
import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.jpa.AccountJPA;

@EnableAsync
@Service
public class UnlockService {

	@Autowired
	private AccountJPA jpa;
	@Autowired
	private AccountDAO dao;
	
	private String impl;
	@Autowired
	public void setImpl(@Value("${bean.service-impl}") String impl) {this.impl = impl;}
	public String getImpl() {return this.impl;}
	
    @Autowired
    private TransactionTemplate template;
	
    @Async
	@Scheduled(fixedRate = 1, initialDelay = 1, timeUnit = TimeUnit.MINUTES)
	public void unlock() {    	
		List<Account> locked = null;
		
		template.setReadOnly(true);
		if(impl.equals("JPA")) {
			locked = template.execute(status ->  {
				return jpa.findByIsActiveAndUpdatedAtIsBefore
						(false, OffsetDateTime.now().minusMinutes(1L));
			});
		}
		else if(impl.equals("DAO")) {
			locked = template.execute(status ->  {
				return dao.getByTime(false, OffsetDateTime.now().minusMinutes(1L));
			});
		}
		template.setReadOnly(false);
		
		if(locked.size() > 0) {
			List<Account> accounts = new ArrayList<>(locked);
			
			if(impl.equals("JPA")) {
				accounts.forEach(account -> account.setActive(true));
				template.executeWithoutResult(status -> {jpa.saveAll(accounts);});
			}
			else if(impl.equals("DAO")) {
				template.executeWithoutResult(status -> {dao.batchUpdate(accounts);});
			}
		}
		
	}
	
}
