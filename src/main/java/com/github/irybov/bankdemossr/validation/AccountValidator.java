package com.github.irybov.bankdemossr.validation;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;

import com.github.irybov.bankdemossr.controller.dto.AccountRequest;
import com.github.irybov.bankdemossr.service.AccountService;

@Component
public class AccountValidator implements org.springframework.validation.Validator {
	
    @Autowired
    private Validator validator;
    
	@Autowired
	@Qualifier("accountServiceAlias")
	private AccountService accountService;

/*	private final AccountService accountService;
	public AccountValidator(@Qualifier("accountServiceAlias")AccountService accountService) {
		this.accountService = accountService;
	}*/

	@Override
	public boolean supports(Class<?> clazz) {
		return AccountRequest.class.equals(clazz);
	}

	@Override
	public void validate(Object target, Errors errors) {
		
	    Set<ConstraintViolation<Object>> violations = validator.validate(target);
	    for (ConstraintViolation<Object> violation : violations) {
	        String propertyPath = violation.getPropertyPath().toString();
	        String message = violation.getMessage();
	        errors.rejectValue(propertyPath, "", message);
	    }
		
		AccountRequest account = (AccountRequest) target;
		if(account.getBirthday().until(LocalDate.now(), ChronoUnit.YEARS) < 18) {
			errors.rejectValue("birthday", "", "Validator in action!");
		}
		if(!accountService.getPhone(account.getPhone()).isPresent()) return;
			errors.rejectValue("phone", "", "Validator in action!");
	}

}
