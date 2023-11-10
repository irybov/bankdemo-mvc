package com.github.irybov.bankdemossr.validation;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDate;
import java.util.Optional;

import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.Errors;

import com.github.irybov.bankdemossr.controller.dto.AccountRequest;
import com.github.irybov.bankdemossr.service.AccountService;
import com.github.irybov.bankdemossr.validation.AccountValidator;

class AccountValidatorTest {

    private Validator validator;
	private static ValidatorFactory validatorFactory;
    @Mock
	private AccountService accountService;
    @InjectMocks
    private AccountValidator accountValidator;
    
	private AutoCloseable autoClosable;
	
	private static String phone;
	
	@BeforeAll
	static void prepare() {
		phone = new String("0000000000");
        validatorFactory = Validation.buildDefaultValidatorFactory();
	}
    
    @BeforeEach
    void set_up() {
        validator = validatorFactory.getValidator();
    	autoClosable = MockitoAnnotations.openMocks(this);
    	accountValidator = new AccountValidator();
		ReflectionTestUtils.setField(accountValidator, "accountService", accountService);
		ReflectionTestUtils.setField(accountValidator, "validator", validator);
    }

	@Test
	void check_supported_clazz() {
		assertTrue(accountValidator.supports(AccountRequest.class));
		assertFalse(accountValidator.supports(Object.class));
	}
	
	@Test
	void check_dto_validation() {
		
		AccountRequest accountRequestDTO = new AccountRequest();
//		accountRequestDTO.setBirthday("2001-01-01");
		accountRequestDTO.setBirthday(LocalDate.of(2001, 01, 01));
		accountRequestDTO.setName("Admin");
		accountRequestDTO.setPassword("superadmin");
		accountRequestDTO.setPhone(phone);
		accountRequestDTO.setSurname("Adminov");
	
		Errors errors = new BeanPropertyBindingResult(accountRequestDTO, "accountRequestDTO");
				
		when(accountService.getPhone(accountRequestDTO.getPhone())).thenReturn(Optional.empty());
		accountValidator.validate(accountRequestDTO, errors);
		assertFalse(errors.hasErrors());
		
		when(accountService.getPhone(accountRequestDTO.getPhone())).thenReturn(Optional.of(phone));
		accountValidator.validate(accountRequestDTO, errors);
		assertTrue(errors.hasFieldErrors("phone"));
		
		
		accountRequestDTO.setBirthday(LocalDate.now().minusYears(17L));
		accountRequestDTO.setName("i");
		accountRequestDTO.setPassword("superb");
		accountRequestDTO.setSurname("a");
		
		when(accountService.getPhone(accountRequestDTO.getPhone())).thenReturn(Optional.empty());
		accountValidator.validate(accountRequestDTO, errors);
		assertTrue(errors.hasFieldErrors("birthday"));
		assertTrue(errors.hasFieldErrors("name"));
		assertTrue(errors.hasFieldErrors("password"));
		assertTrue(errors.hasFieldErrors("surname"));
		
		verify(accountService, times(3)).getPhone(accountRequestDTO.getPhone());
		
				
		accountRequestDTO.setPhone("xxx");
		
		when(accountService.getPhone(accountRequestDTO.getPhone())).thenReturn(Optional.empty());
		accountValidator.validate(accountRequestDTO, errors);
		assertTrue(errors.hasFieldErrors("phone"));
		
		verify(accountService).getPhone(accountRequestDTO.getPhone());
	}
	
    @AfterEach
    void tear_down() throws Exception {
    	autoClosable.close();
    	accountService = null;
    	validator = null;
    }
    
    @AfterAll
    static void clear() { 
    	phone = null;
    	validatorFactory = null;
    }

}
