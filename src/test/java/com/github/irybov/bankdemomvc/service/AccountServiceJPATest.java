package com.github.irybov.bankdemomvc.service;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.BDDAssertions.then;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import java.time.LocalDate;
import java.time.Month;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.parallel.Execution;
//import org.junit.jupiter.api.parallel.ExecutionMode;
//import org.junit.jupiter.api.TestInstance;
//import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.modelmapper.ModelMapper;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.irybov.bankdemomvc.controller.dto.AccountRequest;
import com.github.irybov.bankdemomvc.controller.dto.AccountResponse;
import com.github.irybov.bankdemomvc.controller.dto.BillResponse;
import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.entity.Bill;
import com.github.irybov.bankdemomvc.exception.RegistrationException;
import com.github.irybov.bankdemomvc.jpa.AccountJPA;
import com.github.irybov.bankdemomvc.security.Role;
import com.github.irybov.bankdemomvc.service.AccountServiceJPA;
import com.github.irybov.bankdemomvc.service.BillService;

//@TestInstance(TestInstance.Lifecycle.PER_CLASS)
//@ExtendWith(MockitoExtension.class)
//@Execution(ExecutionMode.CONCURRENT)
class AccountServiceJPATest {

	@Spy
	private ModelMapper modelMapper;
	@Mock
	private BillService billService;
	@Spy
	private BCryptPasswordEncoder bCryptPasswordEncoder;
//	@Mock
//	AccountServiceJPA accountServiceJPA;
	@Mock
	private AccountJPA accountJPA;
	@InjectMocks
	private AccountServiceJPA accountService;
	
	private AutoCloseable autoClosable;
	
	private static String phone;
	private static Account adminEntity;
	
	@BeforeAll
	static void prepare() {
		phone = new String("0000000000");
		adminEntity = new Account("Admin", "Adminov", "0000000000", "adminov@greenmail.io", LocalDate.of(2001, 01, 01),
										 BCrypt.hashpw("superadmin", BCrypt.gensalt(4)), true);
	}
	
    @BeforeEach
    void set_up() {
    	autoClosable = MockitoAnnotations.openMocks(this);
    	accountService = new AccountServiceJPA();
		ReflectionTestUtils.setField(accountService, "accountJPA", accountJPA);
//		ReflectionTestUtils.setField(accountService, "accountService", accountServiceJPA);
		ReflectionTestUtils.setField(accountService, "bCryptPasswordEncoder", bCryptPasswordEncoder);
		ReflectionTestUtils.setField(accountService, "billService", billService);
		ReflectionTestUtils.setField(accountService, "modelMapper", modelMapper);
    }
    
    @Test
    void add_new_bills_and_get_them() {
    	
    	String currency = "SEA";
    	Bill billOne = new Bill(currency, true, adminEntity);
    	Bill billTwo = new Bill(currency, true, adminEntity);
    	
    	given(accountJPA.findByPhone(phone)).willReturn(Optional.ofNullable(adminEntity));
    	doAnswer(new Answer<Account>() {
			@Override
			public Account answer(InvocationOnMock invocation) throws Throwable {
				adminEntity.addBill(billOne);
				adminEntity.addBill(billTwo);
				return adminEntity;
			}}).when(accountJPA).save(adminEntity);
    	
    	try {
    		org.assertj.core.api.BDDAssertions.then(accountService.addBill(phone, currency))
    											.isExactlyInstanceOf(BillResponse.class);
		}
    	catch (Exception exc) {
			exc.printStackTrace();
		}
    	verify(accountJPA).findByPhone(phone);

//    	given(accountRepository.getById(anyInt())).willReturn(adminEntity);
    	List<BillResponse> dtos = adminEntity.getBills().stream()
				.map(source -> modelMapper.map(source, BillResponse.class))
				.collect(Collectors.toList());
    	given(billService.getAll(anyInt())).willReturn(dtos);
    	org.assertj.core.api.BDDAssertions.then(billService.getAll(anyInt())).hasSize(3);
//    	verify(accountRepository).getById(anyInt());
    	verify(billService).getAll(anyInt());
    }
    
    @Test
    void can_get_phone_if_presents() {
        
        given(accountJPA.getPhone(phone)).willReturn(Optional.of(phone));
        org.assertj.core.api.BDDAssertions.then(accountService.getPhone(phone).get())
        									.isExactlyInstanceOf(String.class)
        									.hasSize(phone.length());
        verify(accountJPA).getPhone(phone);
    }
    
    @Test
    void can_not_get_phone() {
        
        given(accountJPA.getPhone(phone)).willReturn(null);
        org.assertj.core.api.BDDAssertions.then(accountService.getPhone(phone)).isNull();
        verify(accountJPA).getPhone(phone);
    }
	
    @Test
    void can_get_single_account() {

		given(accountJPA.findByPhone(phone)).willReturn(Optional.ofNullable(adminEntity));
    	try {
    		org.assertj.core.api.BDDAssertions.then(accountService.getAccount(phone))
    											 .isExactlyInstanceOf(Account.class);
		}
    	catch (Exception exc) {
			exc.printStackTrace();
		}
        verify(accountJPA).findByPhone(phone);
    }
    
    @Test
    void can_get_accounts_list() {
    	
		Account vixenEntity = new Account
		("Kae", "Yukawa", "1111111111", "yukawa@greenmail.io", LocalDate.of(1985, Month.AUGUST, 31), "supervixen", true);
		vixenEntity.addRole(Role.CLIENT);
		vixenEntity.setId(3);
		vixenEntity.setBills(new ArrayList<Bill>());
		Account blondeEntity = new Account
		("Hannah", "Waddingham", "2222222222", "waddingham@greenmail.io", LocalDate.of(1974, Month.JULY, 28), "bustyblonde", true);
		blondeEntity.addRole(Role.CLIENT);
		blondeEntity.setId(2);
		blondeEntity.setBills(new ArrayList<Bill>());
		Account gingerEntity = new Account
		("Ella", "Hughes", "3333333333", "hughes@greenmail.io", LocalDate.of(1995, Month.JUNE, 13), "gingerchick", true);
		gingerEntity.addRole(Role.CLIENT);
		gingerEntity.addRole(Role.ADMIN);
		gingerEntity.setId(1);
		gingerEntity.setBills(new ArrayList<Bill>());
    	
    	List<Account> clients = new ArrayList<>();
    	Collections.addAll(clients, vixenEntity, blondeEntity, gingerEntity);
    	
    	given(accountJPA.getAll()).willReturn(clients);
    	org.assertj.core.api.BDDAssertions.then(accountService.getAll()).hasSameSizeAs(clients)
    								 .isSortedAccordingTo((a1, a2) -> a1.getId() - a2.getId())
    								 .containsAll(new ArrayList<AccountResponse>());
    	org.mockito.BDDMockito.then(accountJPA).should().getAll();
    }
    
    @Test
    void can_change_status() {
    	
    	given(accountJPA.findById(anyInt())).willReturn(Optional.of(adminEntity));
    	then(accountService.changeStatus(anyInt())).isFalse();
    	verify(accountJPA).findById(anyInt());
    }
    
    @Test
    void can_change_password() {
    	
    	String password = "nightrider";
    	given(accountJPA.findByPhone(phone)).willReturn(Optional.ofNullable(adminEntity));
    	doAnswer(new Answer<Account>() {
			@Override
			public Account answer(InvocationOnMock invocation) throws Throwable {
				adminEntity.setPassword(password);
				return adminEntity;
			}}).when(accountJPA).save(adminEntity);
    	
    	try {
			accountService.changePassword(phone, password);
		}
    	catch (Exception exc) {
			exc.printStackTrace();
		}
    	verify(accountJPA).findByPhone(phone);
    	org.assertj.core.api.BDDAssertions.then(adminEntity.getPassword()).isEqualTo(password);
    }
    
    @Test
    void password_comparison() {
    	
    	given(accountJPA.findByPhone(phone)).willReturn(Optional.ofNullable(adminEntity));
//    	given(bCryptPasswordEncoder.matches("superadmin", adminEntity.getPassword())).willReturn(true);
    	try {
			then(accountService.comparePassword("superadmin", phone)).isTrue();
		}
    	catch (Exception exc) {
			exc.printStackTrace();
		}
    	verify(accountJPA).findByPhone(phone);
    	verify(bCryptPasswordEncoder).matches("superadmin", adminEntity.getPassword());
    }
    
	@Test
	void save_and_verify_identity() {

		AccountRequest accountRequestDTO = new AccountRequest();
//		accountRequestDTO.setBirthday("2001-01-01");
		accountRequestDTO.setBirthday(LocalDate.of(2001, 01, 01));
		accountRequestDTO.setName("Admin");
		accountRequestDTO.setPassword("superadmin");
		accountRequestDTO.setPhone("0000000000");
		accountRequestDTO.setSurname("Adminov");
		try {
			accountService.saveAccount(accountRequestDTO);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}		
		ArgumentCaptor<Account> argumentCaptor = ArgumentCaptor.forClass(Account.class);
		org.mockito.BDDMockito.then(accountJPA).should().saveAndFlush(argumentCaptor.capture());
        
		given(accountJPA.findByPhone(phone)).willReturn(Optional.ofNullable(adminEntity));
		try {
			then(accountService.verifyAccount(phone, adminEntity.getPhone())).isTrue();
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
        org.mockito.BDDMockito.then(accountJPA).should().findByPhone(phone);
	}
	
	@Test
	void save_and_catch_exceptions() {
		
		AccountRequest accountRequestDTO = new AccountRequest();
		accountRequestDTO.setBirthday(LocalDate.now().minusYears(10L));
		accountRequestDTO.setName("Admin");
		accountRequestDTO.setPassword("superadmin");
		accountRequestDTO.setPhone("0000000000");
		accountRequestDTO.setSurname("Adminov");

		assertThatExceptionOfType(RegistrationException.class)
		.isThrownBy(() -> {accountService.saveAccount(accountRequestDTO);});
		
		accountRequestDTO.setBirthday(LocalDate.now().minusYears(20L));		
		doThrow(new DataIntegrityViolationException(null)).when(accountJPA).saveAndFlush(adminEntity);
		
		assertThatExceptionOfType(DataIntegrityViolationException.class)
		.isThrownBy(() -> {accountService.saveAccount(accountRequestDTO);});
		org.mockito.BDDMockito.then(accountJPA).should().saveAndFlush(adminEntity);
	}
    
    @AfterEach
    void tear_down() throws Exception {
    	autoClosable.close();
    	accountService = null;
    }
    
    @AfterAll
    static void clear() {    	
    	phone = null;
    	adminEntity = null;
    }
    
}
