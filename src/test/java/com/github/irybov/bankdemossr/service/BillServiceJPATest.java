package com.github.irybov.bankdemossr.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.util.Optional;

import javax.persistence.EntityNotFoundException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.irybov.bankdemossr.controller.dto.BillResponse;
import com.github.irybov.bankdemossr.entity.Account;
import com.github.irybov.bankdemossr.entity.Bill;
import com.github.irybov.bankdemossr.entity.Operation;
import com.github.irybov.bankdemossr.exception.PaymentException;
import com.github.irybov.bankdemossr.repository.BillRepository;
import com.github.irybov.bankdemossr.repository.OperationRepository;
import com.github.irybov.bankdemossr.service.BillServiceJPA;

//@ExtendWith(MockitoExtension.class)
class BillServiceJPATest {

//	@Mock
//	BillServiceJPA billServiceJPA;
	@Mock
	private BillRepository billRepository;
	@Spy
	private OperationRepository operationRepository;
	@InjectMocks
	private BillServiceJPA billService;
	
	private AutoCloseable autoClosable;
	
	private static Bill bill;
	private static Account owner;
		
	private static Operation.OperationBuilder builder;
	
	@BeforeAll
	static void prepare() {
		owner = new Account("Admin", "Adminov", "0000000000", LocalDate.of(2001, 01, 01),
				"superadmin", true);
		bill = new Bill("SEA", true, owner);
		
		builder = mock(Operation.OperationBuilder.class, Mockito.CALLS_REAL_METHODS);
	}
	
	@BeforeEach
	void set_up() {
		autoClosable = MockitoAnnotations.openMocks(this);
		billService = new BillServiceJPA();
		ReflectionTestUtils.setField(billService, "billRepository", billRepository);
//		ReflectionTestUtils.setField(billService, "billService", billServiceJPA);
		ReflectionTestUtils.setField(billService, "operationRepository", operationRepository);
	}
	
	@Test
	void can_save_new_bill() {		
		billService.saveBill(bill);
		verify(billRepository).saveAndFlush(bill);
	}
	
	@Test
	void can_update_new_bill() {		
		billService.updateBill(bill);
		verify(billRepository).save(bill);
	}
	
	@Test
	void can_delete_new_bill() {		
		billService.deleteBill(anyInt());
		verify(billRepository).deleteById(anyInt());
	}
	
	@Test
	void can_change_status() {
		
		when(billRepository.findById(anyInt())).thenReturn(Optional.of(bill));
		try {
			assertThat(billService.changeStatus(anyInt())).isFalse();
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		verify(billRepository).findById(anyInt());
	}
	
	@Test
	void can_get_billDTO() {
		
		when(billRepository.findById(anyInt())).thenReturn(Optional.of(bill));
		try {
			assertThat(billService.getBillDTO(anyInt()))
			.isExactlyInstanceOf(BillResponse.class);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		verify(billRepository).findById(anyInt());
	}
	
	@Test
	void can_get_bill_entity() {
		
		when(billRepository.findById(anyInt())).thenReturn(Optional.of(bill));
		try {
			assertThat(billService.getBill(anyInt())).isExactlyInstanceOf(Bill.class);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		verify(billRepository).findById(anyInt());
	}
	
	@Test
	void catch_entity_not_found_exception() {
		
		when(billRepository.findById(anyInt())).thenReturn(Optional.ofNullable(null));
		assertThatThrownBy(() -> billService.getBill(anyInt()))
				  .isInstanceOf(EntityNotFoundException.class);
		verify(billRepository).findById(anyInt());
	}
	
	@Test
	void catch_amount_payment_exception() {
		
		Operation operation = builder.sender(0).amount(0.00).recipient(0).build();
		
		assertThatThrownBy(() -> billService.deposit(operation))
			.isInstanceOf(PaymentException.class)
		  	.hasMessage("Amount of money should be higher than zero");
		assertThatThrownBy(() -> billService.withdraw(operation))
			.isInstanceOf(PaymentException.class)
		    .hasMessage("Amount of money should be higher than zero");
		assertThatThrownBy(() -> billService.transfer(operation))
		    .isInstanceOf(PaymentException.class)
		    .hasMessage("Amount of money should be higher than zero");
	}
	
	@ParameterizedTest
	@CsvSource({"0.01", "0.02", "0.03"})
	void can_deposit_money(double amount) {
		
		Operation operation = builder.recipient(0).amount(amount).build();
		
		when(billRepository.findById(anyInt())).thenReturn(Optional.of(bill));
		try {
			billService.deposit(operation);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		assertEquals(bill.getBalance().setScale(2, RoundingMode.DOWN).doubleValue(), amount, 0.00);
		verify(billRepository).findById(anyInt());
		
		verify(operationRepository).saveAndFlush(operation);
	}
	
	@Test
	void withdraw_not_enough_money() {
		
		Operation operation = builder.sender(0).amount(0.05).build();
		
		when(billRepository.findById(anyInt())).thenReturn(Optional.of(bill));
		assertThatThrownBy(() -> billService.withdraw(operation))
			.isInstanceOf(PaymentException.class)
			.hasMessage("Not enough money to complete operation");
		verify(billRepository).findById(anyInt());
	}
	
	@Test
	void transfer_not_enough_money() {
		
		Operation operation = builder.sender(0).amount(0.05).recipient(1).build();
		
		when(billRepository.findById(anyInt())).thenReturn(Optional.of(bill));
		assertThatThrownBy(() -> billService.transfer(operation))
			.isInstanceOf(PaymentException.class)
			.hasMessage("Not enough money to complete operation");
		verify(billRepository, times(2)).findById(anyInt());
	}
	
	@Test
	void can_withdraw_money() {
		
		Operation operation = builder.sender(0).amount(0.5).build();
		
		bill.setBalance(new BigDecimal(1.00));
		when(billRepository.findById(anyInt())).thenReturn(Optional.of(bill));
		try {
			billService.withdraw(operation);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		assertEquals(bill.getBalance().setScale(2, RoundingMode.DOWN).doubleValue(), 0.5, 0.00);
		assertThat(bill.getBalance().setScale(2, RoundingMode.FLOOR).doubleValue()).isEqualTo(0.5);
		verify(billRepository).findById(anyInt());
		
		verify(operationRepository).saveAndFlush(operation);
	}

	@Test
	void transfer_source_matches_target() {
		
		Operation operation = builder.sender(0).amount(0.01).recipient(0).build();
		
		assertThatThrownBy(() -> billService.transfer(operation))
	    .isInstanceOf(PaymentException.class)
	    .hasMessage("Source and target bills should not be the same");
	}
	
	@Test
	void transfer_wrong_currency_type() {
		
		Operation operation = builder.sender(0).amount(0.01).recipient(1).build();
		
		bill.setBalance(new BigDecimal(1.00));
		Bill target = new Bill("XXX", false, owner);		
		when(billRepository.findById(1)).thenReturn(Optional.of(target));
		when(billRepository.findById(0)).thenReturn(Optional.of(bill));
		
		assertThatThrownBy(() -> billService.transfer(operation))
	    	.isInstanceOf(PaymentException.class)
	    	.hasMessage("Wrong currency type of the target bill");
		verify(billRepository, times(2)).findById(anyInt());
	}
	
	@Test
	void can_transfer_money() {
		
		Operation operation = builder.sender(0).amount(0.01).recipient(1).build();
		
		bill.setBalance(new BigDecimal(1.00));
		Bill target = new Bill("SEA", false, owner);		
		when(billRepository.findById(1)).thenReturn(Optional.of(target));
		when(billRepository.findById(0)).thenReturn(Optional.of(bill));
		
		try {
			billService.transfer(operation);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		verify(billRepository, times(2)).findById(anyInt());
		
		verify(operationRepository).saveAndFlush(operation);
	}
	
	@AfterEach
	void tear_down() throws Exception {
		autoClosable.close();
		billService = null;
		bill.setBalance(new BigDecimal(0.00));
	}

	@AfterAll
	static void clear() {
		bill = null;
		owner = null;
    	builder = null;
	}
	
}
