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
import com.github.irybov.bankdemossr.dao.BillDAO;
import com.github.irybov.bankdemossr.dao.OperationDAO;
import com.github.irybov.bankdemossr.entity.Account;
import com.github.irybov.bankdemossr.entity.Bill;
import com.github.irybov.bankdemossr.entity.Operation;
import com.github.irybov.bankdemossr.exception.PaymentException;
import com.github.irybov.bankdemossr.service.BillServiceDAO;

//@ExtendWith(MockitoExtension.class)
class BillServiceDAOTest {
	
//	@Mock
//	BillServiceDAO billServiceDAO;
	@Mock
	private BillDAO billDAO;
	@Spy
	private OperationDAO operationDAO;
	@InjectMocks
	private BillServiceDAO billService;
	
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
		billService = new BillServiceDAO();
		ReflectionTestUtils.setField(billService, "billDAO", billDAO);
//		ReflectionTestUtils.setField(billService, "billService", billServiceDAO);
		ReflectionTestUtils.setField(billService, "operationDAO", operationDAO);
	}

	@Test
	void can_save_new_bill() {		
		billService.saveBill(bill);
		verify(billDAO).saveBill(bill);
	}
	
	@Test
	void can_update_new_bill() {		
		billService.updateBill(bill);
		verify(billDAO).updateBill(bill);
	}
	
	@Test
	void can_delete_new_bill() {		
		billService.deleteBill(anyInt());
		verify(billDAO).deleteBill(anyInt());
	}
	
	@Test
	void can_change_status() {
		
		when(billDAO.getBill(anyInt())).thenReturn(bill);
		try {
			assertThat(billService.changeStatus(anyInt())).isFalse();
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		verify(billDAO).getBill(anyInt());
	}
	
	@Test
	void can_get_billDTO() {
		
		when(billDAO.getBill(anyInt())).thenReturn(bill);
		try {
			assertThat(billService.getBillDTO(anyInt()))
			.isExactlyInstanceOf(BillResponse.class);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		verify(billDAO).getBill(anyInt());
	}
	
	@Test
	void can_get_bill_entity() {
		
		when(billDAO.getBill(anyInt())).thenReturn(bill);
		try {
			assertThat(billService.getBill(anyInt())).isExactlyInstanceOf(Bill.class);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		verify(billDAO).getBill(anyInt());
	}
	
	@Test
	void catch_entity_not_found_exception() {
		
		when(billDAO.getBill(anyInt())).thenReturn(null);
		assertThatThrownBy(() -> billService.getBill(anyInt()))
				  .isInstanceOf(EntityNotFoundException.class);
		verify(billDAO).getBill(anyInt());
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
		
		when(billDAO.getBill(anyInt())).thenReturn(bill);
		try {
			billService.deposit(operation);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		assertEquals(bill.getBalance().setScale(2, RoundingMode.DOWN).doubleValue(), amount, 0.00);
		verify(billDAO).getBill(anyInt());
		
		verify(operationDAO).save(operation);
	}
	
	@Test
	void withdraw_not_enough_money() {
		
		Operation operation = builder.sender(0).amount(0.05).build();
		
		when(billDAO.getBill(anyInt())).thenReturn(bill);
		assertThatThrownBy(() -> billService.withdraw(operation))
			.isInstanceOf(PaymentException.class)
			.hasMessage("Not enough money to complete operation");
		verify(billDAO).getBill(anyInt());
	}
	
	@Test
	void transfer_not_enough_money() {
		
		Operation operation = builder.sender(0).amount(0.05).recipient(1).build();
		
		when(billDAO.getBill(anyInt())).thenReturn(bill);
		assertThatThrownBy(() -> billService.transfer(operation))
			.isInstanceOf(PaymentException.class)
			.hasMessage("Not enough money to complete operation");
		verify(billDAO, times(2)).getBill(anyInt());
	}
	
	@Test
	void can_withdraw_money() {
		
		Operation operation = builder.sender(0).amount(0.5).build();
		
		bill.setBalance(new BigDecimal(1.00));
		when(billDAO.getBill(anyInt())).thenReturn(bill);
		try {
			billService.withdraw(operation);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		assertEquals(bill.getBalance().setScale(2, RoundingMode.DOWN).doubleValue(), 0.5, 0.00);
		assertThat(bill.getBalance().setScale(2, RoundingMode.FLOOR).doubleValue()).isEqualTo(0.5);
		verify(billDAO).getBill(anyInt());
		
		verify(operationDAO).save(operation);
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
		when(billDAO.getBill(1)).thenReturn(target);
		when(billDAO.getBill(0)).thenReturn(bill);
		
		assertThatThrownBy(() -> billService.transfer(operation))
	    	.isInstanceOf(PaymentException.class)
	    	.hasMessage("Wrong currency type of the target bill");
		verify(billDAO, times(2)).getBill(anyInt());
	}
	
	@Test
	void can_transfer_money() {
		
		Operation operation = builder.sender(0).amount(0.01).recipient(1).build();
		
		bill.setBalance(new BigDecimal(1.00));
		Bill target = new Bill("SEA", false, owner);		
		when(billDAO.getBill(1)).thenReturn(target);
		when(billDAO.getBill(0)).thenReturn(bill);
		
		try {
			billService.transfer(operation);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		verify(billDAO, times(2)).getBill(anyInt());
		
		verify(operationDAO).save(operation);
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
