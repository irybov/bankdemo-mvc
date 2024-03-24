package com.github.irybov.bankdemomvc.service;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
//import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.irybov.bankdemomvc.controller.dto.OperationResponse;
import com.github.irybov.bankdemomvc.dao.OperationDAO;
import com.github.irybov.bankdemomvc.entity.Operation;
import com.github.irybov.bankdemomvc.page.OperationPage;
import com.github.irybov.bankdemomvc.service.OperationServiceDAO;

class OperationServiceDAOTest {

	@Spy
	private ModelMapper modelMapper;
	@Mock
	private OperationDAO operationDAO;
	@InjectMocks
	private OperationServiceDAO operationService;
	
	private AutoCloseable autoClosable;
	
	private static Operation operation;	
	private static Operation.OperationBuilder builder;
	
	@BeforeAll
	static void prepare() {
		operation = new Operation();
		builder = mock(Operation.OperationBuilder.class, Mockito.RETURNS_SELF);
	}
	
	@BeforeEach
	void set_up() {
		autoClosable = MockitoAnnotations.openMocks(this);
		operationService = new OperationServiceDAO();
		ReflectionTestUtils.setField(operationService, "operationDAO", operationDAO);
		ReflectionTestUtils.setField(operationService, "modelMapper", modelMapper);
	}
	
	@Test
	void can_create_entity() {
		
		String currency = "SEA";		
		when(builder.build()).thenReturn(operation);
		
		assertThat(operationService.deposit(new Random().nextDouble(), currency, "^[A-Z]{3}",
				new Random().nextInt(), "Demo")).hasSameClassAs(operation);
		assertThat(operationService.withdraw(new Random().nextDouble(), currency, "^[A-Z]{3}",
				new Random().nextInt(), "Demo")).hasSameClassAs(operation);
		assertThat(operationService.transfer(new Random().nextDouble(), currency, "^[A-Z]{3}",
				new Random().nextInt(), new Random().nextInt(), "Demo")).hasSameClassAs(operation);
//		verify(operationDAO, times(3)).save(any(Operation.class));
	}
	
	@Test
	void can_get_single_entity() {
		when(operationDAO.getById(anyLong())).thenReturn(operation);
		assertThat(operationService.getOne(anyLong())).isExactlyInstanceOf(OperationResponse.class);
		verify(operationDAO).getById(anyLong());
	}
	
	@Test
	void can_get_list_of_dto() {
		
		final byte size = (byte) new Random().nextInt(Byte.MAX_VALUE + 1);
		List<Operation> operations = Stream.generate(Operation::new)
				.limit(size)
				.collect(Collectors.toList());
		
		when(operationDAO.getAll(anyInt())).thenReturn(operations);
		
		List<OperationResponse> dtos = operationService.getAll(anyInt());
		assertAll(
				() -> assertThat(dtos).hasSameClassAs(new ArrayList<OperationResponse>()),
				() -> assertThat(dtos.size()).isEqualTo(operations.size()));
		verify(operationDAO).getAll(anyInt());
	}
	
	@Test
	void can_get_page_of_dto() {
		
		final byte size = (byte) new Random().nextInt(Byte.MAX_VALUE + 1);
		List<Operation> operations = Stream.generate(Operation::new)
				.limit(size)
				.collect(Collectors.toList());			
		Page<Operation> result = new PageImpl<Operation>(operations);
		when(operationDAO.getPage(anyInt(), anyString(), anyDouble(), anyDouble(),
				any(OffsetDateTime.class), any(OffsetDateTime.class), any(Pageable.class)))
				.thenReturn(result);

		final int id = new Random().nextInt();
		final double value = new Random().nextDouble();
		OperationPage page = new OperationPage();
		Pageable pageable = PageRequest.of(page.getPageNumber(), page.getPageSize(),
				   page.getSortDirection(), page.getSortBy());
		OffsetDateTime date = OffsetDateTime.now();
		
		Page<OperationResponse> dtos = operationService.getPage(id, "^[a-z]{7,8}",
				value, value, date, date, pageable);
		assertThat(dtos)
			.hasSameClassAs(new PageImpl<OperationResponse>(new ArrayList<OperationResponse>()));
		assertThat(dtos.getContent().size()).isEqualTo(size);
		verify(operationDAO).getPage(anyInt(), anyString(), anyDouble(),  anyDouble(),
				any(OffsetDateTime.class), any(OffsetDateTime.class), any(Pageable.class));
	}
	
    @AfterEach
    void tear_down() throws Exception {
    	autoClosable.close();
    	operationService = null;
    }

    @AfterAll
    static void clear() {
    	operation = null;
    	builder = null;
    }
	
}
