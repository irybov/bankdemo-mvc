package com.github.irybov.bankdemoboot.service;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.irybov.bankdemoboot.controller.dto.OperationResponseDTO;
import com.github.irybov.bankdemoboot.entity.Operation;
import com.github.irybov.bankdemoboot.model.OperationPage;
import com.github.irybov.bankdemoboot.repository.OperationRepository;

class OperationServiceJPATest {
	
	@Mock
	private OperationRepository operationRepository;
	@InjectMocks
	private OperationServiceJPA operationService;
	
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
		operationService = new OperationServiceJPA();
		ReflectionTestUtils.setField(operationService, "operationRepository", operationRepository);
	}

	@Test
	void create_and_save_operation() {
		
		when(builder.build()).thenReturn(operation);
		operationService.deposit(new Random().nextDouble(), anyString(), "^[A-Z]{3}",
				new Random().nextInt());
		operationService.withdraw(new Random().nextDouble(), anyString(), "^[A-Z]{3}",
				new Random().nextInt());
		operationService.transfer(new Random().nextDouble(), anyString(), "^[A-Z]{3}",
				new Random().nextInt(), new Random().nextInt());
		verify(operationRepository, times(3)).save(any(Operation.class));
	}
	
	@Test
	void can_get_single_entity() {
		when(operationRepository.getById(anyLong())).thenReturn(operation);
		assertThat(operationService.getOne(anyLong())).isExactlyInstanceOf(Operation.class);
		verify(operationRepository).getById(anyLong());
	}
	
	@Test
	void can_get_list_of_dto() {
		
		final byte size = (byte) new Random().nextInt(Byte.MAX_VALUE + 1);
		List<Operation> operations = Stream.generate(Operation::new)
				.limit(size)
				.collect(Collectors.toList());
		final int id = new Random().nextInt();
		
		when(operationRepository.findBySenderOrRecipientOrderByIdDesc(id, id))
			.thenReturn(operations);
		assertAll(
				() -> assertThat(operationService.getAll(id))
								.hasSameClassAs(new ArrayList<OperationResponseDTO>()),
				() -> assertThat(operationService.getAll(id).size())
								.isEqualTo(operations.size()));
		verify(operationRepository, times(2)).findBySenderOrRecipientOrderByIdDesc(id, id);
	}
	
	@Test
	void can_get_page_of_dto() {
		
		final byte size = (byte) new Random().nextInt(Byte.MAX_VALUE + 1);
		List<Operation> operations = Stream.generate(Operation::new)
				.limit(size)
				.collect(Collectors.toList());			
		Page<Operation> result = new PageImpl<Operation>(operations);
		when(operationRepository.findAll(any(Specification.class), any(Pageable.class)))
				.thenReturn(result);

		final int id = new Random().nextInt();
		final double value = new Random().nextDouble();
		OperationPage page = new OperationPage();
		
		assertThat(operationService.getPage(id, "^[a-z]{7,8}", value, value,
					any(OffsetDateTime.class), any(OffsetDateTime.class), page))
			.hasSameClassAs(new PageImpl<OperationResponseDTO>(new ArrayList<OperationResponseDTO>()));
		verify(operationRepository).findAll(any(Specification.class), any(Pageable.class));
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
