package com.github.irybov.bankdemomvc.dao;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.irybov.bankdemomvc.dao.OperationDAO;
import com.github.irybov.bankdemomvc.entity.Operation;
import com.github.irybov.bankdemomvc.misc.Action;
import com.github.irybov.bankdemomvc.page.OperationPage;

@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Sql("/test-operations-h2.sql")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DataJpaTest
class OperationDAOTest {
	
	@PersistenceContext
	private EntityManager entityManager;
	
	@InjectMocks
	private OperationDAO operationDAO;
	
	@BeforeAll
	void prepare() {
		ReflectionTestUtils.setField(operationDAO, "entityManager", entityManager);
	}

	//@Execution(ExecutionMode.CONCURRENT)
	@ParameterizedTest
	@CsvSource({"1, 3", "2, 2", "3, 3"})
	void test_getAll(int id, int quantity) {
		
	    Comparator<Operation> compareById = Comparator.comparing(Operation::getId).reversed();
		List<Operation> operations = operationDAO.getAll(id);
		assertThat(operations.size()).isEqualTo(quantity);
		assertThat(operations).isSortedAccordingTo((compareById));
	}

	//@Execution(ExecutionMode.CONCURRENT)
	@ParameterizedTest
	@MethodSource("params")
	void test_getPage(int id, String action, double minval, double maxval,
			OffsetDateTime mindate, OffsetDateTime maxdate, int quantity) {
		
		OperationPage page = new OperationPage();
		Pageable pageable = PageRequest.of(page.getPageNumber(), page.getPageSize(),
				page.getSortDirection(), page.getSortBy());
		
		Page<Operation> resultPage = operationDAO.getPage(id, action, minval, maxval,
														  mindate, maxdate, pageable);
		
		assertThat(resultPage.getContent().size()).isEqualTo(quantity);
	}
	private static Stream<Arguments> params() {
		return Stream.of(Arguments.of(1, "deposit",  100.00, 700.00,
				OffsetDateTime.now().minusDays(1L), OffsetDateTime.now().plusDays(1L), 1),
				Arguments.of(2, "transfer",  200.00, 900.00,
						OffsetDateTime.now().minusDays(1L), OffsetDateTime.now().plusDays(1L), 2));
	}
	
	@Test
	void test_persist() {
		
		Operation.OperationBuilder builder = Operation.builder();
		Operation operation = builder
			.amount(0.00)
			.action(Action.EXTERNAL.name().toLowerCase())
			.currency("SEA")
			.createdAt(OffsetDateTime.now())
			.bank("Demo")
			.build();
		
		entityManager.persist(operation);
		assertThat(operation.getId() == 1);
	}
	
}
