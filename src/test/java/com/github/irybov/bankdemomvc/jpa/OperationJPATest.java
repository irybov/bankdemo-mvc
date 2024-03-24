package com.github.irybov.bankdemomvc.jpa;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

//import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.test.context.jdbc.Sql;

import com.github.irybov.bankdemomvc.controller.dto.OperationResponse;
import com.github.irybov.bankdemomvc.entity.Operation;
import com.github.irybov.bankdemomvc.jpa.OperationJPA;
import com.github.irybov.bankdemomvc.page.OperationPage;
import com.github.irybov.bankdemomvc.util.OperationSpecification;

@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Sql("/test-operations-h2.sql")
//@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DataJpaTest
class OperationJPATest {
	
	@Autowired
	private OperationJPA operationJPA;

	//@Execution(ExecutionMode.CONCURRENT)
	@ParameterizedTest
	@CsvSource({"1, 1, 3", "2, 2, 2", "3, 3, 3"})
	void test_findBySenderOrRecipientOrderByIdDesc(int sender, int recipient, int quantity) {
		
	    Comparator<Operation> compareById = Comparator.comparing(Operation::getId).reversed();	
		List<Operation> operations =
				operationJPA.findBySenderOrRecipientOrderByIdDesc(sender, recipient);
		assertThat(operations.size()).isEqualTo(quantity);
		assertThat(operations).isSortedAccordingTo((compareById));
	}
	
	//@Execution(ExecutionMode.CONCURRENT)
	@ParameterizedTest
	@MethodSource("params")
	void test_findAllBySpecs(int id, String action, double minval, double maxval,
			OffsetDateTime mindate, OffsetDateTime maxdate, int quantity) {
		
		OperationPage page = new OperationPage();
		Pageable pageable = PageRequest.of(page.getPageNumber(), page.getPageSize(),
				page.getSortDirection(), page.getSortBy());
		
		ModelMapper modelMapper = new ModelMapper();
		Page<OperationResponse> resultPage = operationJPA.findAll
				(OperationSpecification.orderBy(OperationSpecification.hasAction(action)
				.and(OperationSpecification.hasOwner(id))
				.and(OperationSpecification.amountBetween(minval, maxval))
				.and(OperationSpecification.dateBetween(mindate, maxdate))), pageable)
				.map(source -> modelMapper.map(source, OperationResponse.class));
		
		assertThat(resultPage.getContent().size()).isEqualTo(quantity);
	}
	private static Stream<Arguments> params() {
		return Stream.of(Arguments.of(1, "deposit",  100.00, 700.00,
				OffsetDateTime.now().minusDays(1L), OffsetDateTime.now().plusDays(1L), 1),
				Arguments.of(2, "transfer",  200.00, 900.00,
						OffsetDateTime.now().minusDays(1L), OffsetDateTime.now().plusDays(1L), 2));
	}
	
}
