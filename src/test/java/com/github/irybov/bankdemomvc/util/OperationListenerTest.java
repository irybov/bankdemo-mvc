package com.github.irybov.bankdemomvc.util;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.irybov.bankdemomvc.entity.Operation;
import com.github.irybov.bankdemomvc.service.OperationService;

@ExtendWith(SpringExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(OperationListener.class)
class OperationListenerTest {
	
	@Autowired
	private ApplicationEventPublisher publisher;
	
	@MockBean
	@Qualifier("operationServiceAlias")
	private OperationService operationService;
	@Autowired
	private OperationListener listener;
	
	@BeforeAll
	void prepare() {
		ReflectionTestUtils.setField(listener, "operationService", operationService);
	}

	@Test
	void test() {
		publisher.publishEvent(new OperationEvent(this, new Operation()));
		
		doNothing().when(operationService).save(any(Operation.class));
		verify(operationService).save(any(Operation.class));
	}

}
