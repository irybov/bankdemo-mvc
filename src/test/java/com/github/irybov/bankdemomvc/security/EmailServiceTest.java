package com.github.irybov.bankdemomvc.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EmailServiceTest {
	
	@Mock
	private JavaMailSender mailSender;
	@InjectMocks
	private EmailService emailService;
	private AutoCloseable autoClosable;
	
    @BeforeAll
    void set_up() {
    	autoClosable = MockitoAnnotations.openMocks(this);
    	emailService = new EmailService(mailSender);
    }

	@Test
	void test_activation() throws MessagingException {
		
		MimeMessage mimeMessage = new MimeMessage((Session)null);
		when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
		doNothing().when(mailSender).send(mimeMessage);
		
		emailService.sendActivationLink("recipient");
		
		verify(mailSender).createMimeMessage();
		verify(mailSender).send(mimeMessage);
	}
	
	@Test
	void test_verification() throws MessagingException {
		
		doNothing().when(mailSender).send(any(SimpleMailMessage.class));
		
		emailService.sendVerificationCode(anyString());
		
		verify(mailSender).send(any(SimpleMailMessage.class));
	}
	
    @AfterAll
    void tear_down() throws Exception {
    	autoClosable.close();
    	emailService = null;
    }

}
