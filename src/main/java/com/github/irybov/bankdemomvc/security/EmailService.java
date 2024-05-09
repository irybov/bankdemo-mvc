package com.github.irybov.bankdemomvc.security;

import java.sql.Date;
import java.time.Instant;
import java.util.Random;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Service;

import net.bytebuddy.utility.RandomString;

//@EnableAsync
@Service
public class EmailService {
	
	@Value("${server.address}")
	private String uri;
	@Value("${server.port}")
	private int port;
	@Value("${server.servlet.context-path}")
	private String path;
	
	private final JavaMailSender mailSender;
	public EmailService(JavaMailSender mailSender) {
		this.mailSender = mailSender;
	}	
	private final RandomString random = new RandomString();
	private final Random digit = new Random();

//	@Async
	public String sendActivationLink(String recipient) throws MessagingException {
		
		String tail = random.nextString();
		String link = "<a href='http://" + uri + ":" + port + path + "/activate/" + 
												tail + "'>Activate your account</a>";
		
		MimeMessage mimeMessage = mailSender.createMimeMessage();
//		MimeBodyPart messageBodyPart = new MimeBodyPart();				
		MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "UTF-8");
        helper.setTo(recipient);
        helper.setFrom("noreply@bankdemo.com");
        helper.setSubject("Confirm your registration");
//		messageBodyPart.setText(link, "UTF-8", "html");
        helper.setSentDate(Date.from(Instant.now()));
        helper.setText(link, true);
	        
        mailSender.send(mimeMessage);
        return tail;
	}
	
//	@Async
	public String sendVerificationCode(String recipient) {
		
		StringBuilder code = new StringBuilder();
		for (int i = 1; i < 5; i++) {
		    code.append(String.valueOf(digit.nextInt(10)));
		}
		
		SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(recipient);
        message.setFrom("noreply@bankdemo.com"); 
        message.setSubject("Login verification code"); 
        message.setSentDate(Date.from(Instant.now()));
        message.setText(code.toString());
        
        mailSender.send(message);
        return code.toString();
	}
	
}
