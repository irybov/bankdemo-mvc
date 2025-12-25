package com.github.irybov.bankdemomvc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
//import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

//@EnableWebMvc
@SpringBootApplication(exclude={SecurityAutoConfiguration.class,
								ManagementWebSecurityAutoConfiguration.class})
public class BankDemoBootApplication extends SpringBootServletInitializer {

	public static void main(String[] args) {
		SpringApplication.run(BankDemoBootApplication.class, args);
	}
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(BankDemoBootApplication.class);
    }
}
