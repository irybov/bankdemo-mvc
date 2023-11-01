package com.github.irybov.bankdemossr.config;

import java.io.IOException;
import java.util.concurrent.Executor;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import com.github.irybov.bankdemossr.service.AccountService;
import com.github.irybov.bankdemossr.service.BillService;
import com.github.irybov.bankdemossr.service.OperationService;
import com.github.irybov.bankdemossr.validation.AccountValidator;

@Configuration
@ComponentScan(basePackages="bankdemoboot")
public class AppConfig {

    @Autowired
    private ApplicationContext context;
	
	@ConfigurationProperties(prefix = "spring.datasource")
	@Bean
	@Primary
	public DataSource datasource() {
		return DataSourceBuilder.create().build();
	}
	@Bean
	protected BCryptPasswordEncoder bCryptPasswordEncoder() {
	    return new BCryptPasswordEncoder(4);
	}
	
    @Bean
    @Primary
    public AccountService accountServiceAlias(@Value("accountService"+"${bean.service-impl}")
    String qualifier) {
        return (AccountService) context.getBean(qualifier);
    }
    @Bean
    public BillService billServiceAlias(@Value("billService"+"${bean.service-impl}")
    String qualifier) {
        return (BillService) context.getBean(qualifier);
    }
    @Bean
    public OperationService operationServiceAlias(@Value("operationService"+"${bean.service-impl}")
    String qualifier) {
        return (OperationService) context.getBean(qualifier);
    }    
    
    @Bean
    @Primary
    public AccountValidator beforeCreateAccountValidator() {
        return new AccountValidator();
    }
    
    @Bean
    @Primary
    public Executor asyncExecutor() {
    	final int cores = Runtime.getRuntime().availableProcessors();
    	final ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    	executor.setCorePoolSize(cores);
        executor.setMaxPoolSize(cores * 5);
        executor.setQueueCapacity(cores * 10);
    	executor.initialize();
    	return executor;
    }
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplateBuilder()
        		.errorHandler(new DefaultResponseErrorHandler() {
                    @Override
                    public void handleError(ClientHttpResponse response) throws IOException {
                        //do nothing :)
                    }
                })
                .build();
    }
    
}
