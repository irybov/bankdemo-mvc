package com.github.irybov.bankdemossr.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import com.fasterxml.jackson.core.JsonParser.Feature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

//@Configuration
public class JacksonConfig {

//    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        return JsonMapper.builder()
        	.configure(Feature.ALLOW_UNQUOTED_FIELD_NAMES, true)
        	.configure(Feature.ALLOW_SINGLE_QUOTES, true)
            .addModule(new JavaTimeModule())
            .build();
    }
    
}
