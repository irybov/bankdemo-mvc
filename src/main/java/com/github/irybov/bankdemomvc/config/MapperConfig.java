package com.github.irybov.bankdemomvc.config;

import org.modelmapper.ModelMapper;
import org.modelmapper.config.Configuration.AccessLevel;
import org.modelmapper.convention.MatchingStrategies;
import org.modelmapper.convention.NameTokenizers;
import org.modelmapper.convention.NamingConventions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MapperConfig {
    
    @Bean
    public ModelMapper modelMapper() {
        ModelMapper mapper = new ModelMapper();
        mapper.getConfiguration()
                .setMatchingStrategy(MatchingStrategies.STRICT)
                .setFieldMatchingEnabled(true)
                .setSkipNullEnabled(true)
                .setFieldAccessLevel(AccessLevel.PRIVATE)
		        .setSourceNamingConvention(NamingConventions.JAVABEANS_ACCESSOR)
		        .setDestinationNamingConvention(NamingConventions.JAVABEANS_MUTATOR)
		        .setSourceNameTokenizer(NameTokenizers.CAMEL_CASE)
		        .setDestinationNameTokenizer(NameTokenizers.CAMEL_CASE);
    	return mapper;
    }
	
}
