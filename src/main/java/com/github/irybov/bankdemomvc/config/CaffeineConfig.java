package com.github.irybov.bankdemomvc.config;

import java.util.concurrent.TimeUnit;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

@EnableCaching
@Configuration
public class CaffeineConfig {
	
	@Bean
	public Cache<String, String> cacheConfig() {
		return Caffeine.newBuilder().expireAfterWrite(1, TimeUnit.MINUTES).build();
	}

}
