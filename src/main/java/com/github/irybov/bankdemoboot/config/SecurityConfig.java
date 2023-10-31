package com.github.irybov.bankdemoboot.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

//import javax.sql.DataSource;

//import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCrypt;
//import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
//import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//import org.springframework.web.servlet.config.annotation.CorsRegistry;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.github.irybov.bankdemoboot.security.AccountDetailsService;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${server.address}")
	private String uri;
	@Value("${server.port}")
	private int port;
//	@Value("${management.server.port}")
//	private int m_port;
	
//	@Autowired
//	private DataSource dataSource;
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	@Autowired
	private AccountDetailsService accountDetailsService;
	
    private static final String[] WHITE_LIST_URLS = { 
    		"/home", 
    		"/login", 
    		"/register", 
    		"/confirm", 
    		"/webjars/**", 
    		"/css/**", 
    		"/js/**", 
			"/bills/external"
    };
    private static final String[] SHARED_LIST_URLS = {
    		"/bills/**", 
    		"/accounts/show", 
    		"/accounts/password"
    };
    private static final String[] ADMIN_LIST_URLS = {
			"/**/swagger*/**", 
			"/**/api-docs/**", 
			"/control", 
    		"/accounts/search", 
    		"/accounts/status", 
    		"/accounts/list/**", 
			"/operations/**", 
			"/h2-console/**"
    };
//    private static final String[] REMOTE_LIST_URLS = {
//			"/*swagger*/**", 
//			"/**/api-docs/**", 
//    		"/actuator/**"
//    };
	
/*    private final AccountDetailsService accountDetailsService;
    public SecurityConfig(AccountDetailsService accountDetailsService) {
        this.accountDetailsService = accountDetailsService;
    }	
	@Bean
	protected BCryptPasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder(4);
	}*/    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    	    	
		auth.inMemoryAuthentication()
			.withUser("remote")
			.password(bCryptPasswordEncoder.encode("remote"))
			.roles("REMOTE");
		
        DaoAuthenticationProvider dao = new DaoAuthenticationProvider();
        dao.setUserDetailsService(accountDetailsService);
        dao.setPasswordEncoder(bCryptPasswordEncoder);
        auth.authenticationProvider(dao);
    	
//        auth.userDetailsService(accountDetailsService)
//            .passwordEncoder(passwordEncoder());
    }
	
/*	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		auth.jdbcAuthentication().dataSource(dataSource)
			.usersByUsernameQuery("SELECT phone, password, is_active::int "
								+ "FROM bankdemo.accounts WHERE phone=?")
		    .authoritiesByUsernameQuery
		    ("SELECT phone, roles FROM bankdemo.accounts AS a INNER JOIN bankdemo.roles AS r "
		    + "ON a.id=r.account_id WHERE a.phone=?")
		    .passwordEncoder(passwordEncoder())
		    .rolePrefix("ROLE_");
	}*/
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		CsrfTokenRepository csrfTokenRepository = new HttpSessionCsrfTokenRepository();

		http
//			.sessionManagement()
//	        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//			.cors(Customizer.withDefaults())
//			.cors()
//			.and()
			.authorizeRequests()
			.antMatchers(WHITE_LIST_URLS).permitAll()
			.antMatchers(SHARED_LIST_URLS).hasAnyRole("ADMIN", "CLIENT")
			.antMatchers(ADMIN_LIST_URLS).hasRole("ADMIN")
			.antMatchers("/actuator/**").hasRole("REMOTE")
			.anyRequest().authenticated()
				.and()
		    .csrf()
		    .csrfTokenRepository(csrfTokenRepository)
		    .sessionAuthenticationStrategy(new CsrfAuthenticationStrategy(csrfTokenRepository))
		    .ignoringAntMatchers("/bills/external", "/actuator/**")
//		    .ignoringAntMatchers(REMOTE_LIST_URLS)
		        .and()
			.formLogin()
			.usernameParameter("phone")
			.loginPage("/home")
			.loginProcessingUrl("/auth")
//			.successHandler((request, response, authentication) ->
//			response.sendRedirect("/accounts/show/" + authentication.getName()))
			.defaultSuccessUrl("/success", true)
            .failureUrl("/login?error=true")
				.and()
			.logout()
//          .logoutUrl("/logout")
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .deleteCookies("JSESSIONID")
			.logoutSuccessUrl("/home")
				.and()
			.httpBasic();
//			.and().cors().configurationSource(corsConfigurationSource());
//		http.headers().frameOptions().disable();
	}
	
//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().antMatchers("/**/swagger*/**", "/**/api-docs/**");
//    }
    
//    @Configuration
//    @Order(Ordered.HIGHEST_PRECEDENCE)
//    public static class RemoteSecurityConfig extends WebSecurityConfigurerAdapter {
//    	
//        @Override
//        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        	
//    		auth.inMemoryAuthentication()
//    			.withUser("remote")
//    			.password(BCrypt.hashpw("remote", BCrypt.gensalt(4)))
//    			.roles("REMOTE");
//        }
//    	
//    	@Override
//        protected void configure(HttpSecurity http) throws Exception {
//    		
//            http
//            	.csrf()
//    		    .ignoringAntMatchers(REMOTE_LIST_URLS)
//    		    .disable()
////                .antMatcher("/*swagger*/**")
//                .authorizeRequests()
//                .antMatchers(REMOTE_LIST_URLS).hasRole("REMOTE")
//                .anyRequest().hasRole("REMOTE")
//        			.and()
//                .httpBasic();
//        }
//    	
//    }*/
	
/*    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://" + uri + ":" + port)
                .allowedMethods("*");
    }*/
	
//    @Bean
    CorsConfigurationSource corsConfigurationSource() {

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("http://" + uri +":" + port));
//		configuration.setAllowedOriginPatterns(Arrays.asList("http://" + uri +":" + port));
		configuration.setAllowedMethods(Arrays.asList("*"));
		configuration.setAllowCredentials(true);
		configuration.setExposedHeaders(Arrays.asList("*"));
//		configuration.setMaxAge(1800L);
		configuration.setAllowedHeaders(Arrays.asList("*"));
		source.registerCorsConfiguration("/**", configuration);
		return source;
    }
    
}
