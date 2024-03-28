package com.gcu;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
public class SecurityConfig {
	@SuppressWarnings("removal")
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authz) -> {
				try {
					authz
					    .requestMatchers("/", "/images/**", "/service/**").permitAll()
					    .anyRequest().authenticated()
					    .and()
					.formLogin()
						.loginPage("/login")
						.usernameParameter("username")
						.passwordParameter("password")
						.permitAll()
						.defaultSuccessUrl("/orders/display", true)
						.and()
					.logout()
						.logoutUrl("/logout")
						.invalidateHttpSession(true)
						.clearAuthentication(true)
						.permitAll()
						.logoutSuccessUrl("/");
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
            )
            .httpBasic(withDefaults());
        return http.build();
    }
	
	private Customizer<HttpBasicConfigurer<HttpSecurity>> withDefaults() {
	    return httpBasic -> httpBasic
	            .realmName("Custom Realm")
	            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
	}

	@Autowired
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
				.withUser("test").password("{noop}test").roles("USER");
	}
}
