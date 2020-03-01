/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.sibreweb30.ConfigWebSecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 *
 * @author Convidado
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private ImplementsUserDetaisService userDetailsServer;

	@Override
    protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests()
        .antMatchers(HttpMethod.GET,"/").permitAll()                  
            .antMatchers(HttpMethod.GET, "/agendas_User").permitAll()
            .antMatchers(HttpMethod.POST, "/agendas_User").permitAll()
            .antMatchers(HttpMethod.GET, "/newagenda").hasRole("ADMIN")
            .antMatchers(HttpMethod.POST, "/newagenda").hasRole("ADMIN")
            .antMatchers(HttpMethod.POST, "/agendas").hasRole("ADMIN")
            .antMatchers(HttpMethod.POST, "/agendas").hasRole("ADMIN")  
           .antMatchers(HttpMethod.GET,"/listacantina").hasRole("USER")            
           .anyRequest().authenticated()
	.and().formLogin().loginPage("/entrar").permitAll()
	.and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
   
    }

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsServer).passwordEncoder(new BCryptPasswordEncoder());
	}

}
