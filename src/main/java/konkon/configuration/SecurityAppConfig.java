package konkon.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

@Configuration
@EnableWebSecurity
public class SecurityAppConfig extends WebSecurityConfigurerAdapter {
  @Autowired
  CustomSuccessHandler customSuccessHandler;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication().withUser("dba").password("12345").roles("DBA","ADMIN");
    auth.inMemoryAuthentication().withUser("admin").password("12345").roles("ADMIN");
    auth.inMemoryAuthentication().withUser("user").password("12345").roles("USER");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
            .antMatchers("/","/home").access("hasRole('USER')")
            .antMatchers("/dba/**").access("hasRole('DBA')  and hasRole('DBA')")
            .antMatchers("/admin/**").access("hasRole('ADMIN') ")
            .and().formLogin().successHandler(customSuccessHandler)
            .usernameParameter("ssoId").passwordParameter("password")
            .and().csrf()
            .and().exceptionHandling().accessDeniedPage("/Access_Denied");
  }

/* @Autowired
  public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication().withUser("bill").password("abc123").roles("USER");
    auth.inMemoryAuthentication().withUser("admin").password("root123").roles("ADMIN");
    auth.inMemoryAuthentication().withUser("dba").password("root123").roles("ADMIN","DBA");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
            .antMatchers("/", "/home").access("hasRole('USER')")
            .antMatchers("/admin/**").access("hasRole('ADMIN')")
            .antMatchers("/dba/**").access("hasRole('ADMIN') and hasRole('DBA')")
            .and().formLogin().successHandler(customSuccessHandler)
            .usernameParameter("ssoId").passwordParameter("password")
            .and().csrf()
            .and().exceptionHandling().accessDeniedPage("/Access_Denied");
  }*/
}
