package com.akashify.apiserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;


@SpringBootApplication
@EnableOAuth2Sso
@RestController
public class AkashifyApiServerApplication extends WebSecurityConfigurerAdapter {

  private static final Logger LOGGER = LoggerFactory.getLogger(AkashifyApiServerApplication.class);

  public static void main(String[] args) {
    SpringApplication.run(AkashifyApiServerApplication.class, args);
  }

  @RequestMapping(value = "/user")
  public Principal user(Principal principal) { return principal; }

  /**
   * FIXME: make this as authorized
   *
   * @param request
   * @return
   */
  @RequestMapping(value = "/appConfig", method = RequestMethod.GET)
  public
  @ResponseBody
  AppEnvironment appConfig(HttpServletRequest request) {

    LOGGER.debug("Getting Application Config");

    AppEnvironment appEnvironment = new AppEnvironment();

    String keyCloakUrl = System.getenv("KEYCLOAK_URL");
    keyCloakUrl = keyCloakUrl == null ? "http://koakh.com:8082" : keyCloakUrl;

    LOGGER.info("Using Key Cloak URL : {}", keyCloakUrl);

    appEnvironment.setKeyCloakUrl(keyCloakUrl);

    String redirectUri = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();

    appEnvironment.setRedirectUri(redirectUri);
    return appEnvironment;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .antMatcher("/**").authorizeRequests().antMatchers("/", "/appConfig", "/login/**", "/webjars/**")
        .permitAll().anyRequest()
        .authenticated().and().exceptionHandling()
        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and().logout()
        .logoutSuccessUrl("/").permitAll()
        .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    ;
  }
}
