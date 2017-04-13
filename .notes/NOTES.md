---
### Todo

- [ ] Keycloak using MySQL Docker 

---
### Links

- [Spring Boot and OAuth2 with Keycloak](https://developers.redhat.com/blog/2017/01/05/spring-boot-and-oauth2-with-keycloak/)

- [Keycloak Demo Server](https://github.com/kameshsampath/keycloak-demo-server/)

- [Spring Boot OAuth2 with Keycloak](https://github.com/kameshsampath/springboot-keycloak-demo)
Demo app to show how migration of https://spring.io/guides/tutorials/spring-boot-oauth2/ to use Keycloak

---
### Other Keycloak closed links

- [kameshsampath/springboot-keycloak-demo](https://github.com/kameshsampath/springboot-keycloak-demo)

- [Build a Spring Boot App with User Authentication](https://scotch.io/tutorials/build-a-spring-boot-app-with-user-authentication)

- [How to get the AccessToken of Keycloak in Spring Boot and/or Java EE](http://www.n-k.de/2016/05/how-to-get-accesstoken-from-keycloak-springboot-javaee.html)

```
mvn clean install
mvn spring-boot:run
```

Change KeyCloak URL in `main\java\org\workspace7\springboot\KeyCloakDemoApplication.java`

```java
String kyeCloakUrl = System.getenv("KEYCLOAK_URL");
kyeCloakUrl = kyeCloakUrl == null ? "http://koakh.com:8082" : kyeCloakUrl;
```

change springboot-realm.json

```json
  "id" : "sprinboot-redhat",
  "realm" : "springboot",
  "displayName" : "Spring Boot :: Demos :: RedHat",
```

import realm and users in keycloak

springboot-realm.json
springboot-users-0.json

```
mvn spring-boot:run
```

**Keycloak Demo Users**
- springboot:password
- tom:password
- jerry:password
- mickey:password
- donald:password

Test With users

login an after call api 
http://localhost:8080/user

---
### Add 3 OAUTH Providers, Facebook, Google and GitHub

**Google+**

Google+ Add redirect_uri=http://koakh.com:8082/auth/realms/springboot/broker/google/endpoint
Unexpected error when authenticating with identity provider

FIX: Activate Google+ API
https://issues.jboss.org/browse/KEYCLOAK-4731?_sscc=t
Google login didn't work because I haven't enabled Google+ API in Google API console.

**Github**

Github Add redirect_uri=http://koakh.com:8082/auth/realms/springboot/broker/github/endpoint

--- 
### Test OAuth

```
mvn spring-boot:run
```

login an after call api 
http://localhost:8080/user

---
### Convert Project to Gradle

SPRING INITIALIZR Create Project with Selected Dependencies
Web, Actuator, Websocket, HATEOAS, Rest Repositories HAL Browser, Neo4j, Security

rename src\main\resources\application.properties  to src\main\resources\application.yml

add missing dependencies

```
dependencies {
	compile('org.springframework.security.oauth:spring-security-oauth2')
}
```

add 

```yaml
server:
  port: 8084

logging:
  level:
    org.springframework.security: DEBUG
```

```
gradlew
gradlew tasks
gradlew bootRun
```

copy `AppEnvironment.java`

Change `AkashifyApiServerApplication.java` to

```java
@SpringBootApplication
@EnableOAuth2Sso
@RestController
public class AkashifyApiServerApplication extends WebSecurityConfigurerAdapter {

  private static final Logger LOGGER = LoggerFactory.getLogger(AkashifyApiServerApplication.class);

  public static void main(String[] args) {
    SpringApplication.run(AkashifyApiServerApplication.class, args);
  }


  @RequestMapping(value = "/user")
  public Principal user(Principal principal) {
    return principal;
  }

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

    String kyeCloakUrl = System.getenv("KEYCLOAK_URL");
    kyeCloakUrl = kyeCloakUrl == null ? "http://koakh.com:8082" : kyeCloakUrl;

    LOGGER.info("Using Key Cloak URL : {}", kyeCloakUrl);

    appEnvironment.setKeyCloakUrl(kyeCloakUrl);

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
        .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
  }
}
```

add to application.yml

```yaml
security:
  oauth2:
    client:
      clientId: springboot-local
      clientSecret: e6526cb3-b588-44da-966e-ac0e1d7a586b
      accessTokenUri: http://koakh.com:8082/auth/realms/springboot/protocol/openid-connect/token
      userAuthorizationUri: http://koakh.com:8082/auth/realms/springboot/protocol/openid-connect/auth
      authenticationScheme: header
      clientAuthenticationScheme: header
    resource:
      userInfoUri: http://koakh.com:8082/auth/realms/springboot/protocol/openid-connect/userinfo
```

get values form

```xml
<!-- Application properties-->
<keycloak.host>koakh.com</keycloak.host>
<keycloak.port>8082</keycloak.port>
<keycloak.realm>springboot</keycloak.realm>
<keycloak.client.id>springboot-local</keycloak.client.id>
<keycloak.client.secret>e6526cb3-b588-44da-966e-ac0e1d7a586b</keycloak.client.secret>
```

to replace vars `@keycloak.host>koakh.com@, @keycloak.port>8082@, @keycloak.realm>springboot@, @keycloak.client.id@, @keycloak.client.secret@`

---
### Build

```
gradlew build
```

---
### Add Static files and [WebJars](http://www.webjars.org/)

- [Utilizing WebJars in Spring Boot](https://spring.io/blog/2014/01/03/utilizing-webjars-in-spring-boot)

copy `index.html` to `src\main\resources\static\index.html`

change realm `@keycloak.realm@` var to `springboot`

```
'/@keycloak.realm@/protocol/openid-connect/logout' + '?redirect_uri=' + redirectUri;
```

to 

```
'/springboot/protocol/openid-connect/logout' + '?redirect_uri=' + redirectUri;
```

```
dependencies {
	compile("org.webjars:angularjs:1.4.3")
	compile("org.webjars:jquery:2.1.1")
	compile("org.webjars:bootstrap:3.2.0")
	compile("org.webjars:webjars-locator:0.32")
}
```

--- 
### Run and Test

```
gradlew build
gradlew bootRun
```

**When try to login**

KeyCloak error
WE'RE SORRY ...
Invalid parameter: redirect_uri

with `redirect_uri=http://localhost:8084/login`

config comes from [http://localhost:8084/appConfig](http://localhost:8084/appConfig)

```java
AppEnvironment appConfig(HttpServletRequest request) {
  ...
  String redirectUri = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
  ...
}
```

using localhost:8084

```json
{
"keyCloakUrl": "http://koakh.com.com:8082",
"redirectUri": "http://localhost:8084"
}
```

using akashify.com:8084

```json
{
"keyCloakUrl": "http://koakh.com.com:8082",
"redirectUri": "http://akashify.com:8084"
}
```

Add **Valid Redirect URIs** to Realm\ClientId : `Springboot\springboot-local`

`http://localhost:8084/*`
`http://akashify.com:8084/*`

Test login with KeyCloak user and 3 OAuth Users Created and the API Url

- [http://localhost:8084](http://localhost:8084)
- [http://localhost:8084/user](http://localhost:8084/user)
- [http://localhost:8084/browser/index.html](http://localhost:8084/browser/index.html)

! After login all above protected urls work, inclusive HAL Browser

Test HAL Browser with Endpoint `/user`

---
### Test JWT tokenValue in [JWT](https://jwt.io/)

```json
{
  "authorities": [
    {
      "authority": "ROLE_USER"
    }
  ],
  "details": {
    "remoteAddress": "0:0:0:0:0:0:0:1",
    "sessionId": "09CD350EBCB6D6539AAF02C3FB75EEE2",
    "tokenValue": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJac2hmTURSUlJYTzF6N2I2TTVnSm5JZUZ6Mk14cVZTWndnTHZIM0NWRV9VIn0.eyJqdGkiOiIwZmJiYzM4My01ZTU4LTRlODMtYjIyMS1kMWQ2NWNmYWJkNWQiLCJleHAiOjE0OTIxMDU5MTksIm5iZiI6MCwiaWF0IjoxNDkyMTA1NjE5LCJpc3MiOiJodHRwOi8va29ha2guY29tOjgwODIvYXV0aC9yZWFsbXMvc3ByaW5nYm9vdCIsImF1ZCI6InNwcmluZ2Jvb3QtbG9jYWwiLCJzdWIiOiIzMjNiZGRmZS04ODlkLTQzODAtODM2Yy0wNjA2YTA1ZjU2ODMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJzcHJpbmdib290LWxvY2FsIiwiYXV0aF90aW1lIjoxNDkyMTA1NjE5LCJzZXNzaW9uX3N0YXRlIjoiYzgwNzg4MGUtMjFhZC00NzEyLTlmOWEtZGM1YjJmYmJjYzgzIiwiYWNyIjoiMSIsImNsaWVudF9zZXNzaW9uIjoiOTEzZTIzMmQtMWViNC00Mzk1LTg5Y2MtZjVlNDQwNzRkMzM4IiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJdLCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiJUb20gQ2F0IiwicHJlZmVycmVkX3VzZXJuYW1lIjoidG9tIiwiZ2l2ZW5fbmFtZSI6IlRvbSIsImZhbWlseV9uYW1lIjoiQ2F0IiwiZW1haWwiOiJ0b20uY2F0QGV4YW1wbGUuY29tIn0.TCin-FeiX7Eg981W2o629JxqvFsz1tKlzwQYiwhxhoOIIFnp27aN9mBEOnHjG3FTZUK7Zb01kRoOLZSlS1LVYU7eEEHmUDymAvjzWCOKwi094HQjy23n_DUviJYoh82oLM-nGRgbFxPYcuw2QZkoj5gO5ZNSt3P0tUzCZ3krBKa0JxRJkXn0KqT8G5djkJ-Njj22TEWHVtpdgsvhUIluLes_lACa6nZsPkWjorspThJqcT7atJaGqOfnyXuPgyrwLYg3VgLOo7IG5tKxmK4O1q5h5baGYaEqYhw9j9TV2NTWUw878xisi1zZQY8aoCS8CS719MzQWz7LfbpaSCUI-A",
    "tokenType": "bearer",
    "decodedDetails": null
  },
```

header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "ZshfMDRRRXO1z7b6M5gJnIeFz2MxqVSZwgLvH3CVE_U"
}
```

payload

```json
{
  "jti": "0fbbc383-5e58-4e83-b221-d1d65cfabd5d",
  "exp": 1492105919,
  "nbf": 0,
  "iat": 1492105619,
  "iss": "http://koakh.com:8082/auth/realms/springboot",
  "aud": "springboot-local",
  "sub": "323bddfe-889d-4380-836c-0606a05f5683",
  "typ": "Bearer",
  "azp": "springboot-local",
  "auth_time": 1492105619,
  "session_state": "c807880e-21ad-4712-9f9a-dc5b2fbbcc83",
  "acr": "1",
  "client_session": "913e232d-1eb4-4395-89cc-f5e44074d338",
  "allowed-origins": [
    "http://localhost:8080"
  ],
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "view-profile"
      ]
    }
  },
  "name": "Tom Cat",
  "preferred_username": "tom",
  "given_name": "Tom",
  "family_name": "Cat",
  "email": "tom.cat@example.com"
}
```

Done Project Conversion
