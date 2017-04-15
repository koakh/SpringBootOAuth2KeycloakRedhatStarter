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

---
### [Enable HTTPS in Spring Boot](https://drissamri.be/blog/java/enable-https-in-spring-boot/)

**Step 1: Get a SSL certificate**

```
cd c:\myData\Development\IntelliJIdeaProjects\SpringBootOAuth2KeycloakRedhatStarter
keytool -genkey -alias tomcat -storetype PKCS12 -keyalg RSA -keysize 2048  -keystore keystore.p12 -validity 3650
```

! Follow error to get .p12 location path

```
[file:/C:/myData/Development/IntelliJIdeaProjects/SpringBootOAuth2KeycloakRedhatStarter/keystore.p12] due to [C:\myData\Development\IntelliJIdeaProjects\SpringBootOAuth2KeycloakRedhatStarter\keystore.p12 (O sistema não conseguiu localizar o ficheiro especificado)]
```

**Step 2: Enable HTTPS in Spring Boot**

application.yml

```yaml
server:
  #port: 8084
  port: 8443
  ssl:
    key-store: keystore.p12
    key-store-password: mypassword
    keyStoreType: PKCS12
    keyAlias: tomcat
```

**Step 3: Redirect HTTP to HTTPS (optional)**

add class

AkashifyApiServer\src\main\java\com\akashify\apiserver\ContainerConfiguration.java

```java
public class ContainerConfiguration {
  @Bean
  public EmbeddedServletContainerFactory servletContainer() {
    TomcatEmbeddedServletContainerFactory tomcat = new TomcatEmbeddedServletContainerFactory() {
      @Override
      protected void postProcessContext(Context context) {
        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.setUserConstraint("CONFIDENTIAL");
        SecurityCollection collection = new SecurityCollection();
        collection.addPattern("/*");
        securityConstraint.addCollection(collection);
        context.addConstraint(securityConstraint);
      }
    };

    tomcat.addAdditionalTomcatConnectors(initiateHttpConnector());
    return tomcat;
  }

  private Connector initiateHttpConnector() {
    Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
    connector.setScheme("http");
    connector.setPort(8080);
    connector.setSecure(false);
    connector.setRedirectPort(8443);

    return connector;
  }
}
```

try

- [http://localhost:8443](http://localhost:8443)
- [https://localhost:8443](https://localhost:8443)

Change Springboot-local client

**Root URL:**
- https://localhost:8443

**Valid Redirect URIs:**
- nl.jpelgrm.retrofit2oauthrefresh://oauth
- https://akashify.com:8443/*
- https://localhost:8443/*

**Web Origins:**
- https://localhost:8443

---
### Add to Port Firewall and Forward Port in router and test certificate 

- [Trust Anchor not found for Android SSL Connection
](http://stackoverflow.com/questions/6825226/trust-anchor-not-found-for-android-ssl-connection)

https://www.digicert.com/help/
Test
https://akashify.com:8443
https://github.com/dcm4che/dcm4chee-arc-light/wiki/Enabling-SSL-HTTPS-for-the-Keycloak-Server
https://developer.android.com/training/articles/security-ssl.html#CommonProblems

---- 
#### Curl

Getting started with Keycloak - Securing a REST Service
http://blog.keycloak.org/2015/10/getting-started-with-keycloak-securing.html

Obtain Token and Invoke Service

curl --data "grant_type=password&client_id=springboot-local&client_secret=e6526cb3-b588-44da-966e-ac0e1d7a586b&username=tom&password=password" 
http://localhost:8082/auth/realms/springboot/protocol/openid-connect/token

Now that we have the token we can invoke the secured service. To do this run:

http

https
curl https://localhost:8443/user -H "Authorization: bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJac2hmTUR...."

curl -i -H "Content-Type: application/json" -H "X-Auth-Token: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJac2hmTURSUlJYTzF6N2I2TTVnSm5JZUZ6Mk14cVZTWndnTHZIM0NWRV9VIn0.eyJqdGkiOiJjNjFmZDc4Yy1hZDU0LTRmNmEtYTNhNS1lZTgyNDg0MWExY2MiLCJleHAiOjE0OTIxOTg1MDcsIm5iZiI6MCwiaWF0IjoxNDkyMTk4MjA3LCJpc3MiOiJodHRwOi8va29ha2guY29tOjgwODIvYXV0aC9yZWFsbXMvc3ByaW5nYm9vdCIsImF1ZCI6InNwcmluZ2Jvb3QtbG9jYWwiLCJzdWIiOiIyMjcwM2Q0MC1lNDkwLTRlZGYtYTI1MS1jMDRhZDZjZDFmNmQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJzcHJpbmdib290LWxvY2FsIiwiYXV0aF90aW1lIjoxNDkyMTk4MjA3LCJzZXNzaW9uX3N0YXRlIjoiYWM0Y2NmODctYTU0Yy00MjM2LThlYWUtNjg3ZmNjZmU3OGI0IiwiYWNyIjoiMSIsImNsaWVudF9zZXNzaW9uIjoiZWEzYzVhZTAtZmZlZi00NTk2LWI1YzAtNzU4OGE5NDc2NGRmIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiJN77-977-9cmlvIE1vbnRlaXJvIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibWFyaW9hbW1vbnRlaXJvQGdtYWlsLmNvbSIsImdpdmVuX25hbWUiOiJN77-977-9cmlvIiwiZmFtaWx5X25hbWUiOiJNb250ZWlybyIsImVtYWlsIjoibWFyaW9hbW1vbnRlaXJvQGdtYWlsLmNvbSJ9.iDM-uQAgbWOO-D9BaKZnNPSxYzvDkODo5mkJa7UwI3-4JQidHEt9YyXOwsMIJYWpVCpJrAs4puOiCaoqHsg7u5NH2F2gYwTr38ljR7VFd_fABJcgMNaRxk4MhCPzrDu4wcKRFHj2M7VrZ1IWEwosAwAsP_JojuMW2Ycm0PB9T6EGMMFa_MkJEoCtQftA_vxE3-abeEPKimF_1TC7ZYtaIfjWBj_gEiI2ZRv00Uyl8HrmEMYxluIHAm-3yTYEtpbpLE-iCOy0lzY55uOgIrTB9hZOtRWMmLXShY2ZIlaca1e6cHdPswlJwz_xWaP9PQxKeSAWjZrzMz-seR3rJ38r7w" -X GET http://www.akashify.com:8084/user

curl -i -H "Content-Type: application/json" -H "X-Auth-Token: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJac2hmTURSUlJYTzF6N2I2TTVnSm5JZUZ6Mk14cVZTWndnTHZIM0NWRV9VIn0.eyJqdGkiOiJlOGQwYTg4MC1hOGNiLTQ5OTMtYTk2YS05NDYxYmFlY2YyMmQiLCJleHAiOjE0OTIxOTg3ODUsIm5iZiI6MCwiaWF0IjoxNDkyMTk4NDg1LCJpc3MiOiJodHRwOi8va29ha2guY29tOjgwODIvYXV0aC9yZWFsbXMvc3ByaW5nYm9vdCIsImF1ZCI6InNwcmluZ2Jvb3QtbG9jYWwiLCJzdWIiOiIyMjcwM2Q0MC1lNDkwLTRlZGYtYTI1MS1jMDRhZDZjZDFmNmQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJzcHJpbmdib290LWxvY2FsIiwiYXV0aF90aW1lIjoxNDkyMTk4MjA3LCJzZXNzaW9uX3N0YXRlIjoiYWM0Y2NmODctYTU0Yy00MjM2LThlYWUtNjg3ZmNjZmU3OGI0IiwiYWNyIjoiMCIsImNsaWVudF9zZXNzaW9uIjoiYzA5YzBjNzktYjg1Yy00MDA4LTg4MmUtM2FhZGQ2OGE3ZGZhIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiJN77-977-9cmlvIE1vbnRlaXJvIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibWFyaW9hbW1vbnRlaXJvQGdtYWlsLmNvbSIsImdpdmVuX25hbWUiOiJN77-977-9cmlvIiwiZmFtaWx5X25hbWUiOiJNb250ZWlybyIsImVtYWlsIjoibWFyaW9hbW1vbnRlaXJvQGdtYWlsLmNvbSJ9.MDthReroZGz5hPQKfu71aPG0hbUjY_khsrMe9XRmdn87qXQpVP5DvYx8Vz1A9958oDysQ_uQZhQOfEs4vktAba5t03JGfa3cs1oNuF4RHf-jbU8WuLCuuHNCalYQ_v0DjVmxJt_5pI91c-UVsmfV1s3TLXvDTMbTdtE83wyiJGJWGLSA6HnRETdcRQSIUvqx4avYM4dMD8ij3POgvf1x4ACNYI1Vv1__euG6EQdcnv7_fGIdDhD5nip6K6EoLHvQB6OK0461Sac0ar6Uo9EpgBKkaIx7EHtSIJnf_b_Q-xHKhL9Sd_tP5Dax3y_OCM8t97bOGfVNaTA3rHyMwvXnyQ" -X GET http://localhost:8084/user

Authentication with Spring Boot, AngularJS and Keycloak (Source in GitHub)
http://slackspace.de/articles/authentication-with-spring-boot-angularjs-and-keycloak/





OpenID Connect Discovery
GET /.well-known/openid-configuration
GET /{realm}/.well-known/openid-configuration

http://koakh.com:8082/auth/realms/springboot/.well-known/openid-configuration

go to realm and click in link: Endpoints OpenID Endpoint Configuration

Browser test login



REQUIRE CLIENT TO BE PUBLIC, to not send secret



GREAT LINK
http://stackoverflow.com/questions/33377971/oauth2-spring-security-authorization-code


Get Code
http://koakh.com:8082/auth/realms/springboot/protocol/openid-connect/auth?client_id=springboot-local&scope=no_expiry,write_access&redirect_uri=http://localhost:8084&response_type=code
Returns URL: http://localhost:8084/?code=AZ8EbRBbqyRIESqGcedXgt48qyJX6m3FGDWu2uc24QI.ed6441d0-3e4e-475b-ae9c-414bc8462494
With Code = AZ8EbRBbqyRIESqGcedXgt48qyJX6m3FGDWu2uc24QI.ed6441d0-3e4e-475b-ae9c-414bc8462494

After the login process (login: user password: password), you will be redirected to http://example.com/?code=CODE <-- this is the code that you should use in the next request

now that you get the token use it to get authorization_code

Using the code to get authorization_code

curl -X POST http://localhost:8082/auth/realms/springboot/protocol/openid-connect/token -d "grant_type=authorization_code&client_id=springboot-local&redirect_uri=http://localhost:8084&code=7PjT7wl4U8CSAyT0xmPYWUdDa7uHAzHy7WB8FnAe-3E.6197b6eb-8487-4f2f-8551-82d9f88295e8"

returns token with code

eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJac2hmTURSUlJYTzF6N2I2TTVnSm5JZUZ6Mk14cVZTWndnTHZIM0NWRV9VIn0.eyJqdGkiOiIwYjY5MTkyZS1lMjBmLTQxZGItYWQ4Mi1iZjMxNmE2ODI3OGMiLCJleHAiOjE0OTIyNzYwNDksIm5iZiI6MCwiaWF0IjoxNDkyMjc1NzQ5LCJpc3MiOiJodHRwOi8va29ha2guY29tOjgwODIvYXV0aC9yZWFsbXMvc3ByaW5nYm9vdCIsImF1ZCI6InNwcmluZ2Jvb3QtbG9jYWwiLCJzdWIiOiIzMjNiZGRmZS04ODlkLTQzODAtODM2Yy0wNjA2YTA1ZjU2ODMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJzcHJpbmdib290LWxvY2FsIiwiYXV0aF90aW1lIjoxNDkyMjc1NzM0LCJzZXNzaW9uX3N0YXRlIjoiMjIxMDllNjQtNmM3ZS00ZWYzLWE0MTQtODVjZjMwNWYwMGZlIiwiYWNyIjoiMSIsImNsaWVudF9zZXNzaW9uIjoiNjE5N2I2ZWItODQ4Ny00ZjJmLTg1NTEtODJkOWY4ODI5NWU4IiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiXSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJ2aWV3LXByb2ZpbGUiXX19LCJuYW1lIjoiVG9tIENhdCIsInByZWZlcnJlZF91c2VybmFtZSI6InRvbSIsImdpdmVuX25hbWUiOiJUb20iLCJmYW1pbHlfbmFtZSI6IkNhdCIsImVtYWlsIjoidG9tLmNhdEBleGFtcGxlLmNvbSJ9.sC33o8GHkfia184RnjYH3Sqeu2MaqjdjRhhh-OfXBMYI_p3Bh2gM9o7wRcWZY869hfcn55a7Vp3Lb5OgsYXIl5RB3GAFtjbzkdam2GpfhJ_QYVo1PR-mlPx0PcLF1sA9wryzLMdng4tAvhvm2kkjbvFiDb1cRfkldxnHqMP_n-lB24oNVZGDpbbCQA3V7C7NnChQiEorn5NZPXneIdzCsHvtkabW5h9pnMEXFaUCUZlNXTN023LrC2Y22CekHBXnWwUO8DI8YhZy1M32tAp86yPyKR6PTuZABUY3xSdEDPx2v2b2hrd8GbryggkwxSoKTCMYSvRx4d20fGOL5uSxXw






Using the password grantType
curl springboot-local:e6526cb3-b588-44da-966e-ac0e1d7a586b@koakh.com:8082/auth/realms/springboot/protocol/openid-connect/token -d grant_type=password -d username=tom -d password=password

"response_types_supported": [
"code",
"none",
"id_token",
"token",
"id_token token",
"code id_token",
"code token",
"code id_token token"
]

response_type=code returns in browser 
http://akashify.com:8084/?code=SEvZCzU5dlSTgqFgfpXVV2H2FxY5W0NeH5l_tuBtw58.154e9d1e-601e-4431-aad6-309f68e2fea6

require implicit flow enable
http://koakh.com:8082/auth/realms/springboot/protocol/openid-connect/auth?client_id=springboot-local&scope=no_expiry,write_access&redirect_uri=http://akashify.com:8084&response_type=id_token



http://stackoverflow.com/questions/33377971/oauth2-spring-security-authorization-code