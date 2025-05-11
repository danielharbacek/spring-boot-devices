# Spring Boot Guide
This guide walks you through building a REST API using Spring Boot with components like Controllers, Services, Repositories, DTOs, Entities, Mappers, Exception Handlers, and Architecture patterns.

Spring Boot simplifies API development by providing embedded Tomcat web server and default configuration provide by its dependencies.

## Examples
Following github repositories offer implementation of microservices using Spring Boot.

### [Spring Boot Microservices by AlexPeti](https://github.com/AlexPeti/spring-boot-microservices)
This project demonstrates a microservices architecture using Spring Boot 3.2.4 and Java 17. It includes:
- Eureka Naming Server - For service discovery
- Spring Cloud Config Server - For centralized configuration management
- API Gateway Service - Handles routing and implements filters to ensure only authenticated users with valid JWTs access protected endpoints
- Identity Service - Manages registration, authentication, and JWT issuance and validation
- Demo Controller Microservice - A test endpoint to evaluate the effectiveness of the Gateway Service

### [Spring Boot Microservices by nihadamirov](https://github.com/nihadamirov/spring-boot-microservices)
This repository offers a set of microservices built with Spring Boot, featuring:
- Eureka Server - For service discovery and registration
- API Gateway (Zuul) - Manages routing and load balancing for incoming requests to various microservices
- Order Service - Manages order-related operations
- Product Service - Handles product-related operations
- Customer Service - Manages customer-related operations
- MongoDB - Database used by services to store data
- Mongo Express - Provides a web interface to interact with MongoDB

### [Spring Boot Microservices by DharaniDJ](https://github.com/DharaniDJ/springboot-microservices)
This repository showcases a microservices architecture with Spring Boot, featuring:
- Order and Payment Services - Integrated with Eureka for service discovery
- Spring Cloud Config Server - For centralized configuration
- ELK Stack - For centralized logging using Elasticsearch, Logstash, and Kibana
- Security Service - Implements robust security using JWT for authentication and authorization processes

## Create project
To create new project, use [Spring Boot Starter](https://start.spring.io). Common dependencies include:
- Spring Boot Actuator - monitor and manage Spring Boot application by exposing various metrics, health checks, and other operational information
- Spring Boot Data JPA - simplify the data access layer using JPA
- Database driver - use driver that JPA will use to connect to database and execute queries
- Spring Boot Validation - enables validation of user input in controllers, services, and data transfer objects
- Spring Boot Web - provides all the necessary components to create web-based applications and APIs
- Spring Boot Devtools - enhance the development experience by providing tools that make it easier to build, test, and debug applications

## Useful commands

### Run Spring Boot application
```shell
./mvnw spring-boot:run
```

### Run Spring Boot tests
```shell
./mvnw test
```

### Build JAR file
```shell
./mvnw clean package
```

### Run JAR file
```shell
java -jar target/app-name.jar
```

## Structuring Your Code
It is recommended to locate main application class (annotated with `@SpringBootApplication`) in a root package above other classes. Following shows typical layout:
```
com
 +- example
     +- myapplication
         +- MyApplication.java
         |
         +- customer
         |   +- Customer.java
         |   +- CustomerController.java
         |   +- CustomerService.java
         |   +- CustomerRepository.java
         |
         +- order
             +- Order.java
             +- OrderController.java
             +- OrderService.java
             +- OrderRepository.java
```

If our application is structured as above, all components are registered as beans.

## App Configuration
Spring Boot lets us externalize configuration so that we can work with the same application code in different environments. We can use a variety of external configuration sources including Java properties files, YAML files, environment variables, and command-line arguments. 

Spring Boot reads configuration properties from multiple sources. Spring Boot uses a very particular order that is designed to allow sensible overriding of values. Later property sources can override the values defined in earlier ones. Sources are considered in the following order:
1. Default properties (default configuration)
2. application.properties (or application.yml)
3. environment specific properties (application-dev.properties)
4. OS environment variables 
5. Java system properties 
6. Command-line arguments 
7. ... and many more

Config data files (application.yml or application.properties) are considered in the following order:
1. Application properties packaged inside jar (default application properties file)
2. Profile-specific application properties packaged inside jar (application-{profile} properties file)
3. Application properties outside packaged jar
4. Profile-specific application properties outside packaged jar

Property values can be injected directly into beans by using the `@Value` annotation:

```kotlin
@Component
class MyBean {
    // Use @Value annotation
	@Value("\${app.name}")
	private val appName: String? = null
}

// Or use Environment class to retrieve properties
@Component
class MyBean(
    private val environment: Environment,
) {
   fun getAppName(): String {
       return environment.getProperty("app.name")
   }
}
```


### Auto configuration
Thanks to `@SpringBootApplication` annotation, application is auto-configured by default, which means that, for example, if our app uses any database driver, it is automatically configured and database connection is created. We can override auto-configuration by creating our own configuration. It is generally recommended that primary source of configuration is a single `@Configuration` class. Usually the class that defines the main method is a good candidate as the primary `@Configuration`.

### Profiles
Spring Boot allows different configs for different environments (dev, test, prod, etc.) using profiles. We can specify following application properties files:
- application-dev.yml 
- application-prod.yml 
- application-test.yml

Those files specify three environments - dev, prod and test. Each environment can for example use different database. There are following ways to switch between those environments:
- In application.yml - spring.profiles.active=dev 
- As JVM arg - -Dspring.profiles.active=prod 
- As environment variable - SPRING_PROFILES_ACTIVE=prod
- In test with annotation - @ActiveProfiles("test")
- In conditional beans - @Profile("dev")

```yaml
# Activate 'dev' and 'hsqldb' profiles
spring:
  profiles:
    active: "dev,hsqldb"
```

If no profile is active, a `default` profile is enabled. The name of the `default` profile is `default`. We can also specify custom default profile:

```yaml
spring:
  profiles:
    default: "dev"
```

For example, if an application activates a profile named `prod` and uses YAML files, then both `application.yml` and `application-prod.yml` will be loaded by Spring. Profile-specific properties are loaded from the same locations as standard `application.yml`, with profile-specific files always overriding the non-specific ones.

Best practice is to specify a default profile in default `application.yml` file and then activate another profile when running jar to override default profile.

We can also load specific beans depending on active profile:

```kotlin
// Bean is loaded only if profile 'prod' is active
@Component
@Profile("prod")
class ProductionConfig
```

### Type-safe configuration properties
Using the `@Value("${property}")` annotation to inject configuration properties can sometimes be cumbersome, especially if you are working with multiple properties or your data is hierarchical in nature. Type-safe configuration properties in Spring Boot let us map configuration values directly into a Java class, making them easier to access, validate, and maintain. This approach is strongly recommended over using `@Value` for anything more than a couple of properties.

Type-safe configuration offers following advantages:
- Cleaner and more readable 
- Centralized config 
- Compile-time validation 
- Supports nested and complex objects 
- Auto-completion in IDEs (with Spring support)

Consider following configuration:

```yaml
# It is not necessary to specify every single property - only those that we want to override
my:
  service:
    remote-address: 192.168.1.1
    security:
      username: "admin"
      roles:
      - "USER"
      - "ADMIN"
```

We can load in into Java POJO class:

```kotlin
@Component
// Perform validation on properties
@Validated
// Use common prefix 'my.service'
@ConfigurationProperties("my.service")
class ServiceProperties {
   var isEnabled = false
   var remoteAddress: InetAddress? = null
   val security = Security()

   class Security {
      var username: String? = null
      var password: String? = null

      @field:NotBlank(message = "Roles must not be blank")
      var roles: List<String> = ArrayList(setOf("USER"))
   }
}

// Or use immutable object
@Component
@Validated
@ConfigurationProperties("my.service")
class MyProperties(val enabled: Boolean, val remoteAddress: InetAddress, val security: Security) {
   class Security(val username: String, val password: String, 
                  @param:DefaultValue("USER") 
                  @field:NotBlank(message = "Roles must not be blank") 
                  val roles: List<String>)

}
```

Now inject the bean into our application:
```kotlin
@Service
class ServiceHandler(
    private val properties: ServiceProperties,
)
```

## Dependency injection

### Beans
A Spring Bean is simply a Java object that is managed by the Spring IoC (Inversion of Control) container. Beans are instantiated, assembled, and managed by Spring. They are defined in Spring’s ApplicationContext (which is the container). They form the backbone of your application in Spring.

To create beans, choose one of following approaches:

```kotlin
// Annotate class with @Component annotation
@Component
class MyService

// Declare a method annotated with @Bean inside a @Configuration class
@Configuration
class AppConfig { 
    // Bean name is function's name is not specified by @Bean annotation
    @Bean
    fun myService(): MyService = MyService()
}
```

#### Instantiation of beans
By default, Spring creates an instance of each bean on application startup. This is called eager instantiation. Bean can be configured as lazy. It means that Spring will create an instance of a bean first time when something wants to use it

```kotlin
@Component
@Lazy
class LazyBean
```

#### Lifecycle of beans
Spring calls functions annotated with `@PostConstruct` as soon as a bean is created and correctly initialized. Right before it is destroyed, Spring calls functions annotated with `@PreDestroy`.

```kotlin
// Initialization code
@PostConstruct
fun init() {}

// Cleanup code
@PreDestroy
fun cleanup() {}
```

#### Bean scopes
- Singleton (default) - always use same instance of a bean
- Prototype - everytime we request for a bean, we get a new instance
- Request (web apps only) - there is one instance per HTTP request (web apps only)
- Session (web apps only) - there is one instance per HTTP session
- Application (web apps only) - there is one instance per ServletContext

```kotlin
@Component
@RequestScope
class TestService
```

#### Conditional beans
Spring allows to create a bean only if a certain condition is met.

```kotlin
@ConditionalOnProperty(name=["feature.enabled"], havingValue=true)
fun enabledFeatureBean(): Feature = Feature()
```

#### Inject values
We can also inject values from `appliation.properties` or `application.yml` files.

```kotlin
@Value("\${app.name}")
private lateinit var appName: String
```

### Autowiring
Autowiring is the process of automatically injecting dependencies into a Spring bean by type, name, or constructor.

Objects can be injected in following ways:
- @Autowired - inject bean by data type
- @Qualifier - inject bean by name

```kotlin
// @Autowired annotation is not necessary if class has only one constructor
@Component
class UserController(private val userService: UserService)
```

There are following types of autowiring:
- Constructor injection
- Field injection
- Setter injection

#### Conflicts
When multiple candidates are found for autowiring, we can use two solutions to resolve the conflicts:
- use `@Primary` annotation to indicate which bean should be preferred
- use @Qualifier to autowire a bean using bean name

```kotlin
// Bean name is 'pdfReport'
// Or use @Primary
@Component(value = "pdfReport")
class PdfReportService : ReportService

// Bean name is 'excelReport'
@Component(value = "excelReport")
class ExcelReportService : ReportService

// Inject ReportService by bean name 'pdfReport'
// If parameter name would be 'pdfReport', PdfReportService would be injected without the need for @Qualifier annotation
class ReportController(
   @Qualifier("pdfReport") private val reportService: ReportService
)
```

#### Circular dependency
Spring detects circular dependencies during the creation of beans. If constructor injection is used, Spring will throw an exception indicating a circular dependency. To resolve circular dependencies, you can use setter injection or mark one of the dependencies with `@Lazy` annotation, which tells Spring to initialize the bean lazily.

## Aspect Oriented Programming (AOP)
There are three different concepts in AOP:
- `aspect` - aspect is a piece of code that we want to be executed by Spring - usually a function
- `advice` - defines when the aspect will be executed - whether is it before or after method execution
- `pointcut` - defines which method should be intercepted by Spring to run aspect

Advice types:
- `@Before` - triggers aspect before execution of pointcut
- `@After` - triggers aspect after pointcut is executed
- `@Around` - combines both @Before and @After
- `@AfterReturning` - triggers aspect if execution of pointcut is successful (no exception is thrown)
- `@AfterThrowing` - triggers aspect whenever an exception is thrown by pointcut

Pointcut expression can contain following special symbols:
- `*` - any single name (return type, method name, class name, package name)
- `..` - zero or more packages / parameters
- `()` - method with no args
- `(..)` - method with any number and type ofÂ

Pointcut expression have general form:
```pointcutexpression
execution([modifiers] return-type declaring-type method-name(parameters) [throws-clause])
```

Examples:
```pointcutexpression
// All methods inside UserService class
execution(* com.example.service.UserService.*(..))

// All methods in a package and subpackages
execution(* com.example..*.*(..))

// Specific method
execution(* com.example.service.UserService.getUserById(..))

// All methods that start with 'set'
execution(* *.set*(..))
```

Fully working example:

```kotlin
@Aspect
@Component
class TestAspect {

    private val logger = Logger.getLogger(TestAspect::class.java.name)

    @Around("execution(* com.microservice.devices..*(..))")
    fun test(joinPoint: ProceedingJoinPoint): Any? {
        logger.info("Running test aspect")
        val result = joinPoint.proceed()
        logger.info("Called function ${joinPoint.signature.name} of ${joinPoint.target.javaClass.simpleName}")
        logger.info("Parameters: ${joinPoint.args.joinToString(",")}")
        logger.info("Returned value: $result")
        return result
    }
}
```

### Create aspect using annotation
Instead of defining pointcut directly in aspect, we can create an annotation an assign it to a method which will execute the aspect.

```kotlin
// Define annotation
annotation class LogAspect

// Create aspect
@Aspect
@Component
class TestAspect {
   @Before("@annotation(LogAspect)")
   fun annotationTest(): = println("Running annotationTest")
}

// Assign annotation to a method
@RestController
class TestController {
   @GetMapping
   @LogAspect
   fun helloWorld(@RequestParam name: String): TestDto {
      return TestDto("Hello $name")
   }
}
```

## REST Controllers
Controllers handle HTTP endpoints and generate a response. We can use following annotation that implement basic concepts:
- `@RequestMapping` - specify an URL path that the controller will handle
- `@PostMapping`, `@PutMapping`, ... - handle different HTTP methods
- `@RequestParam` - handle query parameters
- `@PathVariable` - handle parameter passed in URL
- `@RequestBody` - handle body sent in request
- `@RequestHeader` - handle value of particular header
- `@ResponseBody` - if not using @Controller instead of @RestController, tell Spring that this method returns data instead of view

`RequestEntity` and `ResponseEntity` classes are used to specify information inside HTTP request or response, such as HTTP status, headers, data and others.

```kotlin
// Methods will return JSON, rather than HTML templates
// Same as @Controller, except it expects response body instead of view to be returned
@RestController
// All methods in controller are prefixed with /devices
@RequestMapping("/devices")
class DeviceController(
   private val service: DeviceService
) {
   // Get handler with optional query parameter 'name'
   @GetMapping
   fun get(@RequestParam(required = false) name: String?): ResponseEntity<List<DeviceDto>> {
      return ResponseEntity.ok(service.getDevices(name))
   }

   // Put handler with body of type CreateDeviceDto and id from URL
   @PutMapping("/{id}")
   fun update(@Valid @RequestBody device: CreateDeviceDto, @PathVariable id: Long): ResponseEntity<DeviceDto> {
      return ResponseEntity.ok(service.updateDevice(id, device))
   }
}
```

### JSON manipulation
By default, all data returned by application is automatically transferred to JSON. We can use certain annotations to tell Spring how to serialize object into a JSON:
`@JsonProperty` - use this to set name of a property inside a JSON
`@JsonIgnore` - do not include a property in JSON
`@JsonFormat` - specify custom format for a property

```kotlin
class UserDTO (
   // Property 'id' will be in JSON as user_id
    @JsonProperty("user_id")
    val id: Long,
   
    // Property 'password' will not be part of JSON
    @JsonIgnore
    val password: String,

    // Specify how to serialize LocalDate to JSON
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yy-MM-dd")
    val birthDate: LocalDate,
)
```

#### Custom serializer
We can specify a class, that is responsible for serializing an object into JSON:

```kotlin
@JsonSerialize(using = CustomUserSerializer::class)
private val user: User? = null

class CustomUserSerializer: JsonSerializer<User> {
   override fun serialize(user: User, gen: JsonGenerator, serializers: SerializerProvider) {
      gen.writeStartObject()
      gen.writeStringField("username", user.getName())
      gen.writeEndObject()
   }
}
```

For full control, we can also return `Map<String, Object>` from a controller. Map will be converted to JSON.

### Validation
Validators validate incoming HTTP requests. If request doesn't have required structure, Bad request status is returned automatically. We can use annotation from packages `jakarta.validation.constraints` and `org.hibernate.validator.constraints`.

#### Validate Request Body

```kotlin
// Define DTO class
data class CreateDeviceDto (
   // In kotlin, validation must be prefixed with 'field:' to apply it on a field instead of setter of data class
   @field:NotBlank(message = "Device name cannot be blank")
   @field:Size(min = 3, message = "Device name is too short")
   val name: String,
)

// Add parameter with '@Valid' annotation
class DeviceController {
   @PostMapping
   fun create(@Valid @RequestBody device: CreateDeviceDto): ResponseEntity<DeviceDto> {
      return ResponseEntity.ok(service.createDevice(device))
   }
}
```

#### Validate Query Parameter
To validate a query parameter, add a constraint to controller's method parameter.

```kotlin
@GetMapping
fun helloWorld(@RequestParam @NotBlank @Size(min = 3) name: String): TestDto {
   return TestDto("Hello $name")
}
```

#### Validate Path Variable
To validate a path variable, add a constraint to controller's method parameter.

```kotlin
@GetMapping("/{name}")
fun test(@PathVariable @NotBlank @Size(min = 3) name: String): TestDto {
   return TestDto("Hello $name")
}
```

#### Custom validation
First, we need to create an annotation that will represent our custom validator:

```kotlin
// Specify custom logic for this annotation
@Constraint(validatedBy = [StartsWithCapitalValidator::class])
// Specify targets on which this annotation can be used
@Target(AnnotationTarget.VALUE_PARAMETER,AnnotationTarget.FIELD)
// Annotation will be executed at runtime, not at compile time
@Retention(AnnotationRetention.RUNTIME)
// Specify annotation class and its name 'StartsWithCapital'
annotation class StartsWithCapital(
   val message: String = "The string must start with a capital letter",
   val groups: Array<KClass<*>> = [],
   val payload: Array<KClass<out Payload>> = []
)
```

Now, we should create a validation logic class. It must be the class passed in `@Constraint` in our annotation:

```kotlin
// Specify on which type the validation goes
open class StartsWithCapitalValidator : ConstraintValidator<StartsWithCapital?, String?> {
    override fun isValid(value: String?, context: ConstraintValidatorContext): Boolean {
        return !value.isNullOrEmpty() && Character.isUpperCase(value[0])
    }
}
```

Now we can apply the validation on a `String` parameter:

```kotlin
@GetMapping("/{name}")
fun test(@PathVariable @StartsWithCapital name: String): String {
    return "Hello $name"
}
```

## Exception handlers
Exception handlers are responsible for handling API errors. We can create a handler for each exception and return custom response.

```kotlin
// Define that this class handles exceptions
@RestControllerAdvice
class GlobalExceptionHandler {

    // Handle specific exception and return custom message
    @ExceptionHandler(NotFoundException::class)
    fun handleNotFound(ex: NotFoundException): ResponseEntity<String> =
        ResponseEntity.status(404).body(ex.message)
}
```

### CORS
CORS (Cross Origin Resource Sharing) can be enabled on method level, class level or server level:

```kotlin
// Enable CORS for particular method
@CrossOrigin(origins = "http://localhost:9000")
fun handleRequest() {
   // Generate response
}

// Enable CORS for all method inside a controller class
@CrossOrigin(origins = "https://example.com", methods = { RequestMethod.GET, RequestMethod.POST })
class UserController

// Enable CORS on server level
@Configuration
class WebConfig {
   @Bean
   fun corsConfigurer(): WebMvcConfigurer {
      return object : WebMvcConfigurer {
         override fun addCorsMappings(registry: CorsRegistry) {
            registry.addMapping("/**") // Enable all endpoints
               .allowedOrigins("http://example.com") // Allow specific site
               .allowedMethods("GET", "POST") // Allow specific methods
               .allowedHeaders("*") // Allow al headers
               .allowCredentials(true) // Allow sending credentials
         }
      }
   }
}
```

## Consuming REST services
Spring application can use multiple libraries to make HTTP requests to different APIs. Old application can use deprecated RestTemplate class, which is part of `Spring Web` library. More modern approach is to use `WebClient` to make HTTP requests, or `OpenFeign` to declare an interface for each REST API and let the library do the work.

### Using WebClient
`WebClient` can be used for reactive programming, because it returns `Mono` object, which can be observed.

A dependency needs to be added:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-webflux</artifactId>
</dependency>
```

Example usage:

```kotlin
@Service
class UserService(builder: WebClient.Builder) {

   private val webClient: WebClient = builder.baseUrl("https://www.example.com/api").build()

   fun fetchUser(): Mono<User> {
      return webClient
         .get()
         .uri("/user")
         .retrieve()
         .bodyToMono(User::class.java)
   }
}

@RestController
class UserController(
    private val userService: UserService
) { 
    @GetMapping
    fun printUserEmails() {
        return userService.fetchUser().map(User::getEmail).subscribe(System.out::println)
    }
}
```

### Using OpenFeign
in OpenFeign, we define an interface and the library will generated the implementation.

First we add a dependency:

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-openfeign</artifactId>
</dependency>
```

Example:

```kotlin
@SpringBootApplication
@EnableFeignClients // Enable OpenFeign
class MyApplication

// Create Feign interface
@FeignClient(name = "users", url = "https://www.example.com/api", configuration = FeignConfig::class.java)
interface UsersApiClient {

   @GetMapping("/users")
   fun getUsers(@RequestHeader("Authorization") token: String): List<User>
}

// Call REST API
@Service
class MyService(private val usersApiClient: UsersApiClient) {
   fun printUsers(apiToken: String) {
      val users: List<User> = usersApiClient.getUsers(apiToken)
      println(users.joinToString(","))
   }
}

// Or configure api token for each request
@Configuration
class FeignConfig {
   @Bean
   fun requestInterceptor(): RequestInterceptor {
      return RequestInterceptor { it.header("Authorization", "Bearer your-token") }
   }
}
```

## Services
Services contain business logic.

```kotlin
@Service
class DeviceService(
    private val repository: DeviceRepository
) {
    fun getDevices(): List<DeviceDto> {
        return repository.findAllWithModel().map {
            it.toDto()
        }
    }
}
```

### JSON
Spring Boot provides integration with three JSON mapping libraries: `GSON`, `Jackson` (default) and `JSON-B`. Auto-configuration for Jackson is provided and Jackson is part of `spring-boot-starter-json`. When Jackson is on the classpath an `ObjectMapper` bean is automatically configured.

We can also write our own `JsonSerializer` and `JsonDeserializer` classes. Custom serializers are usually registered with Jackson through a module, but Spring Boot provides an alternative `@JsonComponent` annotation that makes it easier to directly register Spring Beans.

```kotlin
@JsonComponent
class MyJsonComponent {
   class Serializer : JsonSerializer<MyObject>() {
      @Throws(IOException::class)
      override fun serialize(value: MyObject, jgen: JsonGenerator, serializers: SerializerProvider) {
         jgen.writeStartObject()
         jgen.writeStringField("name", value.name)
         jgen.writeNumberField("age", value.age)
         jgen.writeEndObject()
      }
   }

   class Deserializer : JsonDeserializer<MyObject>() {
      @Throws(IOException::class, JsonProcessingException::class)
      override fun deserialize(jsonParser: JsonParser, ctxt: DeserializationContext): MyObject {
         val codec = jsonParser.codec
         val tree = codec.readTree<JsonNode>(jsonParser)
         val name = tree["name"].textValue()
         val age = tree["age"].intValue()
         return MyObject(name, age)
      }
   }

}
```

## Repositories
`JpaRepository` is used to manage database access.

```kotlin
@Repository
interface DeviceRepository: JpaRepository<Device, Long> {
    @EntityGraph(attributePaths = ["model"])
    @Query("SELECT d FROM Device d")
    fun findAllWithModel(): List<Device>
    // Find devices by name of model (related entity)
    @EntityGraph(attributePaths = ["model"])
    fun findDevicesByModelName(modelName: String): List<Device>
}
```

### Entity Graphs
Entity graphs optimize database queries by fetching specific attributes using single SQL query.

### Pagination
TODO

### Sorting
TODO

### Transactional
TODO

### Migrations
TODO

## DTOs
DTOs carry data between layers without exposing entity internals. They can also include validation annotations if used in controllers. Each annotation must start with `field:`.

```kotlin
data class CreateDeviceDto(
    @field:NotBlank(message = "Device name cannot be blank")
    val name: String,
)
```

### Entities
Entities represent database tables. They must have `@Id` and may contain database relationships and columns. Relationship's default fetch type is `FetchType.EAGER`, which means that when loading single record from database (using `findById`), relationship is automatically loaded as well.

### Auditing
Audit columns are used to track creation and modification of database records.

1. Enable auditing
    ```kotlin
    @Configuration
    @EnableJpaAuditing(auditorAwareRef = "auditorAwareImpl")
    class AuditConfig
    ```
2. Define auditing entity
    ```kotlin
    @MappedSuperclass
    @EntityListeners
    data class Auditable (
        @CreatedDate
        @Column(nullable = false, updatable = false)
        val createdAt: LocalDateTime,
        @CreatedBy
        @Column(nullable = false, updatable = false)
        val createdBy: String
    )
    ```
3. Extend auditable entity
4. Provide auditor implementation
    ```kotlin
    @Component
    class AuditorAwareImpl: AuditorAware<String> {
        @Override
        fun getCurrentAuditor(): String = "Username"
    }
    ```

```kotlin
@Entity
data class Device(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "model_id", referencedColumnName = "id")
    val model: Model? = null,

    @Column(nullable = false)
    val name: String,
)
```

## Mappers
Mappers map entities to DTOs and vice-versa.

```kotlin
fun Device.toDto() = DeviceDto(
    id = this.id!!,
    name = this.name,
    modelName = this.model.modelName
)
```

## Security
Spring Boot Security allows us to use authentication and authorization, protect against CSRF and XSS and implement JWT, OAuth2 or LDAP.

### Default behavior
- All HTTP endpoints are secured, requiring authentication.
- A default form-based login page is provided for user authentication.
- A default user is created with the username user and a random password printed to the console at startup.
- HTTP Basic authentication is enabled.
- CSRF protection is enabled for non-GET requests.
- Session-based authentication is used (stateful).

To customize this behavior, we need to provide a security configuration. We can use annotation `EnableWeSecurity` to configure own security rules instead of using the default security auto-configuration.

### Security Filter Chain
Spring Security uses a chain of servlet filters to handle security for incoming HTTP requests. Each filter performs a specific task, such as authentication, authorization, or CSRF protection. The filter chain is invoked before the request reaches the application's controllers.

To enable security for our application, we need to add Spring Boot Security Starter dependency. By default, all endpoints are secured even if no configuration is added. Default username is `user` and generated password is printed to console.

We can specify custom request filter and add it to security filter chain:

```kotlin
@Component
class IpFilter : OncePerRequestFilter() {
   private val blockedIps = setOf("192.168.1.100", "10.0.0.1")
   override fun doFilterInternal(
      request: HttpServletRequest,
      response: HttpServletResponse,
      filterChain: FilterChain
   ) {
      if (blockedIps.contains(request.remoteAddr)) {
         logger.warn("Blocked request from IP: $ip")
         response.sendError(HttpServletResponse.SC_FORBIDDEN, "Your IP is blocked")
         return
      }

      // Continue in handling request
      filterChain.doFilter(request, response)
   }
}

@Configuration
class SecurityConfig {
   @Bean
   fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
      return http
         .authorizeHttpRequests {
            it.requestMatchers("/api/auth/**").permitAll()
            it.anyRequest().authenticated()
         }
         // Add custom filter to filter chain
         .addFilter(IpFilter())
         .build()
   }
}
```

### Credentials validation
In Spring Security, an AuthenticationProvider is responsible for validating credentials, returning a valid Authentication object if successful and throwing exceptions if authentication fails.

Spring Security already provides built-in providers, but sometimes we need own custom logic. When someone tries to authenticate, Spring Security calls our CustomAuthenticationProvider.

```kotlin
// Define custom authentication provides
@Component
class CustomAuthenticationProvider(
    private val userDetailsService: CustomUserDetailsService,
    private val passwordEncoder: PasswordEncoder,
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication?): Authentication {
        val username = authentication?.name
        val password = authentication?.credentials?.toString()
        if (username.isNullOrBlank() || password.isNullOrBlank()) {
            throw BadCredentialsException("Username or password cannot be empty")
        }

        val userDetails = userDetailsService.loadUserByUsername(username)
        if (!passwordEncoder.matches(password, userDetails.password)) {
            throw BadCredentialsException("Invalid credentials")
        }

        return UsernamePasswordAuthenticationToken(userDetails, null, userDetails.authorities)
    }

    override fun supports(authentication: Class<*>?): Boolean {
        // Tell Spring which types of authentication this provider supports
        return UsernamePasswordAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}

// Specify authentication manager bean
@Bean
fun authenticationManager(): AuthenticationManager {
   return ProviderManager(listOf(customAuthenticationProvider))
}
```

### Authentication
If user provides credentials using any of configured authentication providers (basic auth or form login), the filter extracts them and delegates to the AuthenticationManager.

`Authentication manager` verifies credentials and returns an Authentication object if successful.

```kotlin
// Provide AuthenticationManager bean
@Bean
fun authenticationManager(authenticationConfiguration: AuthenticationConfiguration): AuthenticationManager {
    return authenticationConfiguration.authenticationManager 
}

// Authenticate user using username and password
authenticationManager.authenticate(
    UsernamePasswordAuthenticationToken(authRequest.username, authRequest.password)
)
```

### Authorization
We can configure URL-based access and method-level security in SecurityConfig.

#### URL-based access
We can protect endpoints based on roles specified in `SecurityFilterChain`:

```kotlin
@Configuration
@EnableWebSecurity
class SecurityConfig{
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .authorizeHttpRequests {
                it
                    .requestMatchers("/api/admin/**").hasRole("ADMIN")  // Protect admin routes
                    .anyRequest().authenticated()  // All other requests require authentication
            }
            .build()
    }
}
```

#### Method-level security
Method-level security allows us to secure any individual method. When a method is invoked, Spring Security intercepts the call before the method is executed. It checks the current user’s roles, permissions, or other security attributes. If the expression in `@PreAuthorize` or `@Secured` is true, the method is executed. If not, a 403 Forbidden error is thrown.

First, we need to enable method-level security:

```kotlin
// Enable method-level security in security config
@Configuration
@EnableMethodSecurity(securedEnabled = true)
class SecurityConfig
```

We can use following annotations:
- `@PreAuthorize` – Allows us to specify more complex conditions for method access.
- `@Secured` – A simpler annotation, typically used to check roles.

##### Preauthorize
`@PreAuthorize` provides a very powerful and flexible way to control access to methods using Spring Expression Language (SpEL). We can define complex expressions that check things like roles, permissions, or even user-specific data.

```kotlin
@PreAuthorize("hasRole('ADMIN')")
fun deleteUser(userId: Long) {
   // Only accessible by users with the 'ADMIN' role
}

@PreAuthorize("hasPermission(#userId, 'DELETE_USER')")
fun deleteUser(userId: Long) {
   // Only users with 'DELETE_USER' permission on the given userId can access
}

@PreAuthorize("authentication.name == #username")
fun getUserProfile(username: String) {
   // User can only access their own profile
}
```

More complex example that protects a resource owned by user:

```kotlin
@RestController
class InvoiceController(
    private val invoiceService: InvoiceService
) {

    @GetMapping("/invoices/{invoiceId}")
    // Check that authenticated user's name is same as username of invoice owner
    @PreAuthorize("authentication.name == @invoiceService.getInvoiceOwnerUsername(#invoiceId)")
    fun getInvoice(@PathVariable invoiceId: Long): Invoice {
        // Process request
    }
}
```

##### Secured
`@Secured` is simpler than `@PreAuthorize` and is used to restrict access based on roles only. It can be used on methods or classes.

```kotlin
@Secured("ROLE_ADMIN", "ROLE_MANAGER")
fun updateProduct(productId: Long) {
// Accessible by users with either 'ROLE_ADMIN' or 'ROLE_MANAGER'
}
```


### User Details Service
It defines how to load user information from your database (or other sources) when Spring Security needs it.

UserDetailsService uses `UserDetails`, which represents the authenticated user in Spring Security.

We can provide our own implementation to allow Spring to load user information when necessary.

```kotlin
@Service
class CustomUserDetailsService(
   private val userRepository: UserRepository,
) : UserDetailsService {
   override fun loadUserByUsername(username: String): UserDetails {
       // Load user from database
       val user = userRepository.findByUsername(username)
         ?: throw UsernameNotFoundException("User not found: $username")

       // Construct UserDetails object
       return User.builder()
         .username(user.username)
         .password(user.password)
         .authorities(user.roles)
         .build()
   }
}
```

### Security Context
Stores the authenticated user's details (e.g., Authentication object) during a request. The SecurityContextHolder makes this information accessible throughout the application

```kotlin
// Create Spring Security Authentication object manually and provides user details and roles
val authToken = UsernamePasswordAuthenticationToken(
     userDetails, null, userDetails.authorities
 )
// Inject the Authentication into Spring Security’s Context
SecurityContextHolder.getContext().authentication = authToken

// Now we can access authenticated user from anywhere within an app
fun extractUsername(): String {
   val auth = SecurityContextHolder.getContext().authentication
   val user = auth.principal as UserDetails
   return user.username
}
```

### Session management
Spring Security, by default, creates a session (HttpSession) when a user logs in (via form login, basic auth, etc.). The session stores the SecurityContext — meaning the authenticated user information. Future requests reuse the session, so users don’t need to re-authenticate every time.

We can disable session in security configuration:

```kotlin
@Bean
fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
   return http.authorizeHttpRequests { it.anyRequest().authenticated() }
       // Disable HTTP Session
      .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
      .build()
}
```

### CSRF
Cross-Site Request Forgery is a kind of attack where a malicious website tricks a user’s browser into sending unwanted requests to your app. When CSRF protection is enabled, every request except GET must include a special CSRF token. Spring Security checks the token against the session’s CSRF token. If the token is missing or invalid, request is rejected (403 Forbidden).

It can be disabled in security configuration:

```kotlin
@Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {   
        return http.authorizeHttpRequests { it.anyRequest().authenticated() }
            // Disable CSRF verification
            .csrf { it.disable() }
            .build()
    }
```

### Default configuration
Default configuration of Spring Security is available in class `SecurityFilterChainConfiguration`. It defines a bean that provides an instance of `SecurityFilterChain` class. It is configured to require each request to be authenticated. User can authenticate using either login form or basic authentication.

```java
@Bean
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    // Any request must be authenticated
    http.authorizeHttpRequests((requests) -> 
           ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl) requests
                   .anyRequest()).authenticated());
    // Allow form login for MVC
    http.formLogin(Customizer.withDefaults());
    // Allow basic auth for API
    http.httpBasic(Customizer.withDefaults());
    return (SecurityFilterChain)http.build();
}
```

### Custom configuration
Allow all requests:

```kotlin
@Bean
fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain { 
    return http.authorizeHttpRequests { 
        // All requests are allowed without authentication
        it.anyRequest().permitAll() 
    }
        // Allow basic authentication
        .httpBasic(Customizer.withDefaults())
        // Allow authentication using custom login page and default redirect
        .formLogin { it.loginPage("/login").defaultSuccessUrl("/dashboard").permitAll() }
        // Specify logout redirect
        .logout { it.logoutSuccessUrl("/logout").permitAll() }
        .build()
}
```

Authenticate based on url:
```kotlin
@Bean
fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
   return http.authorizeHttpRequests { 
        // Allow all requests for public url - usually static folder like images or css
        it.requestMatchers("/public/**").permitAll() 
        // Require authentication for all other requests
        .anyRequest().authenticated() 
   }
      // Allow basic authentication
      .httpBasic(Customizer.withDefaults())
      .build()
}
```

### Get access to authenticated user
There are multiple ways to access currently signed in user. We can use `SecurityContext`, `Authentication` object or inject user instance directly using `@AuthenticationPrincipal` annotation.

When using `@AuthenticationPrincipal` annotation, Spring automatically pulls the principal from `SecurityContextHolder.getContext().authentication.principal` and automatically casts it to our custom user object that implements UserDetails interface.

```kotlin
// Use Security Context
@GetMapping("/user")
fun user(): TestDto {
   return TestDto("Hello ${SecurityContextHolder.getContext().authentication.principal.name}")
}

// Use Authentication object
@GetMapping("/user")
 fun user(authentication: Authentication): TestDto {
     return TestDto("Hello ${authentication.name}")
 }

// Inject user directly (if it implements UserDetails interface
@GetMapping("/user")
fun user(@AuthenticationPrincipal user: User): TestDto {
   return TestDto("Hello ${user.username}")
}
```

### Customize unauthenticated response
If form login is enabled, Spring Security redirects the user to a login page when unauthenticated. If form login is disabled, empty response with status code 401 is returned.

We can customize the behavior by using `AuthenticationEntryPoint` interface. It is invoked when a request is made to a secured resource, but the user is not authenticated.

```kotlin
// Provide custom implementation of AuthenticationEntryPoint
@Component
class CustomAuthenticationEntryPoint(
    private val objectMapper: ObjectMapper
) : AuthenticationEntryPoint {

    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException
    ) {
        // Set content type as JSON and status as 401 Unauthorized
        response.contentType = "application/json"
        response.status = HttpServletResponse.SC_UNAUTHORIZED

        // Create a body with useful error information
        val body = mapOf(
            "error" to "Unauthorized",
            "message" to (authException.message ?: "Authentication failed"),
        )

        // Write the error body as JSON response
        response.writer.write(objectMapper.writeValueAsString(body))
    }
}

// Register AuthenticationEntryPoint in security filter chain
@Bean
fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
   return http
      .exceptionHandling {
         it.authenticationEntryPoint(customAuthenticationEntryPoint) // Use custom entry point
      }
      .authorizeHttpRequests {
         it.anyRequest().authenticated()
      }
      .build()
}
```

### Logging
We can turn on debug logs for spring boot security:

```yaml
logging:
  level:
    org:
      springframework:
        security: debug
```

## Caching
TODO

## Event handling
TODO

## Testing
To get Spring Boot specific features within tests (access to application context, config file or dependency injection), the test class must be annotated with `@SpringBootTest` annotation. By default, Spring loads default `application.yml` configuration file from `src/resources` directory, but if we created `test/resources/application.yml` file, Spring loads it by default when running tests. In test config, we usually define H2 in memory database:

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password:
  jpa:
    database-platform: org.hibernate.dialect.H2Dialect
    hibernate:
      ddl-auto: create-drop  # Creates schema on start, drops it on exit
    show-sql: true  # Enable SQL query logging
```

### Mocking
We use Mocking if we don't want to use real dependency of a class. Spring Boot provides `@MockitoBean` annotation, which creates a mock bean and injects it whenever any class asks for the dependency.

```kotlin
@SpringBootTest
class SimpleTest {

    @Autowired
    private lateinit var testService: TestService

    @MockitoBean
    private lateinit var testRepository: TestRepository

    @Test
    fun testUserGroup() {
        `when`(testRepository.getGroups("user1")).thenReturn(listOf("admin"))
        assertTrue(testService.hasPermission("user1", "admin"))
        assertFalse(testService.hasPermission("user1", "tester"))
    }
}
```

### Test Driven Development
Using TDD, we first write test that fails and then write the code to make the test success. Afterward, we can refactor the code and run the test again.

### Test Helpers
Following annotations and functions can run code before first or each test or setup test database.

```kotlin
@SpringBootTest
class TestApplication {
   @BeforeAll
   fun executeBeforeTestingStarts() {
      // Execute coe before testing starts
   }

   @AfterEach
   fun executeAfterEachTest() {
      // Execute code after each test is executed
   }

   // Run the test multiple times with difference pair of values
   @ParameterizedTest
   @CsvSource(
      "1, 1",
      "2, 4",
      "3, 9"
   )
   fun testSquares(input: Int, expected: Int) {
      // Actual test executed once for each input
   }

   // Data driven test
   @TestFactory
   fun testSquares() = listOf(
      1 to 1,
      2 to 4,
      3 to 9
   )
   .map { (input, expected) ->
      dynamicTest("when I calculate $input^2 then I get $expected") {
         // Actual test - assert
      }
   }

   // Execute SQL script before test is run
   @Sql("/setup.sql")
   @Test
   fun simpleTest() {
      // 
   }
}
```

### Unit tests
Using unit tests, we make sure that smallest pieces of code (functions, classes) works correctly.

```kotlin
@SpringBootTest
class UnitTests {

   @Value("\${spring.application.name}")
   private lateinit var appName: String

   @Autowired
   private lateinit var testService: TestService

   @MockitoBean
   private lateinit var testRepository: TestRepository

   @Test
   fun testUserGroup() {
      // Mock repository to test only service - no db calls are executed
      `when`(testRepository.getGroups(appName)).thenReturn(listOf("admin"))
      assertTrue(testService.hasPermission(appName, "admin"))
      assertFalse(testService.hasPermission(appName, "tester"))
   }
}
```

### Integration tests
Integration tests verify that multiple components work correctly together. Usually, we set up testing database with testing data. We can either insert testing data in `@BeforeEach` method and delete them in `@AfterEach` method, or we can use `@Sql(data.sql)` annotation on test method to automatically execute specified SQL queries.

```kotlin
@SpringBootTest
class IntegrationTests {

   @Value("\${spring.application.name}")
   private lateinit var appName: String

   @Autowired
   private lateinit var testService: TestService

   @Test
   fun testUserGroup() {
      assertTrue(testService.hasPermission(appName, "admin"))
      assertFalse(testService.hasPermission(appName, "tester"))
   }
}
```

### End-to-End Tests
In Spring Boot, we don't have to run whole application with web server to test controllers. Instead, there is annotation `@AutoConfigureMockMvc` that prepares application for testing a controller's methods. It works along `MockMvc` class that simulates HTTP requests without actually performing it.

```kotlin
@SpringBootTest
@AutoConfigureMockMvc
class WebMvcTests {
   @Autowired
   private lateinit var webMvc: MockMvc

   @Test
   fun testController() {
      webMvc.perform(MockMvcRequestBuilders.get("/test"))
         .andExpect(status().isOk)
         .andExpect(content().string("Hello World"))
   }
}
```

## Packaging application for production
It is easily possible to package a Spring Boot uber jar (jar containing all necessary source code and libraries) as a Docker image. However, there are various downsides to copying and running the uber jar as-is in the Docker image. Spring Boot supports several technologies for optimizing applications for deployment.

### Unpacking the executable jar
For faster startup times, it is better to extract single jar file to different layouts. It is also important when building image using Docker. Docker often only needs to change the very bottom layer and can pick others up from its cache. Libraries are extracted to `/lib` folder and application classes reference the `/lib` folder. This results in faster startup, but execution time should remain same.

```shell
# Unpack executable jar
java -Djarmode=tools -jar my-app.jar extract

# Run extracted jar in production
java -jar my-app/my-app.jar
```

### Use Class Data Sharing (CDS)
CDS is a JVM feature that can help reduce the startup time and memory footprint of Java applications. To use it, you should first perform a training run on your application in extracted form. This creates an `application.jsa` file that can be reused as long as the application is not updated. To use the cache, you need to add an extra parameter when starting the application.

```shell
# Build jar file
java -Djarmode=tools -jar my-app.jar extract --destination application

# Navigate to folder with application jar
cd application

# Create application.jsa file
java -XX:ArchiveClassesAtExit=application.jsa -Dspring.context.exit=onRefresh -jar my-app.jar

# Supply cache file when running app
java -XX:SharedArchiveFile=application.jsa -jar my-app.jar
```

### Use Ahead-of-Time (AOT) Processing
It’s beneficial for the startup time to run an application using the AOT generated initialization code. To use that, application must be build with `-Pnative` to activate the native profile. When the JAR has been built, run it with `spring.aot.enabled` system property set to `true`.

```shell
# Build jar with native profile
mvn -Pnative package

# Run app with AOT enabled
java -Dspring.aot.enabled=true -jar myapplication.jar
```

Beware that using the ahead-of-time processing has drawbacks. It implies the following restrictions:
- classpath is fixed and fully defined at build time
- beans defined in Spring application cannot change at runtime, which means that Spring `@Profile` annotation and profile-specific configuration have limitations
- properties that change if a bean is created are not supported (for example, @ConditionalOnProperty and .enabled properties)

### Docker
While it is possible to convert a Spring Boot uber jar into a Docker image with just a few lines in the Dockerfile, using the layering feature will result in an optimized image.

Here is the dockerfile that supports layering, CDS and AOT:
```dockerfile
# Perform the extraction in a separate builder container
FROM bellsoft/liberica-openjre-debian:17-cds AS builder

WORKDIR /builder

# This points to the built jar file in the target folder
ARG JAR_FILE=target/*.jar

# Copy the jar file to the working directory and rename it to application.jar
COPY ${JAR_FILE} application.jar

# Extract the jar file using an efficient layout
RUN java -Djarmode=tools -jar application.jar extract --layers --destination extracted

# This is the runtime container
FROM bellsoft/liberica-openjre-debian:17-cds

WORKDIR /application

# Copy the extracted jar contents from the builder container into the working directory in the runtime container
# Every copy step creates a new docker layer
# This allows docker to only pull the changes it really needs
COPY --from=builder /builder/extracted/dependencies/ ./
COPY --from=builder /builder/extracted/spring-boot-loader/ ./
COPY --from=builder /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder /builder/extracted/application/ ./

# Execute the CDS training run
RUN java -XX:ArchiveClassesAtExit=application.jsa -Dspring.context.exit=onRefresh -jar application.jar

# Start the application jar with CDS enabled - this is not the uber jar used by the builder
# This jar only contains application code and references to the extracted jar files
# This layout is efficient to start up and CDS friendly
# Enable AOT as well, but keep in mind that -Pnative must be use when building the package
ENTRYPOINT ["java", "-Dspring.aot.enabled=true", "-XX:SharedArchiveFile=application.jsa", "-jar", "application.jar"]
```

## Spring Boot Actuator
Spring Boot includes a number of additional features to help you monitor and manage your application when you push it to production. The spring-boot-actuator module provides all of Spring Boot’s production-ready features. The recommended way to enable the features is to add a dependency on the spring-boot-starter-actuator starter. Actuator endpoints let you monitor and interact with your application.

### Endpoints
[Here](https://docs.spring.io/spring-boot/api/rest/actuator/index.html) you can find example usage for all actuator endpoints. You can use applications like [Spring Boot Admin](https://github.com/codecentric/spring-boot-admin?tab=readme-ov-file), which add a GUI over layer of actuator endpoints.

If using Spring Security, we can permit access to all actuator endpoint:

```kotlin
@Bean
fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
    return http.authorizeHttpRequests { 
             it.requestMatchers("/actuator/**").permitAll()
            .anyRequest().authenticated() 
        }
        .build()
}
```

Here is the list of most endpoints:
- conditions - report of autoconfiguration conditions
- configprops - list of all configuration properties
- beans - list of all beans available inside Spring Context
- env - produces report of all property sources and profiles
- heapdump - download heap dump of an application
- health - reports whether application is up and running
- info - expose some extra information defined by developer
- loggers - list of packages and their loggers and log levels
- mappings - list of all HTTP request mappings
- scheduledtasks - list of all scheduled tasks
- threaddump - report of all application threads
- metrics - list of all available metrics

#### Info endpoint
We can specify info properties either using application properties file or by implementing InfoContributor interface:

#### Specify info in application properties
First we need to enable `info` property:

```yaml
management:
  info:
    env:
      enabled: true
```

Now we can for example expose application version defined in `pom.xml` file:

```yaml
info:
  app:
    name: MyApp
    version: '@project.version@'
    description: Production API
```

#### Specify info using Kotlin
Implement `InfoContributor` interface and specify `contribute` function, in which we can access to info builder and add info properties.

```kotlin
@Component
class InfoProps: InfoContributor {
    override fun contribute(builder: Info.Builder?) {
        builder?.withDetail("name", this::class.simpleName)
    }
}
```

### Endpoint access control
You can control access to each individual endpoint and expose them over HTTP or JMX. An endpoint is considered to be available when access to it is permitted and it is exposed. By default, access to all endpoints except for shutdown is unrestricted. If security dependency is added, all endpoints except `health` are secured.

```yaml
# Unrestricted access to shutdown endpoint
management:
  endpoint:
    beans:
      access: unrestricted
```

### Exposing endpoints
Only `/health` endpoint is exposed by default. To override this behavior, we must declare list of exposed endpoint separated by comma:

```yaml
management:
  endpoints:
    web:
      exposure:
        include: "beans,shutdown" # Or use '*' for exposing all endpoints
```

### Loggers
Spring Boot Actuator includes the ability to view and configure the log levels of an application at runtime.

To configure a given logger, POST a partial entity to the resource’s URI, as the following example shows:
```json
{
	"configuredLevel": "DEBUG"
}
```

### Spring Boot Admin
Spring Boot Admin is a third-party application that serves as a GUI for Spring Boot Actuator endpoints. We can create a Spring Boot Admin Server application, that will act as an storage for all Spring Boot Admin Clients. Clients will send all actuator information to configured URL of Spring Boot Admin Server. Spring Boot Admin can also be configured to use Spring Cloud Discovery.

#### Create server application
We need to create brand new Spring Boot application, specify dependencies and add configuration annotation to enable Spring Boot Admin.

```xml
<!-- Add Spring Boot Web and Spring Boot Admin Server dependencies -->
<dependency>
   <groupId>de.codecentric</groupId>
   <artifactId>spring-boot-admin-starter-server</artifactId>
   <version>3.4.5</version>
</dependency>
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

```kotlin
// Enable Spring Boot Admin Server
@EnableAdminServer
@SpringBootApplication
class DevicesApplication
```

#### Register client applications

```xml
<!-- Add Spring Boot Security and Spring Boot Admin Client dependencies -->
<dependency>
   <groupId>de.codecentric</groupId>
   <artifactId>spring-boot-admin-starter-client</artifactId>
   <version>3.4.5</version>
</dependency>
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

```yaml
spring:
  application:
    name: App name # Specify app name visible by Spring Boot Admin
  boot:
    admin:
      client:
        url: http://localhost:8080 # Specify URL of Spring Boot Admin
```

## Logging
Spring Boot supports SLF4J, Logback (default), Java Util and Log4J2. Default logging output for all logs is console. By default, Spring enables logging for levels `ERROR`, `WARN` and `INFO`.

```kotlin
val logger = LoggerFactory.getLogger(this.javaClass)
logger.info("Hello World")
```

### Debug and trace modes
`DEBUG` or `TRACE` modes can be enabled in properties file. When the debug or trace mode is enabled, a selection of core loggers (embedded container, Hibernate, and Spring Boot) are configured to output more information. Enabling the debug or trace modes does not configure an application to log all messages with `DEBUG` level.

```shell
# Run application in debug mode
java -jar application.jar --debug

# Run application in trace mode
java -jar application.jar --trace
```

```yaml
# Enable debug logging
debug: true
# Enable debug and trace logging
trace: true
```

### Change log level of application packages
We set `logging.level.root` property to change logging level of all packages within our application (including libraries and application classes).

```yaml
# Enable DEBUG level for whole application
logging:
  level:
    root: debug
```

To change logging level of particular package, we must specify full package name:

```yaml
# Enable DEBUG level for Spring Security and others
logging:
   level:
      org.springframework.web: debug
      org.hibernate: error
      org.springframework.security: debug
```

### Change log level of group of packages
We can also group certain packages for logging purposes and then set logging level for whole group:

```yaml
# Create logging group
logging:
  group:
    users: com.example.controllers.users,com.example.services.users
# Assign logging level for whole group
  level:
    users: debug
```

### File output
By default, Spring Boot logs only to the console and does not write log files. To write logs into files in addition to the console output, we need to set a `logging.file.name` or `logging.file.path` property. If both properties are set, `logging.file.path` is ignored and only `logging.file.name` is used.

```yaml
logging:
   file:
      # 'spring.log' will be created at root directory of project
      path: '.'
      # 'app.log' will be created at root directory of project
      name: 'app.log'
    
```

#### File rotation
When using Logback, log files rotate automatically when they reach 10 MB. However, it is possible to fine-tune log rotation settings using your `properties` file.

#### Structured Logging
Structured logging is a technique where the log output is written in a well-defined, often machine-readable format. Spring Boot supports structured logging and has support for the following JSON formats out of the box:
- Elastic Common Schema
- Graylog Extended Log Format
- Logstash

To enable structured logging, set the property `logging.structured.format.console` (for console output) or `logging.structured.format.file` (for file output) to the id of the format you want to use. We can also add custom static values to the JSON log using `logging.structure.json.add` property.

```yaml
logging:
  structured:
    format:
      console: logstash # Console output will be formatted using logstash structured logging
      file: logstash  # File output will be formatted using logstash structured logging
    json:
      add:
        version: 2 # Each logging statement will contain version value
```

## Spring Data REST
Spring Data REST is a Spring project that automatically exposes your JPA repositories as RESTful HTTP endpoints — without the need to manually write controller and service classes. It follows the HATEOAS (Hypermedia As The Engine Of Application State) principle, and can also serve data in the HAL (Hypertext Application Language) format. For each JPA repository method, a REST endpoint is created. This is also true for custom JPA methods and queries.

Additionally, Spring Data REST also provides `/profile` endpoint that returns list of all available endpoint and their metadata.

Add following dependency:

```xml
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-data-rest</artifactId>
</dependency>
```

Define JPA Repository:

```kotlin
@RepositoryRestResource
interface UserRepository: JpaRepository<User, Long>
````

### Configuration
We can configure base path for all REST endpoints:

```yaml
spring:
  data:
    rest:
      basePath: /api
```

Change REST path of repository:

```kotlin
@ReposutoryRestResource(path="user")
interface UserRepository: JpaRepository<User,Long>
```

Do not expose REST API for particular JPA repository:

```kotlin
@ReposutoryRestResource(exported = false)
interface UserRepository: JpaRepository<User,Long>
```

### HAL Explorer
HAL (Hypertext Application Language) is a standard for representing resources with hypermedia links. Spring Data REST uses HAL to add _links fields to JSON responses. It makes an API navigable — a REST client can follow the links. This way, an application will be easily navigable and explorable by HAL GUI application.

HAL Explorer is a browser-based GUI for navigating Spring Data REST APIs. It discovers exposed endpoints, explores linked resources and sends requests from the UI.

Add following dependency:

```xml
<dependency>
   <groupId>org.springframework.data</groupId>
   <artifactId>spring-data-rest-hal-explorer</artifactId>
</dependency>
```

## Open API Docs
TODO


## Microservices

### Spring Cloud Gateway

### Service discovery

### Config Server

### Resilience4J

### Distributed Transactions



TODO: sections 15, 16, 17, 18, 20, 23, 24, 25, 26

https://haee.udemy.com/course/spring-springboot-jpa-hibernate-zero-to-master/