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

## Key components
These are the most important components of REST API application:

### Controllers
Controllers handle HTTP endpoints and generate a response.

#### Validation
Validators validate incoming HTTP requests. If request doesn't have required structure, Bad request status is returned automatically.

#### Example Controller
```kotlin
@RestController
@RequestMapping("/devices")
class DeviceController(
    private val service: DeviceService
)  {
    @PostMapping
    fun create(@Valid @RequestBody device: CreateDeviceDto): ResponseEntity<DeviceDto> {
        return ResponseEntity.ok(service.createDevice(device, "admin"))
    }
}
```

### Services
Services contain business logic.

#### Example Service
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

### Repositories
`JpaRepository` is used to manage database access.

#### Entity Graphs
Entity graphs optimize database queries by fetching specific attributes using single SQL query.

#### Pagination and sorting
TODO

#### Transactional
TODO

#### Example Repository
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

### DTOs
DTOs carry data between layers without exposing entity internals. They can also include validation annotations if used in controllers. Each annotation must start with `field:`.

#### Example DTO
```kotlin
data class CreateDeviceDto(
    @field:NotBlank(message = "Device name cannot be blank")
    val name: String,
)
```

### Entities
Entities represent database tables. They must have `@Id` and may contain database relationships and columns. Relationship's default fetch type is `FetchType.EAGER`, which means that when loading single record from database (using `findById`), relationship is automatically loaded as well.

#### Auditing
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
    class AuditorAwareImpl implements AuditorAware<String> {
        @Override
        fun getCurrentAuditor(): String = "Username"
    }
    ```

#### Example entity
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

### Mappers
Mappers map entities to DTOs and vice-versa.

#### Example Mapper
```kotlin
fun Device.toDto() = DeviceDto(
    id = this.id!!,
    name = this.name,
    modelName = this.model.modelName
)
```

### Exception handlers
Exception handlers are responsible for handling API errors.

#### Example Exception Handler
```kotlin

@RestControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(NotFoundException::class)
    fun handleNotFound(ex: NotFoundException): ResponseEntity<String> =
        ResponseEntity.status(404).body(ex.message)
}
```

### Security
TODO

### Caching
TODO

### Event handling
TODO

### Testing
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

#### Mocking
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

#### Test Driven Development
Using TDD, we first write test that fails and then write the code to make the test success. Afterward, we can refactor the code and run the test again.

#### Test Helpers
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

#### Unit tests
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

#### Integration tests
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

#### End-to-End Tests
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
