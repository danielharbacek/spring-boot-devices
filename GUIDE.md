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

## Key components
These are the most important components of REST API application:
### Controllers
Controllers handle HTTP endpoints and generate a response.

#### Validation
Validators validate incoming HTTP requests. If request doesn't have required structure, Bad request status is returned automatically.

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

```kotlin
data class CreateDeviceDto(
    @field:NotBlank(message = "Device name cannot be blank")
    val name: String,
)
```

### Entities
Entities represent database tables. They must have `@Id` and may contain database relationships and columns. Relationship's default fetch type is `FetchType.EAGER`, which means that when loading single record from database (using `findById`), relationship is automatically loaded as well.

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

```kotlin
fun Device.toDto() = DeviceDto(
    id = this.id!!,
    name = this.name,
    modelName = this.model.modelName
)
```

### Exception handlers
Exception handlers are responsible for handling API errors.

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

### Test Driven Development
TODO
