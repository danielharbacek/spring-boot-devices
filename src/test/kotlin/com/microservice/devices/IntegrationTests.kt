package com.microservice.devices

import com.microservice.devices.services.TestService
import org.junit.jupiter.api.BeforeEach
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.test.context.SpringBootTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@SpringBootTest
class IntegrationTests {

    @Value("\${spring.application.name}")
    private lateinit var appName: String

    @Autowired
    private lateinit var testService: TestService

    @BeforeEach
    fun setup() {
        // Insert records to DB
    }

    @Test
    fun testUserGroup() {
        assertTrue(testService.hasPermission(appName, "admin"))
        assertFalse(testService.hasPermission(appName, "tester"))
    }
}