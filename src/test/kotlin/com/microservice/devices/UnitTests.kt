package com.microservice.devices

import com.microservice.devices.repositories.TestRepository
import com.microservice.devices.services.TestService
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.Mockito.`when`
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.bean.override.mockito.MockitoBean
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

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
