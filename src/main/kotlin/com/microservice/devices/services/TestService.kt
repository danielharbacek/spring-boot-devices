package com.microservice.devices.services

import com.microservice.devices.repositories.TestRepository
import org.springframework.stereotype.Service

@Service
class TestService(
    private val testRepository: TestRepository,
) {
    fun hasPermission(user: String, group: String): Boolean {
        return testRepository.getGroups(user).contains(group)
    }
}