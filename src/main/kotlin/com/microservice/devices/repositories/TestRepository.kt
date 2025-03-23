package com.microservice.devices.repositories

import org.springframework.stereotype.Repository

@Repository
class TestRepository {
    fun getGroups(user: String): List<String> {
        println("TestService.getGroups($user)")
        return listOf("admin", "user")
    }
}