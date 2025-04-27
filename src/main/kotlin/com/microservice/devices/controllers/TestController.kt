package com.microservice.devices.controllers

import com.microservice.devices.JwtUtil
import com.microservice.devices.LogAspect
import com.microservice.devices.User
import com.microservice.devices.dto.TestDto
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.http.ResponseEntity
import org.springframework.security.access.annotation.Secured
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.web.bind.annotation.*


@RestController
@RequestMapping("/test")
class TestController(
    private val authenticationManager: AuthenticationManager,
    private val jwtUtil: JwtUtil,
    private val userDetailsService: UserDetailsService,
) {
    @GetMapping
    @LogAspect
    fun helloWorld(@RequestParam @NotBlank @Size(min = 3) name: String): TestDto {
        return TestDto("Hello $name")
    }

    @GetMapping("/{name}")
    fun test(@PathVariable @NotBlank @Size(min = 3) name: String): TestDto {
        return TestDto("Hello $name")
    }

    @Secured("ROLE_SUPERADMIN")
    @GetMapping("/user1")
    fun user(authentication: Authentication): TestDto {
        println((authentication.principal as User))
        return TestDto("Hello ${authentication.name}")
    }

    @GetMapping("/user2")
    fun user(@AuthenticationPrincipal user: User): TestDto {
        println(user)
        return TestDto("Hello ${user.username}")
    }

    @PostMapping("/login")
    fun login(@RequestBody authRequest: AuthRequest): ResponseEntity<*> {
        // Authenticate user
        authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(authRequest.username, authRequest.password)
        )

        // Generate JWT
        val userDetails: UserDetails = userDetailsService.loadUserByUsername(authRequest.username)
        val jwt: String = jwtUtil.generateToken(userDetails)

        return ResponseEntity.ok<Any>(AuthResponse(jwt))
    }
}

data class AuthRequest(val username: String, val password: String)
data class AuthResponse(val jwt: String)