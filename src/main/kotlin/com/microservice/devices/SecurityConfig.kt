package com.microservice.devices

import org.springframework.boot.actuate.audit.AuditEventRepository
import org.springframework.boot.actuate.audit.InMemoryAuditEventRepository
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter


@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
class SecurityConfig(
    private val jwtUtil: JwtUtil,
    private val userDetailsService: CustomUserDetailsService
) {
//    @Bean
//    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
//        return http.authorizeHttpRequests {
//                it.requestMatchers("/login").permitAll()
//                .requestMatchers(HttpMethod.POST, "/test/login").permitAll()
//                .requestMatchers("/actuator/**").permitAll()
//                .anyRequest().authenticated()
//            }
//            .csrf { it.disable() }
//            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
//            .addFilterBefore(JwtAuthenticationFilter(jwtUtil, userDetailsService), UsernamePasswordAuthenticationFilter::class.java)
//            .build()
//    }

    @Bean
    fun auditEventRepository(): AuditEventRepository {
        return InMemoryAuditEventRepository()
    }

    @Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http.authorizeHttpRequests {
            it.requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/test/**").permitAll()
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated()
        }
            .addFilterBefore(JwtAuthenticationFilter(jwtUtil, userDetailsService), UsernamePasswordAuthenticationFilter::class.java)
            .build()
    }

    @Bean
    fun authenticationManager(authenticationConfiguration: AuthenticationConfiguration): AuthenticationManager {
        return authenticationConfiguration.authenticationManager
    }
}