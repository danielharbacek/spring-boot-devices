package com.microservice.devices

import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer.UserDetailsBuilder
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service

@Service
class CustomUserDetailsService(
) : UserDetailsService {
    override fun loadUserByUsername(username: String): UserDetails {
        return if(username == "admin") User() else throw UsernameNotFoundException(username)
    }
}

class User: UserDetails {
    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return mutableListOf(SimpleGrantedAuthority("ROLE_ADMIN"))
    }

    override fun getPassword(): String {
        return BCryptPasswordEncoder().encode("1234")
    }

    override fun getUsername(): String {
        return "admin"
    }

}