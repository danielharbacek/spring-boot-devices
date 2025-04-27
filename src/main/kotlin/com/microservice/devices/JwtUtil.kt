package com.microservice.devices

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import java.util.*

@Component
class JwtUtil(
    @Value("\${jwt.secret}")
    private val secret: String,
) {

    fun generateToken(userDetails: UserDetails): String {
        val claims: Map<String, Any> = mapOf(
            "role" to userDetails.authorities.iterator().next().authority,
            "address" to "Albrechtice",
        )
        return createToken(claims, userDetails.username)
    }

    private fun createToken(claims: Map<String, Any>, subject: String): String {
        return Jwts.builder()
            .claims(claims)
            .subject(subject)
            .issuedAt(Date(System.currentTimeMillis()))
            .signWith(Keys.hmacShaKeyFor(secret.toByteArray()), Jwts.SIG.HS512)
            .compact()
    }

    fun validateToken(token: String?, userDetails: UserDetails): Boolean {
        return extractUsername(token) == userDetails.username
    }

    fun extractUsername(token: String?): String {
        println(extractAllClaims(token))
        return extractAllClaims(token).subject
    }

    fun extractRole(token: String?): String {
        return extractAllClaims(token).get("role", String::class.java)
    }

    private fun extractAllClaims(token: String?): Claims {
        return Jwts.parser()
            .verifyWith(Keys.hmacShaKeyFor(secret.toByteArray()))
            .build()
            .parseSignedClaims(token)
            .payload
    }
}