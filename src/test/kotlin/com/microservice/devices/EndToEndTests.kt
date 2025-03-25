package com.microservice.devices

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.post

@SpringBootTest
@AutoConfigureMockMvc
class EndToEndTests {

    @Autowired
    private lateinit var webMvc: MockMvc

    @Test
    fun testController() {
        // val requestBody = TestDto("name", "surname")
        mockMvc.post("/test") {
            // contentType = MediaType.APPLICATION_JSON
            accept = MediaType.APPLICATION_JSON
            // content = jacksonObjectMapper().writeValueAsString(requestBody)
        }.andExpect {
            status { isOk() }
            content { contentType(MediaType.APPLICATION_JSON) }
            content { jsonPath("$.message") { value("Hello World") } }
        }
    }
}
