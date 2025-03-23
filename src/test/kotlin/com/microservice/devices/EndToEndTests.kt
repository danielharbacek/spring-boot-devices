package com.microservice.devices

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest
@AutoConfigureMockMvc
class EndToEndTests {

    @Autowired
    private lateinit var webMvc: MockMvc

    @Test
    fun testController() {
        webMvc.perform(MockMvcRequestBuilders.get("/test"))
            .andExpect(status().isOk)
            .andExpect(content().string("Hello World"))
    }
}