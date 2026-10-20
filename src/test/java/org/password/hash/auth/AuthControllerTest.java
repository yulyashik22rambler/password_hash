package org.password.hash.auth;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.password.hash.auth.dto.AuthRequest;
import org.password.hash.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        // Очищаем репозиторий (эмуляцию БД) перед каждым тестом,
        // чтобы тесты были изолированными и независимыми
        String testUser = "existingUser";
        if (!userRepository.exists(testUser)) {
            userRepository.save(testUser, passwordEncoder.encode("SecureP@ss123"));
        }
    }

    // --- ТЕСТЫ РЕГИСТРАЦИИ ---

    @Test
    void register_Success_WithComplexPassword() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("newUser");
        request.setPassword("StrongP@ss123"); // Соответствует всем правилам сложности

        mockMvc.perform(post("/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(content().string("User registered successfully"));
    }

    @Test
    void register_Fail_WhenPasswordIsTooSimple() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("failUser");
        request.setPassword("12345"); // Слишком короткий и простой

        mockMvc.perform(post("/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest()); // Срабатывает валидация DTO
    }

    @Test
    void register_Fail_WhenUserAlreadyExists() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("existingUser"); // Этот пользователь уже создан в setUp()
        request.setPassword("NewSecureP@ss123");

        mockMvc.perform(post("/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("User already exists"));
    }

    // --- ТЕСТЫ АУТЕНТИФИКАЦИИ ---

    @Test
    void login_Success_WithCorrectCredentials() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("existingUser");
        request.setPassword("SecureP@ss123"); // Верный пароль

        mockMvc.perform(post("/api/login")
                        .remoteAddress("192.168.1.50") // Указываем уникальный IP для этого теста
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful"));
    }

    @Test
    void login_Fail_WithWrongPassword() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("existingUser");
        request.setPassword("WrongP@ss123"); // Неверный пароль, но сложный (проходит DTO валидацию)

        mockMvc.perform(post("/api/login")
                        .remoteAddress("192.168.1.60") // Указываем другой IP
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid username or password"));
    }

    // --- ТЕСТ НА RATE LIMITING (BRUTE-FORCE) ---

    @Test
    void login_Fail_WhenRateLimitExceeded() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("existingUser");
        request.setPassword("WrongP@ss123");

        String attackIp = "10.0.0.5";

        // Делаем 5 запросов подряд с одного IP — это исчерпает лимит корзины (capacity = 5)
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/login")
                            .remoteAddress(attackIp)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized()); // Первые 5 запросов просто «неверный пароль»
        }

        // 6-й запрос с того же IP должен быть заблокирован Rate Limiter'ом
        mockMvc.perform(post("/api/login")
                        .remoteAddress(attackIp)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isTooManyRequests()) // Ожидаем HTTP 429
                .andExpect(content().string("Too many requests. Try again later."));
    }
}