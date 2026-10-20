package org.password.hash.auth.controller;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.password.hash.auth.dto.AuthRequest;
import org.password.hash.auth.repository.UserRepository;
import org.password.hash.auth.service.RateLimitingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RateLimitingService rateLimitingService;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, RateLimitingService rateLimitingService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rateLimitingService = rateLimitingService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody AuthRequest request) {
        // Безопасность: Логируем только факт попытки без raw-пароля
        logger.info("Registration attempt for user: {}", request.getUsername());

        if (userRepository.exists(request.getUsername())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User already exists");
        }

        // Хэширование с автоматическим наложением соли внутри BCrypt
        String hashedPassword = passwordEncoder.encode(request.getPassword());
        userRepository.save(request.getUsername(), hashedPassword);

        logger.info("User {} successfully registered", request.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody AuthRequest request, HttpServletRequest httpRequest) {
        String ip = httpRequest.getRemoteAddr();

        // Rate Limiting проверка для защиты от Brute-Force
        if (!rateLimitingService.resolveBucket(ip)) {
            logger.warn("Rate limit exceeded for IP: {} attempting to login as {}", ip, request.getUsername());
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("Too many requests. Try again later.");
        }

        logger.info("Login attempt for user: {}", request.getUsername());

        String storedHash = userRepository.findPasswordHash(request.getUsername());

        // Безопасное сравнение хэшей (защита от атак по времени)
        if (storedHash == null || !passwordEncoder.matches(request.getPassword(), storedHash)) {
            logger.warn("Failed login attempt for user: {}", request.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }

        logger.info("User {} successfully authenticated", request.getUsername());
        return ResponseEntity.ok("Login successful");
    }
}