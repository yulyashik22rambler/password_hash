package org.password.hash.auth.service;

import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


@Service
public class RateLimitingService {

    // Хранилище лимитов по IP-адресам
    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();

    private Bucket createNewBucket() {
        return Bucket.builder()
                .addLimit(limit -> limit
                        .capacity(5) // Максимальный баланс токенов (емкость бака)
                        .refillIntervally(5, Duration.ofMinutes(1)) // Пополнение пачкой: 5 токенов строго раз в минуту
                )
                .build();
    }

    public boolean resolveBucket(String ipAddress) {
        Bucket bucket = cache.computeIfAbsent(ipAddress, k -> createNewBucket());
        return bucket.tryConsume(1);
    }
}