package org.password.hash.auth.repository;


import org.springframework.stereotype.Repository;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class UserRepository {
    // Хранит Username -> Хэшированный пароль
    private final Map<String, String> database = new ConcurrentHashMap<>();

    public boolean exists(String username) {
        return database.containsKey(username);
    }

    public void save(String username, String hashedPassword) {
        database.put(username, hashedPassword);
    }

    public String findPasswordHash(String username) {
        return database.get(username);
    }
}