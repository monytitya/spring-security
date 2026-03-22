package security_spring_boot.demo.service;

import java.util.Map;

import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService {
    public Map<String, String> users = Map.of(
            "admin", "ROLE_ADMIN",
            "user", "ROLE_USER");

    public boolean validate(String username, String password) {
        return users.containsKey(username) && password.equals("1234");
    }

    public String getRole(String username) {
        return users.get(username);
    }
}