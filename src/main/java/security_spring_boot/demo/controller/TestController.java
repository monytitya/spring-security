package security_spring_boot.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/public")
    public String publicApi() {
        return "Public API";
    }

    @GetMapping("/user")
    public String userApi() {
        return "User API";
    }

    @GetMapping("/admin")
    public String adminApi() {
        return "Admin API";
    }
}