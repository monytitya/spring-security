package security_spring_boot.demo.controller;

import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.RequiredArgsConstructor;
import security_spring_boot.demo.security.JwtUtil;
import security_spring_boot.demo.service.CustomUserDetailsService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final CustomUserDetailsService userService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        if (userService.validate(username, password)) {
            String role = userService.getRole(username);
            return jwtUtil.generateToken(username, role);
        }
        throw new RuntimeException("Invalid credentials");
    }
}