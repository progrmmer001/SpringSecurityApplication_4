package org.example.controller;

import org.example.config.beans.SessionUser;
import org.example.model.AuthUser;
import org.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@Controller
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private SessionUser sessionUser;

    @GetMapping("/login")
    public String logIn(Model model, @RequestParam(required = false) String error) {
        model.addAttribute("errormessage", error);
        return "auth";
    }

    @GetMapping("/sign")
    public String sign() {
        return "SignIn";
    }

    @PostMapping("/signIn")
    public String signIn(@ModelAttribute AuthUser authUser) {
        authUser.setRole("USER");
        AuthUser authUser1 = AuthUser.builder()
                .username(authUser.getUsername())
                .password(passwordEncoder.encode(authUser.getPassword()))
                .role("USER")
                .build();
        userRepository.save(authUser1);
        return "redirect:/auth/login";
    }

    @GetMapping("/logout")
    public String logout() {
        return "logout";
    }

    @GetMapping("/blockUser/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String blockUser(@PathVariable(name = "id") Long user_id) {
        userRepository.blocked(user_id);
        return "redirect:/auth/allUsers";
    }

    @GetMapping("/unblockUser/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String unblockUser(@PathVariable(name = "id") Long user_id) {
        userRepository.unblocked(user_id);
        return "redirect:/auth/allUsers";
    }

    @GetMapping("/allUsers")
    @PreAuthorize("hasRole('ADMIN')")
    public ModelAndView getAllUsers() {
        ModelAndView modelAndView = new ModelAndView("Admin");
        List<AuthUser> all = userRepository.getAllUsers();
        return modelAndView.addObject("users", all);
    }
}
