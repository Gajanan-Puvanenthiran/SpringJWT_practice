package com.gajanan.SpringJWT.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public ResponseEntity<String> greet() {
        return ResponseEntity.ok("Hello by Everyone!");
    }

    @GetMapping("/admin_only")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> adminOnly(){
        return ResponseEntity.ok("Hello by Admin Only!");
    }
}
