package org.example.authointregration.Controller;

import lombok.RequiredArgsConstructor;
import org.example.authointregration.Service.AuthOService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
@RequiredArgsConstructor
public class AuthController {
    private final AuthOService userService;
    @GetMapping
    public String home(Model model, @AuthenticationPrincipal OidcUser principal) {
        if(principal!=null) {
            model.addAttribute("profile", principal.getClaims());
        }

        return "index";
    }

    @DeleteMapping("/users/{Id}")
    public ResponseEntity<String> deleteUser(@PathVariable String Id) {
        userService.deleteUser(Id);
        return ResponseEntity.ok("User deleted successfully");
    }


    @PatchMapping("/user/{id}")
    public ResponseEntity<Map<String,Object>> updateUser(
            @PathVariable String id,
            @RequestBody Map<String,Object> updates) {

        Map<String,Object> updatedUser = userService.updateUser(id, updates);
        return ResponseEntity.ok(updatedUser);
    }



    @GetMapping("/user/email")
    public ResponseEntity<Map<String,Object>> getUserByEmail(@RequestParam String email) {
        Map<String,Object> user = userService.getUserByEmail(email);
        if(user != null){
            return ResponseEntity.ok(user);
        }
        return ResponseEntity.notFound().build();
    }
}
