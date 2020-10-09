package ru.dfsystems.spring.tutorial.security;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import static ru.dfsystems.spring.tutorial.security.CookieUtils.LOGIN_COOKIE_NAME;

@RestController
@RequestMapping(value = "/auth", produces = "application/json; charset=UTF-8")
@AllArgsConstructor
public class AuthController {
    private UserService userService;

    @PostMapping("/login")
    public void login(@RequestBody AuthDto authDto, HttpServletResponse response) throws UnsupportedEncodingException, java.security.NoSuchAlgorithmException {
        if (!doLogin(authDto, response)){
            throw new RuntimeException("Неверный логин или пароль");
        }
    }

    @GetMapping("/current")
    public UserDto getCurrentUser() {
        return userService.getCurrentUser();
    }

    private boolean doLogin(AuthDto authDto, HttpServletResponse response) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        if (userService.checkPassword(authDto.getLogin(), authDto.getPassword())) {
            Cookie cookie = new Cookie(LOGIN_COOKIE_NAME, authDto.getLogin());
            cookie.setMaxAge(6 * 60 * 60);
            cookie.setPath("/");
            response.addCookie(cookie);

            userService.login(authDto.getLogin());
            return true;
        }
        return false;
    }

    // TODO ДЗ logout
    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie userCookie = CookieUtils.extractLoginCookie(request);
        if (userCookie == null) return;
        userCookie.setMaxAge(0);
        userCookie.setPath("/");
        userCookie.setValue("");
        response.addCookie(userCookie);
        userService.logout();
    }
}
