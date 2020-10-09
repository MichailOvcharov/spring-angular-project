package ru.dfsystems.spring.tutorial.security;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class CookieUtils {
    public static final String LOGIN_COOKIE_NAME = "username";

    public static Cookie extractLoginCookie(HttpServletRequest request) {
        return extractCookie(request, LOGIN_COOKIE_NAME);
    }

    private static Cookie extractCookie(HttpServletRequest request, String cookieName) {
        if (request == null) {
            return null;
        }

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie: cookies){
                if (cookie.getName().equals(cookieName)){
                    return cookie;
                }
            }
        }
        return null;
    }
}
