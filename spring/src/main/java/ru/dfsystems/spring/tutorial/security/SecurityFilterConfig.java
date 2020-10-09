package ru.dfsystems.spring.tutorial.security;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityFilterConfig {

    @Bean
    public FilterRegistrationBean<SecurityFilter> filterRegistrationBean(SecurityFilter filter) {
        var registrationBean = new FilterRegistrationBean<SecurityFilter>();
        registrationBean.setName("SecurityFilter");
        registrationBean.setFilter(filter);

        registrationBean.addInitParameter("public", "/api/auth/login");
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }
}
