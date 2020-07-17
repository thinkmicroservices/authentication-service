package com.thinkmicroservices.ri.spring.auth;

import com.thinkmicroservices.ri.spring.auth.jwt.JWTAuthorizationFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 *
 * @author cwoodward
 */
@Configuration
@Slf4j
public class FilterConfig {

    protected static final String URL_PATTERN = "/*";

    /**
     *
     * @return
     */
    @Bean
    public FilterRegistrationBean<JWTAuthorizationFilter> jwtFilterRegistration() {
        FilterRegistrationBean<JWTAuthorizationFilter> filterRegistrationBean
                = new FilterRegistrationBean<>(new JWTAuthorizationFilter());

        filterRegistrationBean.addUrlPatterns(URL_PATTERN);

        log.debug("JWTFilter patterns {}", filterRegistrationBean.getUrlPatterns());
        return filterRegistrationBean;
    }

}
