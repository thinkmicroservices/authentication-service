package com.thinkmicroservices.ri.spring.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import com.thinkmicroservices.ri.spring.auth.config.AuthProperties;
import com.thinkmicroservices.ri.spring.auth.service.AuthenticationService;
import java.util.logging.Level;
import javax.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.web.client.RestTemplate;

@EnableDiscoveryClient
@SpringBootApplication

@EnableConfigurationProperties(AuthProperties.class)
@Slf4j
public class AuthenticationApplication {

    @Value("${configuration.source:DEFAULT}")
    String configSource;
    @Value("${spring.application.name:NOT-SET}")
    private String serviceName;
    @Autowired
    private AuthenticationService jwtAuthenticationService;

    @Value("#{new Boolean('${admin.user.create:false}')}")
    private boolean createMissingAdminUser;

    @Value("${controller.cors.origin}")
    private String crossOriginHost;

    public static void main(String[] args) {
        SpringApplication.run(com.thinkmicroservices.ri.spring.auth.AuthenticationApplication.class, args);
        log.info("AuthenticationApplication Started!");

    }

    @PostConstruct
    private void displayInfo() {
        log.info("Service-Name:{}, configuration.source={}", serviceName, configSource);
    }

    @LoadBalanced
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void applicationReady() {
        log.info("The application is ready");
        if (createMissingAdminUser) {
            // after the authentication service has started
            // we wait the appointed period and call the
            // AuthenticationService to create a new admin user
            TaskExecutor theExecutor = new SimpleAsyncTaskExecutor();

            theExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        log.info("waiting to create admin user");
                        for (int idx = 5; idx > 0; idx--) {

                            Thread.currentThread().sleep(5000);
                        }
                        jwtAuthenticationService.createAdminUser();
                    } catch (InterruptedException ex) {
                        java.util.logging.Logger.getLogger(AuthenticationApplication.class.getName()).log(Level.SEVERE, null, ex);
                    }

                }
            });
        }
    }

}
