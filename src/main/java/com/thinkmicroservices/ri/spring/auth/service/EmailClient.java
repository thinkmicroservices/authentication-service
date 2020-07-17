 
package com.thinkmicroservices.ri.spring.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author cwoodward
 */
@Component
@Slf4j

public class EmailClient {

    @Autowired
    private RestTemplate restTemplate;

    @Value("${email.notification.service.endpoint.url:http://NOTIFICATION-SERVICE:6005/sendEmail}")
    private String sendEmailEndpointUrl;


    /**
     * 
     * @param destinationEmail 
     */    
    public void sendRegistrationEmail(String destinationEmail){
        log.debug("sending registration email to {}", destinationEmail);
        String body = "Your account has been created." ;
       
        EmailMessage message = EmailMessage.builder().body(body)
                .destinationAddress(destinationEmail)
                .subject("Account created")
                .build();

        
        ResponseEntity<String> response = restTemplate.postForEntity(sendEmailEndpointUrl, message, String.class);
        log.debug("send email response:{}", response);
    }
    
    /**
     * 
     * @param destinationEmail
     * @param recoveryCode 
     */
    public void sendRecoveryEmail(String destinationEmail, String recoveryCode) {

        log.debug("sending recovery code:{}, to {}", recoveryCode, destinationEmail);
        String body = "Your password recovery code is: " + recoveryCode;
       
        EmailMessage message = EmailMessage.builder().body(body)
                .destinationAddress(destinationEmail)
                .subject("Password Recovery Code")
                .build();

        
        ResponseEntity<String> response = restTemplate.postForEntity(sendEmailEndpointUrl, message, String.class);
        log.debug("send email response:{}", response);
    }

}
