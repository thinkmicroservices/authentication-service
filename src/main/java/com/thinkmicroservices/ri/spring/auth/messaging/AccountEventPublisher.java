 
package com.thinkmicroservices.ri.spring.auth.messaging;

import org.springframework.cloud.stream.annotation.EnableBinding;

/**
 *
 * @author cwoodward
 */
@EnableBinding(AccountEventSource.class)
public class AccountEventPublisher {
    
}
