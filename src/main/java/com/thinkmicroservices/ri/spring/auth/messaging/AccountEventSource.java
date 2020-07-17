 
package com.thinkmicroservices.ri.spring.auth.messaging;

import org.springframework.cloud.stream.annotation.Output;
import org.springframework.messaging.MessageChannel;

/**
 *
 * @author cwoodward
 */
public interface AccountEventSource {
    String OUTPUT ="accountEventChannel";
    
    @Output(OUTPUT)
    MessageChannel accountEvents();
}
