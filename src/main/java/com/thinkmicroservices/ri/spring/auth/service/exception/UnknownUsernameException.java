 
package com.thinkmicroservices.ri.spring.auth.service.exception;

import com.thinkmicroservices.ri.spring.auth.i18n.I18NThrowable;

/**
 *
 * @author cwoodward
 */
public class UnknownUsernameException extends AuthenticationException{
     /**
     *
     * @param messageKey
     */
    public UnknownUsernameException(String messageKey) {
        super(messageKey);
    }
    
    /**
     * 
     * @param messageKey
     * @param message 
     */
    public UnknownUsernameException(String messageKey,String nonI18NMessage) {
        super(messageKey,nonI18NMessage);
    }
    
}
