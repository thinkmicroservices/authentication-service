
package com.thinkmicroservices.ri.spring.auth.service.exception;

import com.thinkmicroservices.ri.spring.auth.i18n.I18NThrowable;


/**
 *
 * @author cwoodward
 */
public class AuthenticationException extends I18NThrowable {
     /**
      * 
      * @param messageKey 
      */
    public AuthenticationException(String messageKey){
        super(messageKey);
    }
    /**
     * 
     * @param messageKey
     * @param message 
     */
    public AuthenticationException(String messageKey, String nonI18NMessage){
        super(messageKey,nonI18NMessage);
    }
}
