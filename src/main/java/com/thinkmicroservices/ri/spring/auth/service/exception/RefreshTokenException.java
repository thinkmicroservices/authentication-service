 
package com.thinkmicroservices.ri.spring.auth.service.exception;

import com.thinkmicroservices.ri.spring.auth.i18n.I18NThrowable;

/**
 *
 * @author cwoodward
 */
public class RefreshTokenException extends I18NThrowable {

    /**
     *
     * @param messageKey
     */
    public RefreshTokenException(String messageKey) {
        super(messageKey);
    }
    
    /**
     * 
     * @param messageKey
     * @param message 
     */
    public RefreshTokenException(String messageKey,String nonI18NMessage) {
        super(messageKey,nonI18NMessage);
    }
    
    
}
