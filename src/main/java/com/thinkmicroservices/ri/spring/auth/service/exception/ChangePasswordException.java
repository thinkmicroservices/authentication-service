 
package com.thinkmicroservices.ri.spring.auth.service.exception;

import com.thinkmicroservices.ri.spring.auth.i18n.I18NThrowable;

/**
 *
 * @author cwoodward
 */
public class ChangePasswordException extends I18NThrowable {

    /**
     *
     * @param messageKey
     */
    public ChangePasswordException(String messageKey) {
        super(messageKey);
    }
    
    /**
     * 
     * @param messageKey
     * @param message 
     */
    public ChangePasswordException(String messageKey,String nonI18NMessage) {
        super(messageKey,nonI18NMessage);
    }
    
    
}
