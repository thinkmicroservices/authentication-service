 
package com.thinkmicroservices.ri.spring.auth.service.exception;

import com.thinkmicroservices.ri.spring.auth.i18n.I18NThrowable;

/**
 *
 * @author cwoodward
 */
public class RecoverPasswordException extends I18NThrowable {
    
     /**
     *
     * @param messageKey
     */
    public RecoverPasswordException(String messageKey) {
        super(messageKey);
    }
    
    /**
     * 
     * @param messageKey
     * @param message 
     */
    public RecoverPasswordException(String messageKey,String nonI18NMessage) {
        super(messageKey,nonI18NMessage);
    }
    
}
