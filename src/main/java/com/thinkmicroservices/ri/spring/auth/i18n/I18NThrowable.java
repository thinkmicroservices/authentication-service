package com.thinkmicroservices.ri.spring.auth.i18n;

import com.thinkmicroservices.ri.spring.auth.i18n.I18NResourceBundle;

/**
 * We extend throwable to create an internationalizable exception that contains
 * the messageKey
 *
 * @author cwoodward
 */
abstract public class I18NThrowable extends Throwable {

    private static final String SEPARATOR = " : ";
    protected String messageKey;

    /**
     *
     * @param messageKey - the resource bundle message key that will be
     * internationalized.
     * @param nonI18NMessage - this text will not be internationalized.
     */
    public I18NThrowable(String messageKey, String nonI18NMessage) {
        super(nonI18NMessage);
        this.messageKey = messageKey;
    }

    /**
     *
     * @param messageKey - the resource bundle message key that will be
     * internationalized.
     */
    public I18NThrowable(String messageKey) {
        super("-");
        this.messageKey = messageKey;
    }

    /**
     *
     * @return
     */
    public String getI18NMessage() {

        // if no message key is present return the non-i18n message
        if (messageKey == null) {
            return this.getMessage();
        }

        if (this.getMessage() == null) {
            
            // return the internationalized message concatenated with the non-internationalized message value.
            return I18NResourceBundle.translateForLocale(messageKey) + SEPARATOR + this.getMessage();
        } else {

            // return just the internationalized message
            return I18NResourceBundle.translateForLocale(messageKey);
        }
    }
}
