/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.thinkmicroservices.ri.spring.auth.validator;

import com.thinkmicroservices.ri.spring.auth.config.AuthProperties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 *
 * @author developer
 */
@Component
public class Validator {

    Logger logger = LoggerFactory.getLogger(Validator.class);
    @Autowired
    private AuthProperties authProperties;

    
    private Pattern emailPattern;
    private Pattern passwordPattern;

    /**
     *
     * @param email
     * @return
     */
    public boolean isEmailValid(String email) {
        return regexMatch(emailPattern, authProperties.getEmailRegex(), email);
    }

    /**
     *
     * @param password
     * @return
     */
    public boolean isPasswordValid(String password) {
        return regexMatch(passwordPattern, authProperties.getPasswordRegex(), password);
    }

    private boolean regexMatch(Pattern pattern, String regex, String target) {
        long start = System.currentTimeMillis();

        if (pattern == null) {
            long compileStart = System.currentTimeMillis();
            pattern = Pattern.compile(regex);
            long compileEnd = System.currentTimeMillis();
            logger.info("regex compile time:" + (compileEnd - compileStart));
        }
        ;
        Matcher matcher = pattern.matcher(target);
        boolean matched = matcher.matches();
        long end = System.currentTimeMillis();
        logger.info("regex MATCH time:" + (end - start));
        return matched;
    }

}
