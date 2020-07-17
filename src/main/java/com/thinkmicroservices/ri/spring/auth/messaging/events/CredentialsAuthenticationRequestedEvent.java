/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.thinkmicroservices.ri.spring.auth.messaging.events;

import lombok.Data;

/**
 *
 * @author cwoodward
 */
@Data
public class CredentialsAuthenticationRequestedEvent extends AccountEvent {

    private boolean authenticated = false;

    public CredentialsAuthenticationRequestedEvent(String accountId,String email) {
        this(accountId,email, false);
    }

    public CredentialsAuthenticationRequestedEvent(String accountId,String email, boolean authenticated) {
        super(accountId,email);

        this.authenticated = authenticated;
    }

}
