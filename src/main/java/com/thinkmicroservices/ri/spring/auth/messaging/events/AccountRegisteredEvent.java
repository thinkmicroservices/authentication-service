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
public class AccountRegisteredEvent extends AccountEvent {

    private String firstName;
    private String middleName;
    private String lastName;
    public AccountRegisteredEvent(String accountId,String email) {
        super(accountId,email);
    }
    public AccountRegisteredEvent(String accountId,String email,String firstName, String middleName, String lastName) {
        super(accountId,email);
        this.firstName=firstName;
        this.middleName=middleName;
        this.lastName=lastName;
    }

}
