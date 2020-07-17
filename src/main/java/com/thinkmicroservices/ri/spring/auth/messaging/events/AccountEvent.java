/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.thinkmicroservices.ri.spring.auth.messaging.events;

 
import java.time.ZonedDateTime;
import lombok.Data;
 

/**
 *
 * @author cwoodward
 */

@Data
public abstract class AccountEvent {
   
 
    protected String accountId;
    protected String email;
   
    protected ZonedDateTime timestamp;

    public AccountEvent() {
        this(null,null);
    }
    
    public AccountEvent(String accountId,String email) {
        this(accountId,email,ZonedDateTime.now());
    }

    public AccountEvent(String accountId,String email, ZonedDateTime timestamp) {
        this.accountId=accountId;
        this.email=email;
        this.timestamp=timestamp;
    }

    
 
    
}
