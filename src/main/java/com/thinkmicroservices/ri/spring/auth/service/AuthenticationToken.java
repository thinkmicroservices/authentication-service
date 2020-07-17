/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.thinkmicroservices.ri.spring.auth.service;

import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 *
 * @author cwoodward
 */

@ToString
@EqualsAndHashCode
public class AuthenticationToken {
   private String token;
   
   public AuthenticationToken(String token){
       this.token=token;
   }
   public String getToken(){
       return token;
   }
}
