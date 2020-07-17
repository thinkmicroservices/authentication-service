/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.thinkmicroservices.ri.spring.auth.model;

import lombok.Builder;
import lombok.Data;

/**
 *
 * @author cwoodward
 */
@Data
 
@Builder
public class RegistrationResponse  {
   private boolean success;
    private String errorMessage;
}
