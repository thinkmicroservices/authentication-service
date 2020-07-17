/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.thinkmicroservices.ri.spring.auth.service;

import lombok.Builder;
import lombok.Data;

/**
 *
 * @author developer
 */
@Data
@Builder
public class AuthenticationResponse {
    private boolean success;
    private String token;
    private String errorMessage;
}
