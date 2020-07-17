/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.thinkmicroservices.ri.spring.auth.model;

import lombok.Data;

/**
 *
 * @author cwoodward
 */
@Data
public class RegistrationRequest {
    private String firstName;
    private String middleName;
    private String lastName;
    private String email;
    private String password;
    private String confirmPassword;
}
