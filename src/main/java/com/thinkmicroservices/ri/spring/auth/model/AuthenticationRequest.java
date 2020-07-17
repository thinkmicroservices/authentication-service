package com.thinkmicroservices.ri.spring.auth.model;


import lombok.Data;

@Data
public class AuthenticationRequest {
	private String email;
	private String password;
 

	 
}