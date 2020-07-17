package com.thinkmicroservices.ri.spring.auth.config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import javax.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
 
import org.springframework.stereotype.Component;

 
@Component
@Qualifier("AuthProperties")
@ConfigurationProperties(prefix="authentication")
 
public class AuthProperties {
     private static  Logger logger = LoggerFactory.getLogger(AuthProperties.class);
     @Value("${recovery.code.interval.minutes:5}")
    long recoveryCodeExpirationIntervalMinutes=5;
     @Value("${authentication.mode:USERNAME}")
     
     private String issuer="thinkmicroservices.com";
    

     
    

/*

courtesy of: https://howtodoinjava.com/regex/java-regex-validate-the-minmax-length-of-input-text/
   1) a-z,A-Z,0-9 characters allowed
   2) minimum of 6 character
   3) maximum of 20 characters
 

*/
    @Value("${authentication.regex.username:^[A-Za-z0-9]{6,20}$}")
    private String usernameRegex;//="^[A-Za-z0-9]{6,20}$";
    /*
	courtesy of: https://howtodoinjava.com/regex/java-regex-validate-email-address/

	1) A-Z characters allowed
	2) a-z characters allowed
	3) 0-9 numbers allowed
	4) Additionally email may contain only dot(.), dash(-) and underscore(_)
	5) Rest all characters are not allowed

    */
     @Value("${authentication.regex.email:^[A-Za-z0-9+_.-]+@(.+)$}")
    private String emailRegex;//="^[A-Za-z0-9+_.-]+@(.+)$";

    /*
    courtesy of: https://howtodoinjava.com/regex/how-to-build-regex-based-password-validator-in-java/

    (?=.*[a-z])     : This matches the presence of at least one lowercase letter.
    (?=.*d)         : This matches the presence of at least one digit i.e. 0-9.  
    (?=.*[@-_#$%]) 	: This matches the presence of at least one special character.
    ((?=.*[A-Z])    : This matches the presence of at least one capital letter.
    {6,16}          : This limits the length of password from minimum 6 letters to maximum 16 letters.
    */
     @Value("${authentication.regex.password:((?=.*[a-z])(?=.*d)(?=.*[@-_#$%])(?=.*[A-Z]).{6,16})}")
    private String passwordRegex;//="((?=.*[a-z])(?=.*d)(?=.*[@#$%])(?=.*[A-Z]).{6,16})";

    

    /**
     * @return the usernameRegex
     */
    public String getUsernameRegex() {
        return usernameRegex;
    }

    /**
     * @param usernameRegex the usernameRegex to set
     */
    public void setUsernameRegex(String usernameRegex) {
        this.usernameRegex = usernameRegex;
    }

    /**
     * @return the emailRegex
     */
    public String getEmailRegex() {
        return emailRegex;
    }

    /**
     * @param emailRegex the emailRegex to set
     */
    public void setEmailRegex(String emailRegex) {
        this.emailRegex = emailRegex;
    }

    /**
     * @return the passwordRegex
     */
    public String getPasswordRegex() {
        return passwordRegex;
    }

    /**
     * @param passwordRegex the passwordRegex to set
     */
    public void setPasswordRegex(String passwordRegex) {
        this.passwordRegex = passwordRegex;
    }

    

    public String toString(){
        return "AuthenticationConfiguration={"+
             
                "usernameRegex="+usernameRegex+
                "passwordRegex="+passwordRegex+
                "emailRegex="+emailRegex+
                
                "}";
    }
   
    @PostConstruct
  public void init(){
    logger.info("authentication properties=>"+this.toString());
  }
 
     
}