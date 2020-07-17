package com.thinkmicroservices.ri.spring.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;

import com.thinkmicroservices.ri.spring.auth.model.AuthenticationRequest;
import com.thinkmicroservices.ri.spring.auth.service.AuthenticationService;
import com.thinkmicroservices.ri.spring.auth.service.AuthenticationResponse;
import com.thinkmicroservices.ri.spring.auth.model.ChangePasswordRequest;
import com.thinkmicroservices.ri.spring.auth.model.ChangePasswordResponse;
import com.thinkmicroservices.ri.spring.auth.model.RecoverPasswordRequest;
import com.thinkmicroservices.ri.spring.auth.model.RecoveryCodeDTO;
import com.thinkmicroservices.ri.spring.auth.model.RegistrationRequest;
import com.thinkmicroservices.ri.spring.auth.model.RegistrationResponse;
import com.thinkmicroservices.ri.spring.auth.model.ResetPasswordRequest;
import com.thinkmicroservices.ri.spring.auth.model.ResetPasswordResponse;
import com.thinkmicroservices.ri.spring.auth.service.AuthenticationToken;
import com.thinkmicroservices.ri.spring.auth.validator.Validator;
import com.thinkmicroservices.ri.spring.auth.service.exception.ChangePasswordException;
import com.thinkmicroservices.ri.spring.auth.jwt.JWT;
import com.thinkmicroservices.ri.spring.auth.jwt.JWTService;
import com.thinkmicroservices.ri.spring.auth.service.exception.AuthenticationException;
import com.thinkmicroservices.ri.spring.auth.service.exception.RecoverPasswordException;
import com.thinkmicroservices.ri.spring.auth.service.exception.RefreshTokenException;
import com.thinkmicroservices.ri.spring.auth.service.exception.RegistrationException;
import com.thinkmicroservices.ri.spring.auth.service.exception.ResetPasswordException;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

/**
 *
 * @author cwoodward
 */
@RestController

@Slf4j

public class AuthenticationController {

    @Value("${useEmailAsUsername:true}")

    private boolean useEmailAsUsername;

    @Autowired
    private Validator validator;

     @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private JWTService jwtService;

    /**
     *
     * NO ROLES REQUIRED
     *
     * @param authenticationRequest
     * @return
     * @throws Exception
     */
    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)

    public ResponseEntity<?> authentication(
            @RequestBody AuthenticationRequest authenticationRequest) throws Exception {

        log.debug("authentication request=>" + authenticationRequest);

        try {
            AuthenticationToken token = authenticationService.authenticate(authenticationRequest.getEmail(), authenticationRequest.getPassword());

            return ResponseEntity.ok(AuthenticationResponse.builder()
                    .success(true)
                    .token(token.getToken())
                    .build()
            );

        } catch (AuthenticationException ex) {

            return new ResponseEntity<>(AuthenticationResponse.builder()
                    .success(false)
                    .errorMessage(ex.getI18NMessage())
                    .build(),
                    HttpStatus.UNAUTHORIZED);

        }

    }

    /**
     * NO ROLES REQUIRED
     *
     * @param refreshToken
     * @return
     */
    @RequestMapping(value = "/refreshToken/{refreshToken}", method = RequestMethod.GET)
    public ResponseEntity<?> refreshToken(@PathVariable String refreshToken) {
        log.debug("refresh token=>" + refreshToken);

        try {
            AuthenticationToken token = authenticationService.refreshToken(refreshToken);

            return ResponseEntity.ok(AuthenticationResponse.builder()
                    .success(true)
                    .token(token.getToken())
                    .build()
            );

            //return ResponseEntity.ok(refreshToken);
        } catch (RefreshTokenException ex) {

            return new ResponseEntity<>(AuthenticationResponse.builder()
                    .success(false)
                    .errorMessage(ex.getI18NMessage())
                    .build(),
                    HttpStatus.UNAUTHORIZED);

        }
    }

    /**
     * NO ROLES REQUIRED
     *
     * @param registrationRequest
     * @return
     * @throws Exception
     */
    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity<?> registerUser(@RequestBody RegistrationRequest registrationRequest) throws Exception {

        log.debug("creating user:" + registrationRequest);
        try {
            this.authenticationService.registerUser(registrationRequest.getEmail(),
                    registrationRequest.getFirstName(),
                    registrationRequest.getMiddleName(),
                    registrationRequest.getLastName(),
                    registrationRequest.getPassword(),
                    registrationRequest.getConfirmPassword());
            return new ResponseEntity<>(RegistrationResponse.builder().success(true).build(), HttpStatus.OK);
        } catch (RegistrationException rex) {
            log.error(rex.getMessage());
            return new ResponseEntity<>(RegistrationResponse.builder().success(false)
                    .errorMessage(rex.getI18NMessage()).build(), HttpStatus.UNPROCESSABLE_ENTITY);
        }

    }

    /**
     * USER ROLE REQUIRED
     *
     * @param changePassword
     * @return
     */
    @RequestMapping(value = "/changePassword", method = RequestMethod.POST)
    @ApiImplicitParams({
        @ApiImplicitParam(name = "Authorization", value = "Authorization token",
                required = true, dataType = "string", paramType = "header")})
    public ResponseEntity<ChangePasswordResponse> changePassword(@RequestBody ChangePasswordRequest changePassword, HttpServletRequest httpRequest
    ) {

        JWT jwt = (JWT) httpRequest.getAttribute("JWT");
        if (jwt != null) {

            String accountId = jwt.getAccountId();

            try {

                authenticationService.changePassword(accountId, changePassword.getCurrentPassword(), changePassword.getNewPassword(), changePassword.getConfirmPassword());
                return new ResponseEntity<>(ChangePasswordResponse.builder().success(true).build(), HttpStatus.OK);
            } catch (ChangePasswordException cpex) {
                log.warn(cpex.getMessage());
                return new ResponseEntity<>(ChangePasswordResponse.builder().success(false)
                        .errorMessage(cpex.getI18NMessage()).build(), HttpStatus.UNPROCESSABLE_ENTITY);

            }
        }

        return new ResponseEntity<>(ChangePasswordResponse.builder().success(false)
                .errorMessage("no bearer token in header").build(), HttpStatus.UNAUTHORIZED);

    }

    /**
     * NO ROLES REQUIRED
     *
     * @param recoverPassword
     * @return
     */
    @RequestMapping(value = "/recoverPassword", method = RequestMethod.POST)
    public ResponseEntity<?> recoverPassword(@RequestBody RecoverPasswordRequest recoverPassword) {

        log.debug("recover Password:" + recoverPassword);
        RecoveryCodeDTO recoveryCodeDTO = new RecoveryCodeDTO();
        recoveryCodeDTO.setEmail(recoverPassword.getEmail());
        try {

            String recoveryCodeString = authenticationService.recoverPassword(recoverPassword.getEmail());

        } catch (RecoverPasswordException rpex) {

            return ResponseEntity.status(HttpStatus.PRECONDITION_FAILED)
                    .body(rpex.getI18NMessage());

        }

        return ResponseEntity.ok(recoveryCodeDTO);
    }

    /**
     * USER ROLE REQUIRED
     *
     * @param resetPasswordRequest
     * @return
     */
    @RequestMapping(value = "/resetPassword", method = RequestMethod.POST)
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest) {
        log.debug("recoverPassword=> {}", resetPasswordRequest);
        try {

            authenticationService.resetPassword(resetPasswordRequest.getEmail(),
                    resetPasswordRequest.getRecoveryCode(),
                    resetPasswordRequest.getNewPassword(),
                    resetPasswordRequest.getPasswordConfirm());

            return new ResponseEntity<>(ResetPasswordResponse.builder()
                    .success(true)
                    .build(), HttpStatus.OK);

        } catch (ResetPasswordException rpex) {
            return new ResponseEntity(ResetPasswordResponse.builder()
                    .success(false)
                    .errorMessage(rpex.getI18NMessage()).build(), HttpStatus.FAILED_DEPENDENCY);
        }

    }

    /**
     * ADMIN ROLE REQUIRED
     *
     * @param pageNo
     * @param pageSize
     * @param sortBy
     * @param active
     * @param httpServletRequest
     * @return
     */
    @ApiImplicitParams({
        @ApiImplicitParam(name = "Authorization", value = "Authorization token",
                required = true, dataType = "string", paramType = "header")})
    @RequestMapping(value = "/findUsersByActiveStatus", method = RequestMethod.POST)
    public ResponseEntity<?> findUsersByPage(@RequestParam Integer pageNo, @RequestParam Integer pageSize, @RequestParam String sortBy, @RequestParam boolean active, HttpServletRequest httpServletRequest) {

        return ResponseEntity.ok(this.authenticationService.findActiveUsersByPage(pageNo, pageSize, sortBy, active));
    }

    /**
     * ADMIN ROLE REQUIRED
     *
     * @param accountId
     * @param activeStatus
     * @return
     */
    @ApiImplicitParams({
        @ApiImplicitParam(name = "Authorization", value = "Authorization token",
                required = true, dataType = "string", paramType = "header")})
    @RequestMapping(value = "/setUserActiveStatus/{accountId}", method = RequestMethod.POST)

    public ResponseEntity<?> setUserActiveStatus(@PathVariable String accountId,
            @RequestParam boolean activeStatus) {
        return ResponseEntity.ok(this.authenticationService.setUserActiveStatus(accountId, activeStatus));
    }

    /**
     * ADMIN ROLE REQUIRED
     *
     * @param accountIds
     * @return
     */
    @ApiImplicitParams({
        @ApiImplicitParam(name = "Authorization", value = "Authorization token",
                required = true, dataType = "string", paramType = "header")})
    @RequestMapping(value = "/getAccountStatusByAccountIds", method = RequestMethod.POST)
    public ResponseEntity<?> getAccountStatusByAccountIds(@RequestBody List<String> accountIds
    ) {
        return ResponseEntity.ok(this.authenticationService.findUsersByAccountIds(accountIds));
    }
}
