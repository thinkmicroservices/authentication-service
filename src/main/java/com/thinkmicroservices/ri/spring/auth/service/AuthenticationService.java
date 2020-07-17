package com.thinkmicroservices.ri.spring.auth.service;

import com.thinkmicroservices.ri.spring.auth.service.exception.RegistrationException;
import com.thinkmicroservices.ri.spring.auth.service.exception.RefreshTokenException;
import com.thinkmicroservices.ri.spring.auth.service.exception.AuthenticationException;
import com.thinkmicroservices.ri.spring.auth.service.exception.RecoverPasswordException;
import com.thinkmicroservices.ri.spring.auth.service.exception.ChangePasswordException;
import com.thinkmicroservices.ri.spring.auth.service.exception.ResetPasswordException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.thinkmicroservices.ri.spring.auth.messaging.events.AccountRegisteredEvent;
import com.thinkmicroservices.ri.spring.auth.messaging.AccountEventSource;
import com.thinkmicroservices.ri.spring.auth.messaging.events.CredentialsAuthenticationRequestedEvent;
import com.thinkmicroservices.ri.spring.auth.messaging.events.PasswordChangedEvent;
import com.thinkmicroservices.ri.spring.auth.messaging.events.PasswordRecoveryRequestedEvent;

import com.thinkmicroservices.ri.spring.auth.repository.model.Role;
import com.thinkmicroservices.ri.spring.auth.repository.model.User;
import com.thinkmicroservices.ri.spring.auth.i18n.I18NResourceBundle;
import com.thinkmicroservices.ri.spring.auth.jwt.JWTProvider;
import com.thinkmicroservices.ri.spring.auth.messaging.events.PasswordRecoveryCompletedEvent;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.support.MessageBuilder;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import com.thinkmicroservices.ri.spring.auth.repository.RoleRepository;
import com.thinkmicroservices.ri.spring.auth.repository.UserRepository;
import com.thinkmicroservices.ri.spring.auth.service.exception.UnknownUsernameException;
import com.thinkmicroservices.ri.spring.auth.validator.Validator;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 *
 * @author cwoodward
 */
@Service
@Slf4j

public class AuthenticationService {

    private static final String BASIC_USER_ROLE_VALUE = "user";
    private static final String ADMIN_USER_ROLE_VALUE = "admin";

    /**
     * The discovery client provides access to the <b>ServiceDiscovery</b>
     * service.
     */
    @Autowired
    private DiscoveryClient discoveryClient;

    /**
     * Provides access to <b>User</b> entities.
     */
    @Autowired
    private UserRepository userRepository;

    /**
     * Provides access to <b>Role</b> entities.
     */
    @Autowired
    private RoleRepository roleRepository;

    /**
     * Responsible for the generation of JSON Web tokens <b>JWT</b>
     */
    @Autowired
    private JWTProvider jwtProvider;

    /**
     * Provides encryption support for passwords
     */
    @Autowired
    private PasswordEncoder bcryptEncoder;

    /**
     * Provides an email client that sends email messages through the
     * <b>NotificationService</b>.
     */
    @Autowired
    private EmailClient emailClientService;

    /**
     * Provides a message channel for sending <b>Account Events</b> to the
     * applications message broker.
     */
    @Autowired
    private AccountEventSource accountEventSource;

    /**
     * Provides various string validation methods
     */
    @Autowired
    private Validator validator;

    @Autowired
    private MeterRegistry meterRegistry;

    @Value("${admin.user.email:administrator@thinkmicroservices.com}")
    private String adminEmail;

    @Value("${admin.user.password:Password_1}")
    private String adminPassword;

    @Value("${recovery.code.interval.minutes:5}")
    long recoveryCodeExpirationIntervalMinutes = 5;

    @Value("${token.expiration.interval.minutes:2}")
    long tokenExpirationIntervalMinutes = 2;

    @Value("${refresh.token.expiration.interval.minutes:15}")
    long refreshTokenExpirationIntervalMinutes = 5;

    @Value("${active.services.required.check:false}")
    private boolean checkRequiredActiveServices = false;

    @Value("#{'${active.services.required.for.authentication}'.split(',')}")
    private List<String> activeServicesRequiredForAuthentication;

    private Counter registrationCounter;
    private Counter authenticationSuccessfulCounter;
    private Counter authenticationFailedCounter;
    private Counter passwordChangedCounter;
    private Counter passwordRecoveredCounter;

    /**
     *
     * @param username
     * @param password
     * @return
     * @throws AuthenticationException
     */
    public AuthenticationToken authenticate(String username, String password) throws
            AuthenticationException {

        log.debug("authenticate:" + username);

        if ((checkRequiredActiveServices) && (activeServicesRequiredForAuthentication.size() > 0)) {
            log.info("requiredServices:{}", this.activeServicesRequiredForAuthentication.toString());
            List<String> activeServices = discoveryClient.getServices().stream().map(String::toUpperCase).collect(Collectors.toList());;

            log.info("Discovery services:{}", activeServices);
            this.authenticationFailedCounter.increment();
            if (!activeServices.containsAll(this.activeServicesRequiredForAuthentication)) {
                log.info("all required services are not available,");
                List<String> required = new ArrayList<>(this.activeServicesRequiredForAuthentication);
                required.removeAll(activeServices);
                log.info("missing services:{}", required);

                throw new AuthenticationException("error.authentication.required.services.unavailable", required.toString());

            }
        }

        User user = this.loadUserByUsername(username);

        // throw exception if no user found
        if (user == null) {
            this.accountEventSource
                    .accountEvents()
                    .send(MessageBuilder
                            .withPayload(new CredentialsAuthenticationRequestedEvent(null, username, false))
                            .setHeader("type", "CREDENTIALS_AUTHENTICATION_REQUEST_EVENT").build());
            this.authenticationFailedCounter.increment();
            throw new AuthenticationException("error.authentication.credentials.invalid");
        }

        // throw exception if the user account is disabled
        boolean isEnabled = this.isAccountEnabled(username);
        log.debug("{} activeStatus is {}", username, isEnabled);
        if (isEnabled == false) {
            this.accountEventSource
                    .accountEvents()
                    .send(MessageBuilder
                            .withPayload(new CredentialsAuthenticationRequestedEvent(null, username, false))
                            .setHeader("type", "CREDENTIALS_AUTHENTICATION_REQUEST_EVENT").build());
            this.authenticationFailedCounter.increment();
            throw new AuthenticationException("error.authentication.account.disabled");
        }

        // check if password matches
        User testUser = this.userRepository.findByUsername(username);

        if (this.bcryptEncoder.matches(password, testUser.getPassword())) {

            Set<Role> roles = user.getRoles();
            ArrayList<GrantedAuthority> authorities = this.getGrantedAuthorities(roles);

            java.sql.Timestamp lastLogonTimestamp = new java.sql.Timestamp((new java.util.Date().getTime()));
            String refreshToken = UUID.randomUUID().toString();

            LocalDateTime refreshTokenExpirationTimestamp = LocalDateTime.now();
            refreshTokenExpirationTimestamp = refreshTokenExpirationTimestamp.plusMinutes(this.refreshTokenExpirationIntervalMinutes);

            LocalDateTime tokenExpiresAtTimestamp = LocalDateTime.now();
            tokenExpiresAtTimestamp = tokenExpiresAtTimestamp.plusMinutes(this.tokenExpirationIntervalMinutes);

            user.setRefreshTokenExpirationAt(Timestamp.valueOf(refreshTokenExpirationTimestamp));
            user.setRefreshToken(refreshToken);
            user.setLastLogon(lastLogonTimestamp);

            user.setTokenIssuedAt(lastLogonTimestamp);
            user.setTokenExpirationAt(Timestamp.valueOf(tokenExpiresAtTimestamp));

            this.userRepository.save(user);

            final String tokenString = jwtProvider.generateToken(user,
                    authorities,
                    lastLogonTimestamp.getTime(), // issued at
                    Timestamp.valueOf(tokenExpiresAtTimestamp).getTime(),
                    refreshToken,
                    Timestamp.valueOf(refreshTokenExpirationTimestamp).getTime());
            this.accountEventSource.accountEvents()
                    .send(MessageBuilder.withPayload(new CredentialsAuthenticationRequestedEvent(user.getAccountId(), username, true))
                            .setHeader("type", "CREDENTIALS_AUTHENTICATION_REQUEST_EVENT").build());
            authenticationSuccessfulCounter.increment();
            return new AuthenticationToken(tokenString);

        } else {

            log.debug("alternate authentication Failed");
            this.authenticationFailedCounter.increment();

            throw new AuthenticationException("error.authentication.credentials.invalid");
        }

    }

    /**
     *
     * @param refreshToken
     * @return
     * @throws RefreshTokenException
     */
    public AuthenticationToken refreshToken(String refreshToken) throws
            RefreshTokenException {

        log.debug("refresh token:" + refreshToken);

        // check with the service discovery service client that the required
        // services are active before allowing a user to authenticate
        if (activeServicesRequiredForAuthentication.size() > 0) {
            log.info("requiredServices:{}", this.activeServicesRequiredForAuthentication.toString());
            List<String> activeServices = discoveryClient.getServices().stream().map(String::toUpperCase).collect(Collectors.toList());;

            log.info("Discovery services:{}", activeServices);

            if (!activeServices.containsAll(this.activeServicesRequiredForAuthentication)) {
                log.info("all required services are not available,");
                List<String> required = new ArrayList<>(this.activeServicesRequiredForAuthentication);
                required.removeAll(activeServices);
                log.info("missing services:{}", required);

                throw new RefreshTokenException("error.authentication.required.services.unavailable", required.toString());

            }
        }

        // get the user
        User user = this.loadUserByRefreshToken(refreshToken);

        // if user is disabled dont return a token
        if (!user.isActiveStatus()) {
            return new AuthenticationToken("");
        }

        // everything is cool - generate the new token
        Set<Role> roles = user.getRoles();
        ArrayList<GrantedAuthority> authorities = this.getGrantedAuthorities(roles);

        java.sql.Timestamp lastLogonTimestamp = new java.sql.Timestamp((new java.util.Date().getTime()));
        String newRefreshToken = UUID.randomUUID().toString();

        LocalDateTime refreshTokenExpirationTimestamp = LocalDateTime.now();
        refreshTokenExpirationTimestamp = refreshTokenExpirationTimestamp.plusMinutes(this.refreshTokenExpirationIntervalMinutes);

        LocalDateTime tokenExpiresAtTimestamp = LocalDateTime.now();
        tokenExpiresAtTimestamp = tokenExpiresAtTimestamp.plusMinutes(this.tokenExpirationIntervalMinutes);

        user.setRefreshTokenExpirationAt(Timestamp.valueOf(refreshTokenExpirationTimestamp));
        user.setRefreshToken(newRefreshToken);
        user.setLastLogon(lastLogonTimestamp);

        user.setTokenIssuedAt(lastLogonTimestamp);
        user.setTokenExpirationAt(Timestamp.valueOf(tokenExpiresAtTimestamp));

        this.userRepository.save(user);

        final String tokenString = jwtProvider.generateToken(user,
                authorities,
                lastLogonTimestamp.getTime(), // issued at
                Timestamp.valueOf(tokenExpiresAtTimestamp).getTime(),
                newRefreshToken,
                Timestamp.valueOf(refreshTokenExpirationTimestamp).getTime());

        // TODO generate refresh token event
        /*this.accountEventSource.accountEvents()
                    .send(MessageBuilder.withPayload(new CredentialsAuthenticationRequestedEvent(user.getAccountId(), username, true))
                            .setHeader("type", "CREDENTIALS_AUTHENTICATION_REQUEST_EVENT").build());
         */
        return new AuthenticationToken(tokenString);

    }

    /**
     *
     * @param username
     * @return
     * @throws UnknownUsernameException
     */
    public boolean isAccountEnabled(String username) throws UnknownUsernameException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UnknownUsernameException("error.loaduser.not.found", username);

        }
        if (user.isActiveStatus()) {
            return true;
        }
        return false;
    }

    /**
     *
     * @param username
     * @return
     * @throws UnknownUsernameException
     */
    public User loadUserByUsername(String username) throws UnknownUsernameException {
        User user = userRepository.findByUsername(username);

        if (user == null) {

            this.accountEventSource
                    .accountEvents()
                    .send(MessageBuilder
                            .withPayload(new CredentialsAuthenticationRequestedEvent(null, username, false))
                            .setHeader("type", "CREDENTIALS_AUTHENTICATION_REQUEST_EVENT").build());

            throw new UnknownUsernameException(I18NResourceBundle.translateForLocale("error.loaduser.not.found") + " " + username);
        }
        this.accountEventSource.accountEvents()
                .send(MessageBuilder.withPayload(new CredentialsAuthenticationRequestedEvent(user.getAccountId(), username, true))
                        .setHeader("type", "CREDENTIALS_AUTHENTICATION_REQUEST_EVENT").build());
        return user;
    }

    /**
     *
     * @param refreshToken
     * @return
     * @throws RefreshTokenException
     */
    public User loadUserByRefreshToken(String refreshToken) throws RefreshTokenException {

        User user = userRepository.findByRefreshToken(refreshToken);
        // TODO send refreshToken event
        if (user == null) {

            throw new RefreshTokenException("error.loaduser.refresh.token.not.found");
        }

        // throw exception if no user found
        if (user == null) {
            /* this.accountEventSource
                    .accountEvents()
                    .send(MessageBuilder
                            .withPayload(new CredentialsAuthenticationRequestedEvent(null, username, false))
                            .setHeader("type", "CREDENTIALS_AUTHENTICATION_REQUEST_EVENT").build());
             */

            throw new RefreshTokenException("error.authentication.credentials.invalid");
        }

        // throw exception if the user account is disabled
        boolean isEnabled = user.isActiveStatus();

        //log.debug("{} activeStatus is {}", username, isEnabled);
        if (isEnabled == false) {
            /*
            this.accountEventSource
                    .accountEvents()
                    .send(MessageBuilder
                            .withPayload(new CredentialsAuthenticationRequestedEvent(null, username, false))
                            .setHeader("type", "CREDENTIALS_AUTHENTICATION_REQUEST_EVENT").build());
             */

            throw new RefreshTokenException("error.refresh.token.account.disabled");
        }

        if (user.getRefreshTokenExpirationAt() == null) {

            throw new RefreshTokenException("error.refresh.token.not.set");
        }

        if (user.getRefreshTokenExpirationAt().getTime() <= System.currentTimeMillis()) {

            throw new RefreshTokenException("error.refresh.token.expired");
        }

        return user;
    }

    /**
     *
     * @param recoveryCode
     * @return
     * @throws UsernameNotFoundException
     */
    public UserDetails loadUserByRecoveryCode(String recoveryCode) throws UnknownUsernameException {

        User user = userRepository.findByRecoveryCode(recoveryCode);

        if (user == null) {
            //this.accountEventSource.accountEvents().send(MessageBuilder.withPayload(new AccountPasswordRecoverRequestEvent(username)).build());

            throw new UnknownUsernameException("error.passwordrecovery.invalid", recoveryCode);
        }
        //this.accountEventSource.accountEvents().send(MessageBuilder.withPayload(new AccountPasswordRecoverRequestEvent(username)).build());

        Set<Role> roles = user.getRoles();
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                getGrantedAuthorities(roles)
        );
    }

    /**
     *
     * @param username
     * @return
     */
    public boolean isUsernameAvailable(String username) {
        User user = userRepository.findByUsername(username);

        if (user == null) {

            return true;

        }
        return false;
    }

    /**
     *
     * @param changePasswordRequest
     * @return
     * @throws ChangePasswordException
     */
    public void changePassword(String accountId, String currentPassword, String newPassword, String confirmPassword) throws ChangePasswordException {
        User userModel = null;
        log.debug("change password accountID:{}", accountId);
        // lookup the user by email address
        if (accountId != null) {

            // check if the user exists
            log.debug("change password for account id:{}", accountId);
            userModel = this.userRepository.findByAccountId(accountId);
            if (userModel == null) {
                throw new ChangePasswordException("error.authentication.token.isnull");
            }

            // check if the current password has been supplied
            if ((currentPassword == null) || (currentPassword.length() == 0)) {
                throw new ChangePasswordException("error.authentication.current.password.required");
            }
            // check if the current password supplied matches the persisted password

            if (!this.bcryptEncoder.matches(currentPassword, userModel.getPassword())) {
                throw new ChangePasswordException("error.authentication.current.password.does.not.match");
            }

            // check if they supplied a new password
            if ((newPassword == null) || (newPassword.length() == 0)) {
                throw new ChangePasswordException("error.changepassword.cannot.be.empty");
            }

            // check if the user supplied a matching confirmation password
            if (!newPassword.equals(confirmPassword)) {
                throw new ChangePasswordException("error.changepassword.confirmation.does.not.match");
            }

            // check that the new password meets the complexity requirements
            if (!validator.isPasswordValid(newPassword)) {
                throw new ChangePasswordException("error.changepassword.complexity.failure");
            }

            // save the new password
            userModel.setPassword(bcryptEncoder.encode(newPassword));
            userRepository.save(userModel);

            // send account event "ChangePassword"
            this.accountEventSource
                    .accountEvents()
                    .send(MessageBuilder.withPayload(new PasswordChangedEvent(userModel.getAccountId(), userModel.getEmail()))
                            .setHeader("type", "PASSWORD_CHANGED_EVENT").build());
            this.passwordChangedCounter.increment();
        } else {
            throw new ChangePasswordException("error.authentication.token.invalid");
        }

    }

    /**
     *
     * @param user
     * @return
     * @throws RecoverPasswordException
     */
    public String recoverPassword(String email) throws RecoverPasswordException {
        log.debug("recover password for:" + email);

        User userModel = userRepository.findByUsername(email);
        if (userModel == null) {
            throw new RecoverPasswordException("error.passwordrecovery.invalid.user", email);

        }
        String recoveryCodeString = UUID.randomUUID().toString();

        userModel.setRecoveryCode(recoveryCodeString);

        LocalDateTime expirationTimestamp = LocalDateTime.now();
        log.debug("recoveryCodeExpireationIntervalMinutes:{}", recoveryCodeExpirationIntervalMinutes);
        log.debug("currentTime         :{}" + Timestamp.valueOf(expirationTimestamp));
        // add the interval before we store it
        expirationTimestamp = expirationTimestamp.plusMinutes(recoveryCodeExpirationIntervalMinutes);
        log.debug("currentTime+interval:{}" + Timestamp.valueOf(expirationTimestamp));
        log.debug("{} -recovery code={}, expires={} ", email, recoveryCodeString, Timestamp.valueOf(expirationTimestamp));
        userModel.setRecoveryExpiresAt(Timestamp.valueOf(expirationTimestamp));
        userRepository.save(userModel);

        this.emailClientService.sendRecoveryEmail(email, recoveryCodeString);
        // send account event "RecoverPassword Requested"
        this.accountEventSource.accountEvents().send(MessageBuilder.withPayload(new PasswordRecoveryRequestedEvent(userModel.getAccountId(), userModel.getEmail()))
                .setHeader("type", "PASSWORD_RECOVERY_REQUESTED_EVENT").build());
        this.passwordRecoveredCounter.increment();
        return recoveryCodeString;
    }

    /**
     *
     * @param email
     * @param recoveryCode
     * @param newPassword
     * @param passwordConfirm
     * @throws ResetPasswordException
     */
    public void resetPassword(String email, String recoveryCode, String newPassword,
            String passwordConfirm) throws ResetPasswordException {
        log.debug("reset password");
        // check if the email is a registered user
        User userModel = userRepository.findByUsername(email);
        if (userModel == null) {
            throw new ResetPasswordException("error.passwordreset.invalid.user", email);

        }
        long currentTime = System.currentTimeMillis();

        if (userModel.getRecoveryExpiresAt() != null) {
            log.debug("difference                  -{}", userModel.getRecoveryExpiresAt().getTime() - currentTime);
        }
        // check if the recovery code exists for the user
        String persistedRecoveryCode = userModel.getRecoveryCode();

        if ((persistedRecoveryCode == null) || (!persistedRecoveryCode.equals(recoveryCode))) {
            throw new ResetPasswordException("error.passwordreset.invalid.code");
        }

        // check if the recovery code expiration is set
        if (userModel.getRecoveryExpiresAt() == null) {
            log.debug("no recovery expiration date");
            throw new ResetPasswordException("error.passwordreset.invalid.code");
        }

        // check the recovery code hasn't expired
        if (currentTime > userModel.getRecoveryExpiresAt().getTime()) {
            log.debug("recovery code expired");
            throw new ResetPasswordException("error.passwordreset.recovery.code.expired");
        }

        // check if the new password meets the complexity requirements
        if ((newPassword == null) || (!this.validator.isPasswordValid(newPassword))) {
            throw new ResetPasswordException("error.passwordreset.password.complexity.failure");
        }

        // check if the confirmation password matches
        if (!newPassword.equals(passwordConfirm)) {
            throw new ResetPasswordException("error.passwordreset.password.does.not.match");
        }

        // ok- change the password
        userModel.setPassword(bcryptEncoder.encode(newPassword));
        userRepository.save(userModel);

        // send account event "ResetPassword"
        this.accountEventSource
                .accountEvents()
                .send(MessageBuilder.withPayload(new PasswordRecoveryCompletedEvent(userModel.getAccountId(), userModel.getEmail()))
                        .setHeader("type", "PASSWORD_RECOVERY_COMPLETED_EVENT").build());

    }

    /**
     *
     * @param email
     * @param firstName
     * @param middleName
     * @param lastName
     * @param password
     * @param confirmPassword
     * @return
     * @throws RegistrationException
     */
    public User registerUser(String email, String firstName, String middleName, String lastName, String password, String confirmPassword) throws RegistrationException {

        log.info("register user: {},{},{}", email, password, confirmPassword);

        if ((firstName == null) || (firstName.length() == 0)) {
            throw new RegistrationException("error.registration.first.name.required");
        }

        if ((lastName == null) || (lastName.length() == 0)) {
            throw new RegistrationException("error.registration.first.name.required");
        }

        if (!this.isUsernameAvailable(email)) {
            throw new RegistrationException("error.registration.email.already.registered");
        }
        if (!this.validator.isEmailValid(email)) {
            throw new RegistrationException("error.registration.email.invalid");
        }

        if ((password == null) || (password.length() == 0)) {
            throw new RegistrationException("error.registration.password.cannot.be.empty");
        }
        if (!this.validator.isPasswordValid(password)) {
            throw new RegistrationException("error.registration.password.complexity.failure");
        }
        if (!password.equals(confirmPassword)) {
            throw new RegistrationException("error.registration.password.confirmation.does.not.match");
        }

        User user = save(email, password);
        AccountRegisteredEvent accountRegisteredEvent = new AccountRegisteredEvent(user.getAccountId(), email, firstName, middleName, lastName);
        log.debug(accountRegisteredEvent.toString());
        // send account event "Created User"
        this.accountEventSource.accountEvents()
                .send(MessageBuilder.withPayload(accountRegisteredEvent)
                        .setHeader("type", "ACCOUNT_REGISTERED_EVENT").build());
        this.registrationCounter.increment();
        this.emailClientService.sendRegistrationEmail(email);
        return user;
    }

    /**
     *
     * @param email
     * @param password
     * @return
     */
    public User save(String email, String password) {

        User newUser = new User();
        String accountId = UUID.randomUUID().toString();
        log.debug("created accountId {}", accountId);
        newUser.setAccountId(accountId);
        newUser.setUsername(email);
        newUser.setActiveStatus(true);
        newUser.setPassword(bcryptEncoder.encode(password));
        log.debug("new user:" + newUser);

        Set<Role> roles = new HashSet<>();

        roles.add(getBasicUserRole());
        newUser.setRoles(roles);

        User createdUser = userRepository.save(newUser);

        return createdUser;

    }

    /**
     *
     * @return
     */
    public List<User> findActiveUsers() {
        return this.userRepository.findUser(true);
    }

    /**
     *
     * @param pageNo
     * @param pageSize
     * @param sortBy
     * @param active
     * @return
     */
    public Page<User> findActiveUsersByPage(Integer pageNo, Integer pageSize, String sortBy, boolean active) {

        Pageable paging = PageRequest.of(pageNo, pageSize, Sort.by(sortBy));

        Page<User> result = this.userRepository.findByActiveStatus(paging, active);

        return result;
    }

    /**
     *
     * @return
     */
    public List<User> findInactiveUsers() {
        return this.userRepository.findUser(false);
    }

    /**
     *
     * @param accountIds
     * @return
     */
    public List<User> findUsersByAccountIds(List<String> accountIds) {
        return this.userRepository.findUserByAccountIdList(accountIds);
    }

    /**
     *
     * @param accountId
     * @param status
     * @return
     */
    public boolean setUserActiveStatus(String accountId, boolean status) {

        User user = this.userRepository.findByAccountId(accountId);
        user.setActiveStatus(status);
        userRepository.save(user);
        return status;
    }

    /**
     * when this method is called, it will create an admin user if one doesn't
     * already exist.
     */
    public void createAdminUser() {

        // check if admin user already exists
        if (this.isUsernameAvailable(adminEmail)) {

            log.info("creating admin user...");

            User adminUser = new User();
            String accountId = UUID.randomUUID().toString();
            log.debug("created admin with accountId {},username:{},password:{}", accountId, adminEmail, adminPassword);
            adminUser.setAccountId(accountId);
            adminUser.setUsername(adminEmail);
            adminUser.setPassword(bcryptEncoder.encode(adminPassword));
            adminUser.setActiveStatus(true);
            Set<Role> roles = new HashSet<>();
            roles.add(getAdminUserRole());
            roles.add(getBasicUserRole());

            adminUser.setRoles(roles);

            User createdUser = userRepository.save(adminUser);

            this.accountEventSource.accountEvents().send(MessageBuilder.withPayload(new AccountRegisteredEvent(accountId, adminEmail, "Admin", "I", "Strator"))
                    .setHeader("type", "ACCOUNT_REGISTERED_EVENT").build());
            log.info("created admin user: {}", createdUser.toString());

        } else {
            log.info("Admin user already exists...");
        }
    }

    /**
     *
     * @return
     */
    private Role getBasicUserRole() {

        return roleRepository.findByValue(BASIC_USER_ROLE_VALUE);

    }

    /**
     *
     * @return
     */
    private Role getAdminUserRole() {

        return roleRepository.findByValue(ADMIN_USER_ROLE_VALUE);

    }

    /**
     *
     * @param roles
     * @return
     */
    public ArrayList<GrantedAuthority> getGrantedAuthorities(Set<Role> roles) {

        ArrayList<GrantedAuthority> grants = new ArrayList<>();
        for (Role role : roles) {
            grants.add(new SimpleGrantedAuthority(role.getValue()));
        }
        return grants;
    }

    @PostConstruct
    public void initializeMetrics() {
        this.registrationCounter = Counter.builder("registration.new")
                
                .description("The number of registration operations.")
                .register(meterRegistry);

        this.authenticationSuccessfulCounter = Counter.builder("authentication.successful")
                
                .description("The number of authentication attempts that succeeded.")
                .register(meterRegistry);

        this.authenticationFailedCounter = Counter.builder("authentication.failed")
                
                .description("The number of authentication attempts that failed.")
                .register(meterRegistry);

        this.passwordChangedCounter = Counter.builder("password.changed")
                
                .description("The number of times passwords have been changed.")
                .register(meterRegistry);

        this.passwordRecoveredCounter = Counter.builder("password.recovered")
                
                .description("The number of times passwords have been recovered.")
                .register(meterRegistry);

    }

}
