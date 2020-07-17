package com.thinkmicroservices.ri.spring.auth.controller;

import com.thinkmicroservices.ri.spring.auth.i18n.I18NResourceBundle;
import com.thinkmicroservices.ri.spring.auth.jwt.JWTProvider;
import com.thinkmicroservices.ri.spring.auth.jwt.JWTService;
import com.thinkmicroservices.ri.spring.auth.jwt.JWT;
import com.thinkmicroservices.ri.spring.auth.repository.UserRepository;
import com.thinkmicroservices.ri.spring.auth.repository.RoleRepository;
import com.thinkmicroservices.ri.spring.auth.repository.model.User;
import com.thinkmicroservices.ri.spring.auth.repository.model.Role;
import com.thinkmicroservices.ri.spring.auth.service.AuthenticationService;
import com.thinkmicroservices.ri.spring.auth.messaging.AccountEventSource;
import com.thinkmicroservices.ri.spring.auth.service.AuthenticationToken;
import com.thinkmicroservices.ri.spring.auth.service.EmailClient;
import com.thinkmicroservices.ri.spring.auth.service.exception.AuthenticationException;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import javax.sql.DataSource;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import static org.mockito.Mockito.*;
import org.mockito.Spy;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.messaging.MessageChannel;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 *
 * @author cwoodward
 */
@RunWith(MockitoJUnitRunner.class)
@SpringBootTest(properties = "spring.cloud.config.enabled=false", classes = TestConfig.class)

public class SmokeTest {
 
    @Autowired
    private DataSource dataSource;

    @Mock
    private UserRepository userRepository;

    @Mock
    private DiscoveryClient discoveryClient;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private AccountEventSource accountEventSource;

    @Mock
    private EmailClient emailClientService;

    @Autowired
    private MeterRegistry meterRegistry;
     
    @Spy
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Spy
    @Autowired
    private JWTProvider jwtProvider;

    @Autowired
    private I18NResourceBundle resourceBundle;

    @Spy
    @Autowired
    private JWTService jwtService;

    @InjectMocks
    private AuthenticationService authenticationService;

    @Test
    public void authenticateUser() throws AuthenticationException {
        /*
        //authenticationService.initializeMetrics();
        String email = "admin@thinkmicroservices.com";
        String password = "Password_1";

        when(passwordEncoder.matches(any(), any())).thenReturn(true);

        LocaleContextHolder.setLocale(new Locale("en", "US"));
        User user = new User();
        String encodedPassword = passwordEncoder.encode(password);
        System.out.println("passwordEncode" + passwordEncoder + "/" + encodedPassword);

        user.setPassword(encodedPassword);
        user.setActiveStatus(true);
        user.setAccountId("12345");
        user.setUsername(email);

        Set<Role> roles = new HashSet<>();

        Role userRole = new Role();
        userRole.setLabel("USER");
        userRole.setValue(("USER"));
        roles.add(userRole);

        Role adminRole = new Role();
        adminRole.setLabel("ADMIN");
        adminRole.setValue(("ADMIN"));
        roles.add(adminRole);

        user.setRoles(roles);

        MessageChannel outboundMessageChannel = mock(MessageChannel.class);

        Optional<Role> optionalRole = Optional.of(userRole);

        when(accountEventSource.accountEvents()).thenReturn(outboundMessageChannel);

        when(userRepository.findByUsername(any(String.class))).thenReturn(user);

        

        AuthenticationToken authenticationToken = authenticationService.authenticate(email, password);
   
        assertNotNull("token should not be null", authenticationToken);

        JWT jwt = jwtService.decodeJWT(authenticationToken.getToken());
        assertTrue ("User should have 'USER' role",jwt.hasRole("USER"));
        
        assertTrue("User should have 'ADMIN' role",jwt.hasRole("ADMIN"));
*/
    }

    
}
