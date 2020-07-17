package com.thinkmicroservices.ri.spring.auth.jwt;

import java.io.IOException;
import java.util.List;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 *
 * @author cwoodward
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j

public class JWTAuthorizationFilter implements Filter {

    /**
     * message returned when the supplied token has expired.
     */
    protected static final String TOKEN_EXPIRED_MESSAGE = "Token Expired";
    /**
     * message returned when the no token is present
     */
    protected static final String TOKEN_MISSING_MESSAGE = "Token Missing";

    protected static final String TOKEN_ROLES_INSUFFICIENT_MESSAGE = "Token Insufficient Privileges";

    @Autowired
    private JWTService jwtService;

    /**
     * filters incoming requests and ensures a token is provided and has not
     * expired. The token is added to the request prior to dispatch to the next
     * filter.
     *
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        log.debug("invoking JWTAuthorizationFilter...>");
        checkJWTServiceAvailable(request);
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String requestURI = httpRequest.getRequestURI();
        log.debug("requestURI={}", requestURI);
        List<String> rolesRequired = JWTRoleTable.getRequiredRolesByUriPath(requestURI);
        log.debug("required roles for {}={}", requestURI, rolesRequired);

        if (rolesRequired.size() > 0) {

            // get the token
            JWT jwt = extractJwtFromRequest(httpRequest);

            // if no token present send an error
            if (jwt == null) {

                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, TOKEN_MISSING_MESSAGE);
                return;
            }

            // if the token has expired send an error
            if (jwt.isTokenExpired()) {
                log.debug("uri:{},token expired", httpRequest.getRequestURI());
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, TOKEN_EXPIRED_MESSAGE);
                return;
            }

            // if token is missing required roles send an error
            if (!jwt.hasAllRoles(rolesRequired)) {
                log.debug("uri:{},insufficient roles", httpRequest.getRequestURI());
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, TOKEN_ROLES_INSUFFICIENT_MESSAGE);
                return;
            }
            // everything looks good. set the JWT into the request for future use

            request.setAttribute("JWT", jwt);
            log.debug("uri:{},set JWT Attribute", httpRequest.getRequestURI());
         //   return;
        }
        //} else {
            chain.doFilter(request, response);
        //}
    }

    private JWT extractJwtFromRequest(HttpServletRequest httpRequest) {
        String authHeader = httpRequest.getHeader("Authorization");

        if ((authHeader != null) && (authHeader.length() > 7)) {
            String token = authHeader.substring(7);
            log.debug("uri:{},token=>{}", httpRequest.getRequestURI(), token);

            return jwtService.decodeJWT(token);
        }
        return null;

    }

    public void checkJWTServiceAvailable(ServletRequest request) {
        log.debug("checking JWTService");
        // this is hack to get the jwtService in the Filter
        if (jwtService == null) {
            ServletContext servletContext = request.getServletContext();
            WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(servletContext);
            jwtService = webApplicationContext.getBean(JWTService.class);
        }
        log.debug("JWTService=>{}", jwtService);
    }
}
