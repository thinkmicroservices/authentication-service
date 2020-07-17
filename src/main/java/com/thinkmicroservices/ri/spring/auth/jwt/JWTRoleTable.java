package com.thinkmicroservices.ri.spring.auth.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import lombok.extern.slf4j.Slf4j;

/**
 * The JWTRoleTable provides a mechanism for looking up the required roles for a
 * given application uri path. The uri paths and corresponding roles are stored
 * in a two dimensional array.
 *
 * @author cwoodward
 */
@Slf4j
public class JWTRoleTable {

    // declare the role names
    private static final String USER_ROLE = "user";
    private static final String ADMIN_ROLE = "admin";

    // name the two dimensional array indexes
    private static int URI_PREFIX_INDEX = 0;
    private static int URI_REQUIRED_ROLES_INDEX = 1;

    private static final Object[][] uriRoleTable = {
        {"/changePassword", new String[]{USER_ROLE}},
        {"/findUsersByActiveStatus", new String[]{ADMIN_ROLE}},
        {"/setUserActiveStatus", new String[]{ADMIN_ROLE}},
        {"/getAccountStatusByAccountIds", new String[]{ADMIN_ROLE}}

    };

    /**
     *
     * @param uriPath URI path string
     * @return Collection of Strings representing the roles required for the URI
     * path. Returns <b>null</b> if no match found
     *
     */
    public static List<String> getRequiredRolesByUriPath(String uriPath) {

        for (int idx = 0; idx < uriRoleTable.length; idx++) {
            log.debug("uri path {}->{}", uriPath, uriRoleTable[idx][URI_PREFIX_INDEX]);
            // compare the incoming uri path agains the table. Return the List
            // of role strings for the first match
            if (uriPath.startsWith(uriRoleTable[idx][URI_PREFIX_INDEX].toString())) {

                return convertToStringList(uriRoleTable[idx][URI_REQUIRED_ROLES_INDEX]);

            }
        }

        return new ArrayList<String>();
    }

    /**
     *
     * @param objects
     * @return a list of all non-null object strings
     */
    private static List<String> convertToStringList(Object objx) {
        List<String> results = new ArrayList<>();

        // guard to ensure method parameter is a non-null, array
        if ((objx == null) && (objx.getClass().isArray())) {
            return results;
        }

        // convert the object to an array of objects
        Object[] objects = (Object[]) objx;
        for (Object obj : objects) {
            if (obj != null) {
                results.add(obj.toString());
            }
        }
        return results;
    }

}
