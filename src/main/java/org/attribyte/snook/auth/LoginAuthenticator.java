package org.attribyte.snook.auth;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface LoginAuthenticator {

   /**
    * Performs a login.
    * <p>
    *    If username + password is valid, sets a header or a cookie on the response
    *    and returns {@code true}.
    *    Otherwise, does nothing and returns {@code false}.
    * </p>
    * @param username The username.
    * @param password The password.
    * @param tokenLifetimeSeconds The authentication token lifetime in seconds.
    * @param resp The response.
    * @return Was the password valid and token saved and set as a cookie?
    * @throws IOException if credentials save failed.
    */
   public boolean doLogin(final String username, final String password,
                          final int tokenLifetimeSeconds,
                          final HttpServletResponse resp) throws IOException;

}
