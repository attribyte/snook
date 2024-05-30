package org.attribyte.snook.auth.webauthn;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;

public class RestIndexServlet extends HttpServlet {

   RestIndexServlet() throws MalformedURLException {
      ops = new RestIndexOperations();
   }

   @Override
   protected final void doGet(final HttpServletRequest request,
                              final HttpServletResponse response) throws IOException {
      ops.writeIndex(response);
   }

   private final RestIndexOperations ops;
}