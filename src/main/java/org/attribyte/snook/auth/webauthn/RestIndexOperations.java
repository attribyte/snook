package org.attribyte.snook.auth.webauthn;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

public class RestIndexOperations extends Operations {

   public RestIndexOperations(final URL baseURL, final boolean pretty) {
      super(baseURL, pretty);
   }

   RestIndexOperations() throws MalformedURLException {
      this(new URL("http://localhost:8081/api/"), true);
   }

   public final class IndexResponse {
      private IndexResponse() throws MalformedURLException {
      }

      public final Index actions = new Index();
      public final Info info = new Info();
   }

   public final class Index {
      public Index() throws MalformedURLException {
         authenticate = new URL(baseURL, "authenticate");
         deleteAccount = new URL(baseURL, "delete-account");
         deregister = new URL(baseURL, "deregister");
         register = new URL(baseURL, "register");
      }

      public final URL authenticate;
      public final URL deleteAccount;
      public final URL deregister;
      public final URL register;
   }

   public final class Info {
      public Info() throws MalformedURLException {
         version = new URL(baseURL, "version");
      }
      public final URL version;
   }

   public void writeIndex(final HttpServletResponse response) throws IOException {
      writeResponse(new IndexResponse(), response);
   }
}
