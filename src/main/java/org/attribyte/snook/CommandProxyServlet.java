package org.attribyte.snook;

import com.google.common.base.Strings;
import com.google.common.io.ByteStreams;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

@SuppressWarnings("serial")
public class CommandProxyServlet extends HttpServlet {

   @Override
   protected final void service(final HttpServletRequest request,
                                final HttpServletResponse response) throws IOException {

      String proxyURL = Strings.nullToEmpty(request.getParameter("url"));
      if(proxyURL.isEmpty()) {
         proxyURL = request.getRequestURL().toString();
      }

      ProcessBuilder processBuilder = new ProcessBuilder();
      processBuilder.command("/opt/google/chrome/chrome", "--headless", "--disable-gpu", "--dump-dom", proxyURL);
      Process process = processBuilder.start();
      InputStream is = new BufferedInputStream(process.getInputStream());
      byte[] bytes = ByteStreams.toByteArray(is);
      try {
         int exitCode = process.waitFor();
         if(exitCode == 0) {
            response.setStatus(200);
            response.setContentType("text/html");
            response.setContentLength(bytes.length);
            response.getOutputStream().write(bytes);
            response.getOutputStream().flush();
         } else {
            response.sendError(500, "Failed");
         }
      } catch(InterruptedException ie) {
         response.sendError(500, "Interrupted");
      } finally {
         is.close();
      }
   }
}