/*
 * Copyright 2018 Attribyte, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.attribyte.snook.auth.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Default login form renderer that produces minimal inline HTML.
 */
public class DefaultLoginFormRenderer implements LoginFormRenderer {

   @Override
   public void render(final HttpServletRequest request,
                      final HttpServletResponse response,
                      final String clientName,
                      final String errorMessage,
                      final String formAction,
                      final String hiddenFieldsHtml) throws IOException {

      response.setStatus(errorMessage != null ? 401 : 200);
      response.setContentType("text/html;charset=UTF-8");
      PrintWriter writer = response.getWriter();
      writer.write("<!DOCTYPE html><html><head><meta charset='UTF-8'>");
      writer.write("<meta name='viewport' content='width=device-width,initial-scale=1'>");
      writer.write("<title>Sign In</title>");
      writer.write("<style>");
      writer.write("body{font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;");
      writer.write("align-items:center;min-height:100vh;margin:0;background:#f5f5f5}");
      writer.write(".card{background:white;border-radius:8px;padding:2rem;box-shadow:0 2px 8px rgba(0,0,0,.1);");
      writer.write("width:100%;max-width:360px}");
      writer.write("h2{margin:0 0 1.5rem;font-size:1.25rem;text-align:center}");
      writer.write(".client{color:#666;font-size:.875rem;text-align:center;margin-bottom:1.5rem}");
      writer.write("label{display:block;font-size:.875rem;margin-bottom:.25rem;color:#333}");
      writer.write("input[type=text],input[type=password]{width:100%;padding:.5rem;border:1px solid #ddd;");
      writer.write("border-radius:4px;font-size:1rem;margin-bottom:1rem;box-sizing:border-box}");
      writer.write("button{width:100%;padding:.625rem;background:#2563eb;color:white;border:none;");
      writer.write("border-radius:4px;font-size:1rem;cursor:pointer}");
      writer.write("button:hover{background:#1d4ed8}");
      writer.write(".error{background:#fef2f2;color:#dc2626;padding:.5rem;border-radius:4px;");
      writer.write("font-size:.875rem;margin-bottom:1rem;text-align:center}");
      writer.write("</style></head><body><div class='card'>");
      writer.write("<h2>Sign In</h2>");
      writer.write("<div class='client'>" + escapeHtml(clientName) + " is requesting access</div>");
      if(errorMessage != null) {
         writer.write("<div class='error'>" + escapeHtml(errorMessage) + "</div>");
      }
      writer.write("<form method='POST' action='" + escapeHtml(formAction) + "'>");
      writer.write("<label for='username'>Username</label>");
      writer.write("<input type='text' id='username' name='username' required autofocus>");
      writer.write("<label for='password'>Password</label>");
      writer.write("<input type='password' id='password' name='password' required>");
      writer.write(hiddenFieldsHtml);
      writer.write("<button type='submit'>Sign In</button>");
      writer.write("</form></div></body></html>");
      writer.flush();
   }

   static String escapeHtml(String s) {
      if(s == null) return "";
      return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
              .replace("\"", "&quot;").replace("'", "&#39;");
   }
}
