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

package org.attribyte.snook;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

/**
 * Helper to test methods that expect servlet requests.
 */
public abstract class TestHttpServletRequest implements HttpServletRequest {

   @Override
   public String getAuthType() {
      return null;
   }

   @Override
   public Cookie[] getCookies() {
      return new Cookie[0];
   }

   @Override
   public long getDateHeader(final String s) {
      return 0;
   }

   @Override
   public String getHeader(final String s) {
      return null;
   }

   @Override
   public Enumeration<String> getHeaders(final String s) {
      return null;
   }

   @Override
   public Enumeration<String> getHeaderNames() {
      return null;
   }

   @Override
   public int getIntHeader(final String s) {
      return 0;
   }

   @Override
   public String getMethod() {
      return null;
   }

   @Override
   public String getPathInfo() {
      return null;
   }

   @Override
   public String getPathTranslated() {
      return null;
   }

   @Override
   public String getContextPath() {
      return null;
   }

   @Override
   public String getQueryString() {
      return null;
   }

   @Override
   public String getRemoteUser() {
      return null;
   }

   @Override
   public boolean isUserInRole(final String s) {
      return false;
   }

   @Override
   public Principal getUserPrincipal() {
      return null;
   }

   @Override
   public String getRequestedSessionId() {
      return null;
   }

   @Override
   public String getRequestURI() {
      return null;
   }

   @Override
   public StringBuffer getRequestURL() {
      return null;
   }

   @Override
   public String getServletPath() {
      return null;
   }

   @Override
   public HttpSession getSession(final boolean b) {
      return null;
   }

   @Override
   public HttpSession getSession() {
      return null;
   }

   @Override
   public boolean isRequestedSessionIdValid() {
      return false;
   }

   @Override
   public boolean isRequestedSessionIdFromCookie() {
      return false;
   }

   @Override
   public boolean isRequestedSessionIdFromURL() {
      return false;
   }

   @Override
   @SuppressWarnings("deprecation")
   public boolean isRequestedSessionIdFromUrl() {
      return false;
   }

   @Override
   public boolean authenticate(final HttpServletResponse httpServletResponse) throws IOException, ServletException {
      return false;
   }

   @Override
   public void login(final String s, final String s1) throws ServletException {

   }

   @Override
   public void logout() throws ServletException {

   }

   @Override
   public Collection<Part> getParts() throws IOException, ServletException {
      return null;
   }

   @Override
   public Part getPart(final String s) throws IOException, ServletException {
      return null;
   }

   @Override
   public Object getAttribute(final String s) {
      return null;
   }

   @Override
   public Enumeration<String> getAttributeNames() {
      return null;
   }

   @Override
   public String getCharacterEncoding() {
      return null;
   }

   @Override
   public void setCharacterEncoding(final String s) throws UnsupportedEncodingException {

   }

   @Override
   public int getContentLength() {
      return 0;
   }

   @Override
   public long getContentLengthLong() {
      return 0;
   }

   @Override
   public String getContentType() {
      return null;
   }

   @Override
   public ServletInputStream getInputStream() throws IOException {
      return null;
   }

   @Override
   public String getParameter(final String s) {
      return null;
   }

   @Override
   public Enumeration<String> getParameterNames() {
      return null;
   }

   @Override
   public String[] getParameterValues(final String s) {
      return new String[0];
   }

   @Override
   public Map<String, String[]> getParameterMap() {
      return null;
   }

   @Override
   public String getProtocol() {
      return null;
   }

   @Override
   public String getScheme() {
      return null;
   }

   @Override
   public String getServerName() {
      return null;
   }

   @Override
   public int getServerPort() {
      return 0;
   }

   @Override
   public BufferedReader getReader() throws IOException {
      return null;
   }

   @Override
   public String getRemoteAddr() {
      return null;
   }

   @Override
   public String getRemoteHost() {
      return null;
   }

   @Override
   public void setAttribute(final String s, final Object o) {

   }

   @Override
   public void removeAttribute(final String s) {

   }

   @Override
   public Locale getLocale() {
      return null;
   }

   @Override
   public Enumeration<Locale> getLocales() {
      return null;
   }

   @Override
   public boolean isSecure() {
      return false;
   }

   @Override
   public RequestDispatcher getRequestDispatcher(final String s) {
      return null;
   }

   @Override
   @SuppressWarnings("deprecation")
   public String getRealPath(final String s) {
      return null;
   }

   @Override
   public int getRemotePort() {
      return 0;
   }

   @Override
   public String getLocalName() {
      return null;
   }

   @Override
   public String getLocalAddr() {
      return null;
   }

   @Override
   public int getLocalPort() {
      return 0;
   }

   @Override
   public ServletContext getServletContext() {
      return null;
   }

   @Override
   public AsyncContext startAsync() throws IllegalStateException {
      return null;
   }

   @Override
   public AsyncContext startAsync(final ServletRequest servletRequest, final ServletResponse servletResponse) throws IllegalStateException {
      return null;
   }

   @Override
   public boolean isAsyncStarted() {
      return false;
   }

   @Override
   public boolean isAsyncSupported() {
      return false;
   }

   @Override
   public AsyncContext getAsyncContext() {
      return null;
   }

   @Override
   public DispatcherType getDispatcherType() {
      return null;
   }

   @Override
   public String changeSessionId() {
      return null;
   }

   @Override
   public <T extends HttpUpgradeHandler> T upgrade(Class<T> var1) throws IOException, ServletException {
      return null;
   }
}
