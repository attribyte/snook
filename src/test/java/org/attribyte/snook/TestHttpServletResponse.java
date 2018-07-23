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

import com.google.common.collect.Lists;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * A test servlet response.
 */
public class TestHttpServletResponse implements HttpServletResponse {

   public List<Cookie> cookies = Lists.newArrayList();

   @Override
   public void addCookie(final Cookie cookie) {
      cookies.add(cookie);
   }

   @Override
   public boolean containsHeader(final String s) {
      return false;
   }

   @Override
   public String encodeURL(final String s) {
      return null;
   }

   @Override
   public String encodeRedirectURL(final String s) {
      return null;
   }

   @Override
   @SuppressWarnings("deprecation")
   public String encodeUrl(final String s) {
      return null;
   }

   @Override
   @SuppressWarnings("deprecation")
   public String encodeRedirectUrl(final String s) {
      return null;
   }

   @Override
   public void sendError(final int i, final String s) throws IOException {

   }

   @Override
   public void sendError(final int i) throws IOException {

   }

   @Override
   public void sendRedirect(final String s) throws IOException {

   }

   @Override
   public void setDateHeader(final String s, final long l) {

   }

   @Override
   public void addDateHeader(final String s, final long l) {

   }

   @Override
   public void setHeader(final String s, final String s1) {

   }

   @Override
   public void addHeader(final String s, final String s1) {

   }

   @Override
   public void setIntHeader(final String s, final int i) {

   }

   @Override
   public void addIntHeader(final String s, final int i) {

   }

   @Override
   public void setStatus(final int i) {

   }

   @Override
   @SuppressWarnings("deprecation")
   public void setStatus(final int i, final String s) {

   }

   @Override
   public int getStatus() {
      return 0;
   }

   @Override
   public String getHeader(final String s) {
      return null;
   }

   @Override
   public Collection<String> getHeaders(final String s) {
      return null;
   }

   @Override
   public Collection<String> getHeaderNames() {
      return null;
   }

   @Override
   public String getCharacterEncoding() {
      return null;
   }

   @Override
   public String getContentType() {
      return null;
   }

   @Override
   public ServletOutputStream getOutputStream() throws IOException {
      return null;
   }

   @Override
   public PrintWriter getWriter() throws IOException {
      return null;
   }

   @Override
   public void setCharacterEncoding(final String s) {

   }

   @Override
   public void setContentLength(final int i) {

   }

   @Override
   public void setContentType(final String s) {

   }

   @Override
   public void setBufferSize(final int i) {

   }

   @Override
   public int getBufferSize() {
      return 0;
   }

   @Override
   public void flushBuffer() throws IOException {

   }

   @Override
   public void resetBuffer() {

   }

   @Override
   public boolean isCommitted() {
      return false;
   }

   @Override
   public void reset() {

   }

   @Override
   public void setLocale(final Locale locale) {

   }

   @Override
   public Locale getLocale() {
      return null;
   }
}
