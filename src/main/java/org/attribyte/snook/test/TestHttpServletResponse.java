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

package org.attribyte.snook.test;

import com.google.common.base.MoreObjects;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.net.HttpHeaders;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A test servlet response.
 */
public class TestHttpServletResponse implements HttpServletResponse {

   @Override
   public void addCookie(final Cookie cookie) {
      cookies.add(cookie);
   }

   @Override
   public boolean containsHeader(final String s) {
      return headers.containsKey(s);
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
   public void sendError(final int i, final String s) throws IOException {
      this.status = i;
   }

   @Override
   public void sendError(final int i) throws IOException {
      this.status = i;
   }

   @Override
   public void sendRedirect(final String s) throws IOException {
      this.status = HttpServletResponse.SC_MOVED_PERMANENTLY;
   }

   @Override
   public void setDateHeader(final String s, final long l) {
      headers.put(s, Long.toString(l));
   }

   @Override
   public void addDateHeader(final String s, final long l) {
      headers.put(s, Long.toString(l));
   }

   @Override
   public void setHeader(final String s, final String s1) {
      headers.put(s, Strings.nullToEmpty(s1));
   }

   @Override
   public void addHeader(final String s, final String s1) {
      headers.put(s, Strings.nullToEmpty(s1));
   }

   @Override
   public void setIntHeader(final String s, final int i) {
      headers.put(s, Long.toString(i));
   }

   @Override
   public void addIntHeader(final String s, final int i) {
      headers.put(s, Long.toString(i));
   }

   @Override
   public void setStatus(final int i) {
      this.status = i;
   }

   @Override
   public int getStatus() {
      return status;
   }

   @Override
   public String getHeader(final String s) {
      return headers.get(s);
   }

   @Override
   public Collection<String> getHeaders(final String s) {
      return headers.containsKey(s) ? ImmutableList.of(headers.get(s)) : ImmutableList.of();
   }

   @Override
   public Collection<String> getHeaderNames() {
      return headers.keySet();
   }

   @Override
   public String getCharacterEncoding() {
      return null;
   }

   @Override
   public String getContentType() {
      return headers.getOrDefault("Content-Type", null);
   }

   @Override
   public ServletOutputStream getOutputStream() throws IOException {
      return new ServletOutputStream() {
         @Override
         public boolean isReady() {
            return true;
         }

         @Override
         public void setWriteListener(final WriteListener writeListener) {
         }

         @Override
         public void write(final int b) throws IOException {
            outputStream.write(b);
         }
      };
   }

   @Override
   public PrintWriter getWriter() throws IOException {
      return new PrintWriter(outputStream);
   }

   @Override
   public void setCharacterEncoding(final String s) {
   }

   @Override
   public void setContentLength(final int i) {
   }

   @Override
   public void setContentLengthLong(final long l) {
   }

   @Override
   public void setContentType(final String s) {
      this.headers.put(HttpHeaders.CONTENT_TYPE, s);
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
      outputStream.flush();
   }

   @Override
   public void resetBuffer() {
      outputStream.reset();
   }

   @Override
   public boolean isCommitted() {
      return false;
   }

   @Override
   public void reset() {
      outputStream.reset();
   }

   @Override
   public void setLocale(final Locale locale) {
   }

   @Override
   public Locale getLocale() {
      return null;
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("status", status)
              .add("headers", headers)
              .add("cookies", cookies)
              .toString();
   }

   /**
    * The output stream.
    */
   public final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

   /**
    * The HTTP status.
    */
   public int status = 0;

   /**
    * A map of headers.
    */
   public final Map<String, String> headers = Maps.newHashMap();

   /**
    * A list of added cookies.
    */
   public final List<Cookie> cookies = Lists.newArrayList();
}
