package org.attribyte.snook.auth.impl;

import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.util.List;

import static org.junit.Assert.*;

public class UsersFileTest {

   @Test
   public void testGenerateToken() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$token$");
      List<UsersFile.Record> records = UsersFile.parse(lines, true);
      assertEquals(1, records.size());
      UsersFile.Record record = records.get(0);
      assertNotNull(record.value);
      System.out.println(record);
      System.out.println(record.toLine());
      assertEquals(UsersFile.HashType.SHA256, record.hashType);
      assertEquals("tester:$token$" + record.value, record.toLine());
      assertNotNull(record.hashCode);
   }

   @Test
   public void testGeneratePassword() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$password$");
      List<UsersFile.Record> records = UsersFile.parse(lines, true);
      assertEquals(1, records.size());
      UsersFile.Record record = records.get(0);
      assertEquals(UsersFile.HashType.BCRYPT, record.hashType);
      assertNotNull(record.hashCode);
      System.out.println(record.toLine());
   }

   @Test
   public void testConvertToSecure() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$password$");
      lines.add("tester:$token$");
      List<UsersFile.Record> records = UsersFile.parse(lines, true);
      assertEquals(2, records.size());
      List<UsersFile.Record> secureRecords = UsersFile.toSecure(records);
      assertEquals(2, secureRecords.size());
      assertTrue(secureRecords.get(0).toLine().startsWith("tester:$2a$10$"));
      assertTrue(secureRecords.get(1).toLine().startsWith("tester:$sha256$"));
   }


   @Test
   public void testPreserve() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$password$");
      lines.add("tester:$token$");
      lines.add("");
      lines.add("#comment");

      List<UsersFile.Record> records = UsersFile.parse(lines, true);
      assertEquals(4, records.size());
      List<UsersFile.Record> secureRecords = UsersFile.toSecure(records);
      assertEquals(2, secureRecords.size());
      assertTrue(secureRecords.get(0).toLine().startsWith("tester:$2a$10$"));
      assertTrue(secureRecords.get(1).toLine().startsWith("tester:$sha256$"));
   }
}
