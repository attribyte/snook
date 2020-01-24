package org.attribyte.snook.auth;

import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import com.google.common.hash.HashCode;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;

import static org.junit.Assert.*;

public class UsersTest {

   @Test
   public void generateToken() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$token$");
      List<Users.Record> records = Users.parse(lines, true);
      assertEquals(1, records.size());
      Users.Record record = records.get(0);
      assertNotNull(record.value);
      assertEquals(Users.HashType.SHA256, record.hashType);
      assertEquals("tester:$token$" + record.value, record.toLine());
      assertNotNull(record.hashCode);
   }

   @Test
   public void generatePassword() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$password$");
      List<Users.Record> records = Users.parse(lines, true);
      assertEquals(1, records.size());
      Users.Record record = records.get(0);
      assertEquals(Users.HashType.BCRYPT, record.hashType);
      assertNotNull(record.hashCode);
   }

   @Test
   public void convertToSecure() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$password$");
      lines.add("tester:$token$");
      List<Users.Record> records = Users.parse(lines, true);
      assertEquals(2, records.size());
      List<Users.Record> secureRecords = Users.toSecure(records);
      assertEquals(2, secureRecords.size());
      assertTrue(secureRecords.get(0).toLine().startsWith("tester:$2a$11$"));
      assertTrue(secureRecords.get(1).toLine().startsWith("tester:$sha256$"));
   }

   @Test
   public void maps() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester0:$password$123456789012");
      lines.add("tester1:$token$123456789012123456789012123456789012");
      List<Users.Record> records = Users.parse(lines, true);
      assertEquals(2, records.size());
      Users users = new Users(records);
      assertEquals(1, users.bcryptHashes.size());
      assertEquals(1, users.sha256Hashes.size());
      assertEquals(2, users.userForHash.size());
      String user0 = users.userForHash.getOrDefault(records.get(0).hashCode, "");
      assertEquals("tester0", user0);
      String user1 = users.userForHash.getOrDefault(records.get(1).hashCode, "");
      assertEquals("tester1", user1);
      HashCode user0Hash = users.bcryptHashes.get("tester0");
      assertNotNull(user0Hash);
      assertTrue(BCryptAuthenticator.checkPassword("123456789012", user0Hash));
      assertFalse(BCryptAuthenticator.checkPassword("x123456789012", user0Hash));
      HashCode user1Hash = users.sha256Hashes.get("tester1");
      assertNotNull(user1Hash);
      assertEquals(Authenticator.hashCredentials("123456789012123456789012123456789012"), user1Hash);
   }

   @Test(expected = IOException.class)
   public void dupeHash() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester0:$token$123456789012123456789012123456789012");
      lines.add("tester1:$token$123456789012123456789012123456789012");
      List<Users.Record> records = Users.parse(lines, true);
      assertEquals(2, records.size());
      Users users = new Users(records);
   }


   @Test
   public void preserveLines() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$password$");
      lines.add("tester:$token$");
      lines.add("");
      lines.add("#comment");

      List<Users.Record> records = Users.parse(lines, true);
      assertEquals(4, records.size());
      List<Users.Record> secureRecords = Users.toSecure(records);
      assertEquals(2, secureRecords.size());
      assertTrue(secureRecords.get(0).toLine().startsWith("tester:$2a$11$"));
      assertTrue(secureRecords.get(1).toLine().startsWith("tester:$sha256$"));
   }

   @Test
   public void generateFiles() throws IOException  {

      String inputLines = ("btester:$basic$\ntester:$password$\ntester:$token$\n\n#comment");
      File secureFile = Files.createTempFile("secure_", ".txt").toFile();
      File insecureFile = Files.createTempFile("insecure_", ".txt").toFile();

      try(InputStream is = new ByteArrayInputStream(inputLines.getBytes(Charsets.UTF_8))) {
         Users.generateFiles(is, secureFile, insecureFile, true);
         Users users = new Users(secureFile);
         assertEquals(3, users.userForHash.size());
         assertEquals(2, users.sha256Hashes.size());
         assertEquals(1, users.bcryptHashes.size());
      } finally {
         secureFile.delete();
         insecureFile.delete();
      }
   }
}
